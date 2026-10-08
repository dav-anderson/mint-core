//! Note/nonce/amount/config types for the sandbox mint.

//! BDHKE has no vestigial multi-party/threshold code (Cashu's protocol,
//! which defines BDHKE) and it's checkable against a published, cross-implementation
//! set of test vectors (see `crypto/bdhke`'s tests).

//! plain BDHKE is **not publicly verifiable**. Given
//! only the mint's public key for a denomination, there's no way to confirm
//! a signature is genuine. Verifying requires either the mint's private
//! key, or an additional non-interactive proof (Cashu's NUT-12 "DLEQ
//! proof") that is not presently implemented. In practice this means a
//! holder can't cryptographically self-check a note the instant they
//! receive it; the check that matters, can this note actually be redeemed,
//! happens only when they try to spend it.

use std::fmt;
use std::ops::{Add, AddAssign};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use thiserror::Error;

/// Default denomination base for ecash notes (powers of 2).
pub const DEFAULT_DENOMINATION_BASE: u16 = 2;

/// A count of this mint's own unit of value. Deliberately opaque and
/// unbacked there is no bitcoin, satoshi, or millisatoshi concept
/// anywhere; `units` means only the denominations intrinsic to the mint 
/// for a given note, nothing more.
#[derive(
    Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Amount {
    pub units: u64,
}

impl Amount {
    pub const ZERO: Amount = Amount { units: 0 };

    pub const fn from_units(units: u64) -> Self {
        Amount { units }
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.units)
    }
}

impl Add for Amount {
    type Output = Amount;
    fn add(self, rhs: Amount) -> Amount {
        Amount::from_units(self.units + rhs.units)
    }
}

impl AddAssign for Amount {
    fn add_assign(&mut self, rhs: Amount) {
        self.units += rhs.units;
    }
}

/// A verifiable, one-time-use IOU from the mint: a user-generated nonce and
/// the mint's BDHKE signature over it (computed while the nonce was in
/// [`BlindNonce`] form, so the mint never saw the nonce itself).

#[derive(Copy, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Note {
    pub nonce: Nonce,
    pub signature: secp256k1::PublicKey,
}

impl fmt::Debug for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Note")
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

impl Note {
    /// The nonce, viewed as the public key to the spend key, this is what
    /// `verify_spend_authorization` checks a [`MintInput`]'s
    /// `spend_signature` against.
    pub fn spend_key(&self) -> &secp256k1::PublicKey {
        &self.nonce.0
    }
}

/// Unique ID of a note. User-generated, unpredictable. Internally a public
/// key so transactions spending the note can be signed and its
/// serialized bytes double as the BDHKE "secret" that gets hashed to a
/// curve point (see `hash_to_curve` in `crypto/bdhke`). This is one keypair with two
/// jobs: identifying the note, and proving the right to spend it.
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct Nonce(pub secp256k1::PublicKey);

impl Nonce {
    /// The exact bytes fed into `bdhke::hash_to_curve` the note's
    /// identity, as far as the blind-signature math is concerned.
    pub fn as_hash_preimage(&self) -> [u8; 33] {
        self.0.serialize()
    }

    pub fn fmt_short(&self) -> String {
        let bytes = self.0.serialize();
        format!("{}_{}", hex::encode(&bytes[..4]), hex::encode(&bytes[29..]))
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", self.fmt_short())
    }
}

/// [`Nonce`] blinded by the user's blinding key (`B_ = Y + rG` in BDHKE
/// terms).

/// Blinding is what prevents the mint from linking a note being redeemed as
/// an *input* to the note it issued as an *output* when it was created.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct BlindNonce(pub secp256k1::PublicKey);

impl fmt::Debug for BlindNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlindNonce({:?})", self.0)
    }
}

/// A request to spend an existing, previously-issued note.

/// `spend_signature` is not optional and not a formality. `note` by itself
/// is public-ish data anyone who has *seen* it (a relay, a logging
/// mistake, a network observer on an unencrypted hop) could otherwise submit
/// it as an input paired with outputs *of their own choosing*, stealing the
/// value before its rightful holder spends it. The mint's blind signature
/// inside `note` proves the note is genuine (the mint is the only
/// party that can check it); it says nothing about who is authorized to 
/// spend it right now, to these particular outputs. `spend_signature` closes 
/// that gap: a Schnorr signature, by the note's own nonce keypair (`note.spend_key()`),
/// over [`transaction_sighash`] of the full swap request this input is part of.

/// Verified in `mint-core::MintLogic::verify_spend_authorization`.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct MintInput {
    pub amount: Amount,
    pub note: Note,
    #[serde(with = "hex_signature")]
    pub spend_signature: secp256k1::schnorr::Signature,
}

mod hex_signature {
    use secp256k1::schnorr::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v.as_ref()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        Signature::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

/// The message every input in a swap/redemption signs over: a hash
/// committing to every input's (amount, nonce) and every output's (amount,
/// blind_nonce) in the request. Binding the signature to the *whole*
/// transaction, not just "I own this note" in isolation, is what stops a
/// note's owner-proof from one request being replayed against a different
/// set of outputs.

/// Returns the raw 32-byte digest, not a `secp256k1::Message`, this
/// project's Schnorr signing/verification (`SECP256K1.sign_schnorr`/
/// `verify_schnorr`) takes `&[u8]` directly rather than the `Message`
/// wrapper type, which is really an ECDSA-signing convention.
pub fn transaction_sighash(inputs: &[MintInput], outputs: &[MintOutput]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    for input in inputs {
        hasher.update(input.amount.units.to_be_bytes());
        hasher.update(input.note.nonce.0.serialize());
    }
    for output in outputs {
        hasher.update(output.amount.units.to_be_bytes());
        hasher.update(output.blind_nonce.0.serialize());
    }
    hasher.finalize().into()
}

const MELT_SIGHASH_TAG: &[u8] = b"sandbox-mint/melt/v1";

pub fn melt_sighash(inputs: &[MintInput], memo: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(MELT_SIGHASH_TAG);
    hasher.update((inputs.len() as u64).to_be_bytes());
    for input in inputs {
        hasher.update(input.amount.units.to_be_bytes());
        hasher.update(input.note.nonce.0.serialize());
    }
    hasher.update((memo.len() as u64).to_be_bytes());
    hasher.update(memo);
    hasher.finalize().into()
}

/// A request to issue a fresh, blindly-signed note.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct MintOutput {
    pub amount: Amount,
    pub blind_nonce: BlindNonce,
}

/// The mint's response to a [`MintOutput`]: a blind signature (`C_` in
/// BDHKE terms) the client unblinds locally (with the blinding key only
/// they know) to get a spendable [`Note`]. We return this synchronously in
/// the HTTP response rather than requiring the client to poll for it --
/// there's no consensus round to wait on.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct MintOutputOutcome(pub secp256k1::PublicKey);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum MintInputError {
    #[error("The note is already spent")]
    SpentCoin,
    #[error("The note has an invalid amount not issued by this mint: {0}")]
    InvalidAmountTier(Amount),
    #[error("The note has an invalid signature")]
    InvalidSignature,
    #[error("The spend signature does not authorize this note for this transaction")]
    InvalidSpendAuthorization,
    #[error("Internal storage error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum MintOutputError {
    #[error("Requested amount is not one of this mint's denominations: {0}")]
    InvalidAmountTier(Amount),
    #[error("This blind nonce was already used")]
    BlindNonceAlreadyUsed,
    #[error("Internal storage error: {0}")]
    Internal(String),
}

/// Generate the standard power-of-two denomination ladder, e.g. `base = 2`
/// gives 1, 2, 4, 8, ... units up to `max`. Notes are split into fixed
/// denominations (rather than issued for exact arbitrary amounts) so that
/// "amount requested" doesn't become a correlation fingerprint across an
/// issue/swap/redeem.
pub fn gen_denominations(base: u16, max: Amount) -> Vec<Amount> {
    let mut tiers = Vec::new();
    let mut amount = Amount::from_units(1);
    while amount <= max {
        tiers.push(amount);
        amount = Amount::from_units(amount.units.saturating_mul(u64::from(base)));
    }
    tiers
}

/// This mint's keys and policy, for one denomination tier.

/// `sk` holds one plain secp256k1 secret key per denomination.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfig {
    pub sk: std::collections::BTreeMap<Amount, secp256k1::SecretKey>,
}
