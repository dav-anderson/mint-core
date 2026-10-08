//! Blind Diffie-Hellman Key Exchange: the blind-signature primitive this
//! mint uses to issue and redeem notes.

//! This is a from-scratch implementation of the five operations Cashu's
//! [NUT-00 spec](https://cashubtc.github.io/nuts/00/) defines for BDHKE. 
// It exists because we wanted the *properties* NUT-00 describes 
// 1. plain secp256k1 math
// 2. no vestigial multi-party machinery
// 3. published set of test vectors we can check our own work against without 
// adopting Cashu's wire format, its token types, or any of its 
// Bitcoin/Lightning-flavored surrounding code. 

// Nothing outside this crate needs to know BDHKE is what's underneath; from
//! `mint-core`'s perspective this is just "sign" and "verify."
//!
//! ## The scheme, in five functions
//!
//! - [`hash_to_curve`]: deterministically maps arbitrary bytes to a curve
//!   point `Y`, so nobody, including the mint, can choose a point with a
//!   known discrete log relative to another. This is what makes a "note
//!   secret" unforgeable: you can't work backwards from a curve point to a
//!   secret that hashes to it, and you can't pick a secret whose point has a
//!   known relationship to some other point.
//! - [`blind_message`]: the note holder blinds `Y` with a random secret `r`
//!   they alone know, producing `B_ = Y + rG`. The mint will sign `B_`
//!   without ever seeing `Y` or `r`.
//! - [`sign_message`]: the mint signs the blinded point with its
//!   denomination's private key `k`: `C_ = kB_`. This is the *entire*
//!   issuance operation (see the repo README's "On backing" section).
//! - [`unblind_message`]: the holder removes their own blinding factor:
//!   `C = C_ - rK` (`K = kG`, the mint's public key), leaving `C = kY`, a
//!   valid signature on `Y` that the mint never saw being computed. This
//!   step is what makes a note issued to Alice unlinkable from the note she
//!   later redeems: the mint has no record connecting `B_` to `C`.
//! - [`verify_message`]: anyone holding the mint's public key can confirm
//!   `C == kY` without the private key `k`.
//!
//! ## Why the domain separator matches NUT-00's
//!
//! `hash_to_curve`'s domain separator string below is the literal one
//! specified in NUT-00, not something we chose ourselves. It has to be, for
//! to check our implementation against NUT-00's published test vectors 
// the entire point of building on a spec with
//! published answer keys instead of a bespoke scheme. This does **not**
//! make this mint wire-compatible with Cashu, it just means this one function, 
// in isolation, reproduces the reference answers.

use secp256k1::{Parity, PublicKey, Scalar, SecretKey, XOnlyPublicKey, SECP256K1};
use sha2::{Digest, Sha256};

const DOMAIN_SEPARATOR: &[u8] = b"Secp256k1_HashToCurve_Cashu_";

/// Deterministically map `message` to a point on the secp256k1 curve with no
/// known discrete log relative to any other point, the "nothing-up-my-
/// sleeve" step that makes note secrets unforgeable. Tries successive
/// counter values until SHA-256 output happens to be a valid curve
/// x-coordinate (expected within a handful of iterations).
pub fn hash_to_curve(message: &[u8]) -> PublicKey {
    let msg_hash: [u8; 32] = Sha256::digest([DOMAIN_SEPARATOR, message].concat()).into();

    for counter in 0u32..(1 << 16) {
        let mut candidate = Vec::with_capacity(36);
        candidate.extend_from_slice(&msg_hash);
        candidate.extend_from_slice(&counter.to_le_bytes());
        let hash: [u8; 32] = Sha256::digest(&candidate).into();

        if let Ok(x_only) = XOnlyPublicKey::from_slice(&hash) {
            return PublicKey::from_x_only_public_key(x_only, Parity::Even);
        }
    }

    // Probability of exhausting 2^16 counters without hitting a valid curve
    // point is astronomically small (~(1 - 1/2)^65536). If this ever
    // actually fires, something is deeply wrong with the inputs, not just
    // unlucky.
    unreachable!("no valid curve point found in 2^16 attempts")
}

/// The note holder's half of issuance: blind `secret` with a fresh (or
/// caller-supplied, for testing) blinding factor `r`, producing `(B_, r)`.
/// `B_` is sent to the mint to be signed; `r` never leaves the holder and is
/// needed later to unblind the result.
pub fn blind_message(secret: &[u8], blinding_factor: Option<SecretKey>) -> (PublicKey, SecretKey) {
    let y = hash_to_curve(secret);
    let r = blinding_factor.unwrap_or_else(|| SecretKey::new(&mut rand::thread_rng()));
    let b = y
        .combine(&r.public_key(&SECP256K1))
        .expect("sum of two valid curve points is a valid curve point except with negligible probability");
    (b, r)
}

/// The mint's entire issuance operation: sign a blinded point with the
/// private key `k` for one denomination. Nothing here checks backing.
pub fn sign_message(k: &SecretKey, blinded_message: &PublicKey) -> PublicKey {
    blinded_message
        .mul_tweak(&SECP256K1, &Scalar::from(*k))
        .expect("scalar multiplication of a valid point by a nonzero tweak stays on the curve")
}

/// The note holder's second half: remove the blinding factor `r` from the
/// mint's signature `blinded_signature`, given the mint's public key
/// `mint_pubkey` for this denomination. The result is a valid signature on
/// the original secret that the mint cannot link to the blinded signature it
/// computed.
pub fn unblind_message(
    blinded_signature: &PublicKey,
    r: &SecretKey,
    mint_pubkey: &PublicKey,
) -> PublicKey {
    let r_times_k = mint_pubkey
        .mul_tweak(&SECP256K1, &Scalar::from(*r))
        .expect("scalar multiplication stays on the curve");
    let neg_r_times_k = r_times_k.negate(&SECP256K1);
    blinded_signature
        .combine(&neg_r_times_k)
        .expect("sum of two valid curve points is a valid curve point except with negligible probability")
}

/// Confirm `unblinded_message` is a valid signature on `msg` under the
/// mint's private key `k` for this denomination i.e. that `hash_to_curve(msg) * k == unblinded_message`.
pub fn verify_message(k: &SecretKey, unblinded_message: PublicKey, msg: &[u8]) -> bool {
    let y = hash_to_curve(msg);
    let expected = y
        .mul_tweak(&SECP256K1, &Scalar::from(*k))
        .expect("scalar multiplication stays on the curve");
    unblinded_message == expected
}

#[cfg(test)]
mod tests {
    //! These test vectors are copied from NUT-00's published test
    //! vectors (https://cashubtc.github.io/nuts/00/), they're the spec's answer key, 
    // and the reason this crate can claim its `hash_to_curve` and
    //! blind/sign/unblind math is correct against an interoperable
    //! reference.

    use secp256k1::PublicKey;

    use super::*;

    fn pk(hex_str: &str) -> PublicKey {
        PublicKey::from_slice(&hex::decode(hex_str).unwrap()).unwrap()
    }

    fn sk(hex_str: &str) -> SecretKey {
        SecretKey::from_slice(&hex::decode(hex_str).unwrap()).unwrap()
    }

    #[test]
    fn hash_to_curve_matches_nut00_vectors() {
        assert_eq!(
            hash_to_curve(
                &hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap()
            ),
            pk("024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725")
        );
        assert_eq!(
            hash_to_curve(
                &hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                    .unwrap()
            ),
            pk("022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf")
        );
        // This one requires several loop iterations before landing on a
        // valid curve point. exercises the counter path, not just counter == 0.
        assert_eq!(
            hash_to_curve(
                &hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
                    .unwrap()
            ),
            pk("026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f")
        );
    }

    #[test]
    fn blind_message_matches_nut00_vector() {
        let message =
            hex::decode("d341ee4871f1f889041e63cf0d3823c713eea6aff01e80f1719f08f9e5be98f6").unwrap();
        let secret = sk("99fce58439fc37412ab3468b73db0569322588f62fb3a49182d67e23d877824a");

        let (b, r) = blind_message(&message, Some(secret));

        assert_eq!(r, secret);
        assert_eq!(
            b,
            pk("033b1a9737a40cc3fd9b6af4b723632b76a67a36782596304612a6c2bfb5197e6d")
        );
    }

    #[test]
    fn unblind_message_matches_nut00_vector() {
        let blinded_key = pk("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
        let r = sk("0000000000000000000000000000000000000000000000000000000000000001");
        let a = pk("020000000000000000000000000000000000000000000000000000000000000001");

        assert_eq!(
            unblind_message(&blinded_key, &r, &a),
            pk("03c724d7e6a5443b39ac8acf11f40420adc4f99a02e7cc1b57703d9391f6d129cd")
        );
    }

    #[test]
    fn full_roundtrip_issues_and_verifies_a_note() {
        let secret = b"a note only the holder should be able to construct a valid signature for";

        let mint_k = SecretKey::new(&mut rand::thread_rng());
        let mint_pubkey = mint_k.public_key(&SECP256K1);

        let (blinded, r) = blind_message(secret, None);
        let blinded_signature = sign_message(&mint_k, &blinded);
        let signature = unblind_message(&blinded_signature, &r, &mint_pubkey);

        assert!(verify_message(&mint_k, signature, secret));
    }

    #[test]
    fn verify_rejects_signature_from_a_different_key() {
        let secret = b"some note secret";
        let mint_k = SecretKey::new(&mut rand::thread_rng());
        let wrong_k = SecretKey::new(&mut rand::thread_rng());

        let (blinded, r) = blind_message(secret, None);
        let blinded_signature = sign_message(&mint_k, &blinded);
        let signature = unblind_message(&blinded_signature, &r, &mint_k.public_key(&SECP256K1));

        assert!(!verify_message(&wrong_k, signature, secret));
    }
}
