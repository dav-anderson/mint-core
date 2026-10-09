//! Note issuance and redemption logic: verify, issue, redeem, swap, melt.
//!
//! Signing and verifying go through `bdhke` (plain secp256k1 Blind
//! Diffie-Hellman Key Exchange). `verify_note` needs this mint's own secret
//! key, because plain BDHKE isn't publicly verifiable, so it only ever runs
//! here, server-side, where the key already lives.

pub mod keygen;
pub mod store;

use std::collections::BTreeMap;

use mint_types::{
    Amount, MintConfig, MintInput, MintInputError, MintOutput, MintOutputError,
    MintOutputOutcome, Nonce, melt_sighash, transaction_sighash,
};
use secp256k1::{PublicKey, SECP256K1, SecretKey};
use thiserror::Error;

use crate::store::Store;

pub struct MintLogic {
    sk: BTreeMap<Amount, SecretKey>,
    pk: BTreeMap<Amount, PublicKey>,
    store: Store,
}

impl MintLogic {
    pub fn new(cfg: MintConfig, store: Store) -> Self {
        let pk = keygen::public_keys(&cfg);
        Self {
            sk: cfg.sk,
            pk,
            store,
        }
    }

    /// Public keys clients need to blind their withdrawal/swap requests
    /// against, one per denomination. Safe to expose publicly (e.g. a
    /// `GET /keys` endpoint).
    pub fn public_keys(&self) -> &BTreeMap<Amount, PublicKey> {
        &self.pk
    }

    /// Confirms the note's BDHKE signature is genuine for its claimed
    /// denomination. Needs this mint's own secret key. Does **not** by itself
    /// prove the presenter is authorized to spend the note, see
    /// [`MintLogic::verify_spend_authorization`] and `mint-types::MintInput`.
    pub fn verify_note(&self, input: &MintInput) -> Result<(), MintInputError> {
        let sk = self
            .sk
            .get(&input.amount)
            .ok_or(MintInputError::InvalidAmountTier(input.amount))?;

        if !bdhke::verify_message(
            sk,
            input.note.signature,
            &input.note.nonce.as_hash_preimage(),
        ) {
            return Err(MintInputError::InvalidSignature);
        }

        Ok(())
    }

    /// Confirms `input.spend_signature` is a valid signature, by the note's
    /// own nonce keypair, over `sighash`. I.e. that whoever submitted this
    /// swap request actually holds the note, for exactly this set of
    /// inputs and outputs, and isn't replaying a note they merely observed.
    pub fn verify_spend_authorization(
        &self,
        input: &MintInput,
        sighash: [u8; 32],
    ) -> Result<(), MintInputError> {
        SECP256K1
            .verify_schnorr(
                &input.spend_signature,
                &sighash,
                &input.note.spend_key().x_only_public_key().0,
            )
            .map_err(|_| MintInputError::InvalidSpendAuthorization)
    }

    /// Mark the note's nonce spent (erroring if it already was, this is
    /// the double-spend check) and add its amount to the redeemed total.
    fn redeem(&self, input: &MintInput, sighash: [u8; 32]) -> Result<(), MintInputError> {
        self.verify_note(input)?;
        self.verify_spend_authorization(input, sighash)?;

        let newly_spent = self
            .store
            .mark_nonce_spent(&input.note.nonce)
            .map_err(|e| MintInputError::Internal(e.to_string()))?;
        if !newly_spent {
            return Err(MintInputError::SpentCoin);
        }

        self.store
            .add_redeemed(input.amount)
            .map_err(|e| MintInputError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Blind-sign the requested nonce and record it as issued.
    /// **Unconditional**: this is the "unilateral, arbitrary issuance"
    /// primitive; every other entry point in this crate is either
    /// read-only or built out of this plus [`MintLogic::redeem`].
    pub fn issue(&self, output: &MintOutput) -> Result<MintOutputOutcome, MintOutputError> {
        let sk = self
            .sk
            .get(&output.amount)
            .ok_or(MintOutputError::InvalidAmountTier(output.amount))?;

        let newly_used = self
            .store
            .mark_blind_nonce_used(&output.blind_nonce)
            .map_err(|e| MintOutputError::Internal(e.to_string()))?;
        if !newly_used {
            return Err(MintOutputError::BlindNonceAlreadyUsed);
        }

        let blinded_signature = bdhke::sign_message(sk, &output.blind_nonce.0);

        self.store
            .add_issued(output.amount)
            .map_err(|e| MintOutputError::Internal(e.to_string()))?;

        Ok(MintOutputOutcome(blinded_signature))
    }

    /// Redeem `inputs` and issue `outputs`, enforcing that this is a transfer and
    /// not a backdoor mint: total input value must cover total
    /// output value. Not atomic yet: inputs are redeemed one at a time, so a
    /// failure partway can leave earlier inputs spent (see README, Deferred). This is the swap/reissue operation, the thing two
    /// users actually do to hand ecash to each other, and the step that
    /// makes the handoff unlinkable. It is deliberately the *only* other
    /// caller of `issue` in this crate besides the admin path.
    pub fn swap(
        &self,
        inputs: &[MintInput],
        outputs: &[MintOutput],
    ) -> Result<Vec<MintOutputOutcome>, SwapError> {
        // Every input signs over this same commitment to the full set of
        // inputs and outputs, see `transaction_sighash`'s doc comment for
        // why that (and not just "prove you own *a* note") is what actually
        // stops a note from being stolen in transit.
        let sighash = transaction_sighash(inputs, outputs);

        let mut input_total = Amount::ZERO;
        for input in inputs {
            self.verify_note(input).map_err(SwapError::Input)?;
            self.verify_spend_authorization(input, sighash)
                .map_err(SwapError::Input)?;
            input_total += input.amount;
        }

        let mut output_total = Amount::ZERO;
        for output in outputs {
            if !self.sk.contains_key(&output.amount) {
                return Err(SwapError::Output(MintOutputError::InvalidAmountTier(
                    output.amount,
                )));
            }
            output_total += output.amount;
        }

        if input_total < output_total {
            return Err(SwapError::Unbalanced {
                input_total,
                output_total,
            });
        }

        for input in inputs {
            self.redeem(input, sighash).map_err(SwapError::Input)?;
        }

        let mut outcomes = Vec::with_capacity(outputs.len());
        for output in outputs {
            outcomes.push(self.issue(output).map_err(SwapError::Output)?);
        }

        Ok(outcomes)
    }

    /// Redeem `inputs` and issue nothing, returning the total burned. Every
    /// input is checked (genuine, spend signature over `melt_sighash`, not
    /// spent, no duplicates) before any is marked spent.
    pub fn melt(&self, inputs: &[MintInput], memo: &[u8]) -> Result<Amount, MintInputError> {
        if inputs.is_empty() {
            return Err(MintInputError::Internal("melt requires at least one input".into()));
        }

        let sighash = melt_sighash(inputs, memo);

        let mut seen = std::collections::HashSet::new();
        let mut total = Amount::ZERO;
        for input in inputs {
            self.verify_note(input)?;
            self.verify_spend_authorization(input, sighash)?;
            if !seen.insert(input.note.nonce) {
                return Err(MintInputError::SpentCoin);
            }
            let spent = self
                .store
                .is_nonce_spent(&input.note.nonce)
                .map_err(|e| MintInputError::Internal(e.to_string()))?;
            if spent {
                return Err(MintInputError::SpentCoin);
            }
            total += input.amount;
        }

        for input in inputs {
            self.redeem(input, sighash)?;
        }

        Ok(total)
    }

    /// Has this nonce been spent? For a `/check-state`-style endpoint so
    /// clients can confirm a note they received has actually settled before
    /// treating it as theirs.
    pub fn is_spent(&self, nonce: Nonce) -> anyhow::Result<bool> {
        self.store.is_nonce_spent(&nonce)
    }

    /// Running (issued, redeemed) totals, outstanding supply is
    /// `issued - redeemed`. Since `issue` is unconditional, this number is
    /// exactly as meaningful as the operator's own issuance policy makes it.
    /// It's internal bookkeeping.
    pub fn audit_totals(&self) -> anyhow::Result<(Amount, Amount)> {
        Ok((self.store.issued_total()?, self.store.redeemed_total()?))
    }
}

#[derive(Debug, Error)]
pub enum SwapError {
    #[error("invalid input: {0}")]
    Input(MintInputError),
    #[error("invalid output: {0}")]
    Output(MintOutputError),
    #[error("inputs ({input_total}) do not cover outputs ({output_total})")]
    Unbalanced {
        input_total: Amount,
        output_total: Amount,
    },
}
