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
    Amount, BlindNonce, MintConfig, MintInput, MintInputError, MintOutput, MintOutputError,
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
    ///
    /// The key comes from the fixed key table, chosen by `input.amount`. A
    /// mint with derived keys, such as ESP, calls
    /// [`MintLogic::verify_note_with_key`] instead.
    pub fn verify_note(&self, input: &MintInput) -> Result<(), MintInputError> {
        let sk = self
            .sk
            .get(&input.amount)
            .ok_or(MintInputError::InvalidAmountTier(input.amount))?;

        self.verify_note_with_key(sk, input)
    }

    /// Same as [`MintLogic::verify_note`], except the caller supplies the
    /// secret key to check the signature against, instead of the mint looking
    /// it up by amount in its fixed key table. See
    /// [`MintLogic::issue_with_key`] for why a mint would derive its own keys.
    /// The caller is responsible for deriving the right key for this note.
    pub fn verify_note_with_key(
        &self,
        sk: &SecretKey,
        input: &MintInput,
    ) -> Result<(), MintInputError> {
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
        let sk = self
            .sk
            .get(&input.amount)
            .ok_or(MintInputError::InvalidAmountTier(input.amount))?;

        self.redeem_with_key(sk, input, sighash)
    }

    /// Same as the internal redeem used by `swap` and `melt`, except the
    /// caller supplies the secret key the note was signed with, instead of the
    /// mint looking it up by amount in its fixed key table. It checks the
    /// signature with that key, checks the spend authorization over `sighash`,
    /// marks the nonce spent (the double-spend check) and adds the amount to
    /// the redeemed total. See [`MintLogic::issue_with_key`] for why a mint
    /// would derive its own keys. The caller is responsible for deriving the
    /// right key and for any checks of its own, such as redeemable-after dates,
    /// before calling this.
    pub fn redeem_with_key(
        &self,
        sk: &SecretKey,
        input: &MintInput,
        sighash: [u8; 32],
    ) -> Result<(), MintInputError> {
        self.verify_note_with_key(sk, input)?;
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
    ///
    /// This signs with the mint's fixed key table, which holds one secret key
    /// per denomination and picks the key from `output.amount` alone. PSP and
    /// FSP use this method, because every note of a given amount is signed by
    /// the same key.
    ///
    /// It is not the only way to issue. A mint whose signing key depends on
    /// more than the amount, such as ESP, where the key also depends on the
    /// note's terms, cannot look its key up in a table. It calls
    /// [`MintLogic::issue_with_key`] with the key it derived instead. This
    /// method is that one with the key taken from the table.
    pub fn issue(&self, output: &MintOutput) -> Result<MintOutputOutcome, MintOutputError> {
        let sk = self
            .sk
            .get(&output.amount)
            .ok_or(MintOutputError::InvalidAmountTier(output.amount))?;

        self.issue_with_key(sk, output)
    }

    /// Same as [`MintLogic::issue`], except the caller supplies the signing
    /// key instead of the mint looking it up by amount in its fixed key table.
    ///
    /// It exists for mints whose signing key is not a function of the amount
    /// alone. ESP derives a separate key for every combination of amount and
    /// terms (the redeeming service and the redeemable-after date), so that a
    /// note's terms are bound into its signature and cannot be edited later.
    /// There are too many combinations to keep in a table, so the caller
    /// derives the key and passes it here.
    ///
    /// The caller chooses the key and decides which amounts are allowed. This
    /// method does not check the amount against the key table, and it cannot
    /// tell whether `sk` is the right key for the output. Beyond that it does
    /// exactly what `issue` does: it marks the blind nonce used, signs, and
    /// adds the amount to the issued total.
    ///
    /// `swap` and `melt` still use the fixed key table only.
    pub fn issue_with_key(
        &self,
        sk: &SecretKey,
        output: &MintOutput,
    ) -> Result<MintOutputOutcome, MintOutputError> {
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

    pub fn is_blind_nonce_used(&self, blind_nonce: &BlindNonce) -> anyhow::Result<bool> {
        self.store.is_blind_nonce_used(blind_nonce)
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

#[cfg(test)]
mod tests {
    use super::*;
    use mint_types::{DEFAULT_DENOMINATION_BASE, gen_denominations};

    #[test]
    fn blind_nonce_is_unused_until_issued() {
        let dir = std::env::temp_dir().join(format!("mint-core-{}-blind-nonce", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = keygen::generate(&gen_denominations(
            DEFAULT_DENOMINATION_BASE,
            Amount::from_units(8),
        ));
        let logic = MintLogic::new(cfg, Store::open(&dir).unwrap());
        let sk = SecretKey::new(&mut rand::thread_rng());
        let output = MintOutput {
            amount: Amount::from_units(4),
            blind_nonce: BlindNonce(sk.public_key(&SECP256K1)),
        };
        assert!(!logic.is_blind_nonce_used(&output.blind_nonce).unwrap());
        logic.issue(&output).unwrap();
        assert!(logic.is_blind_nonce_used(&output.blind_nonce).unwrap());
        drop(logic);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn fresh_logic(name: &str) -> (MintLogic, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("mint-core-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = keygen::generate(&gen_denominations(
            DEFAULT_DENOMINATION_BASE,
            Amount::from_units(8),
        ));
        (MintLogic::new(cfg, Store::open(&dir).unwrap()), dir)
    }

    fn signed_input(
        units: u64,
        mint_pk: &PublicKey,
        issue: impl FnOnce(&MintOutput) -> MintOutputOutcome,
    ) -> (MintInput, [u8; 32]) {
        let keypair = secp256k1::Keypair::new(&SECP256K1, &mut rand::thread_rng());
        let nonce = Nonce(keypair.public_key());
        let (blinded, r) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        let output = MintOutput {
            amount: Amount::from_units(units),
            blind_nonce: BlindNonce(blinded),
        };
        let outcome = issue(&output);
        let signature = bdhke::unblind_message(&outcome.0, &r, mint_pk);
        let mut input = MintInput {
            amount: output.amount,
            note: mint_types::Note { nonce, signature },
            spend_signature: secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap(),
        };
        let sighash = melt_sighash(std::slice::from_ref(&input), b"test");
        input.spend_signature = SECP256K1.sign_schnorr(&sighash, &keypair);
        (input, sighash)
    }

    #[test]
    fn issue_with_key_signs_with_the_supplied_key_and_skips_the_tier_table() {
        let (logic, dir) = fresh_logic("issue-with-key");
        let sk = SecretKey::new(&mut rand::thread_rng());
        let (blinded, _) = bdhke::blind_message(b"x", None);
        let output = MintOutput {
            amount: Amount::from_units(3),
            blind_nonce: BlindNonce(blinded),
        };
        assert_eq!(
            logic.issue(&output),
            Err(MintOutputError::InvalidAmountTier(Amount::from_units(3)))
        );
        let outcome = logic.issue_with_key(&sk, &output).unwrap();
        assert_eq!(outcome.0, bdhke::sign_message(&sk, &output.blind_nonce.0));
        assert_eq!(
            logic.issue_with_key(&sk, &output),
            Err(MintOutputError::BlindNonceAlreadyUsed)
        );
        assert_eq!(logic.audit_totals().unwrap().0, Amount::from_units(3));
        drop(logic);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn redeem_with_key_checks_the_key_the_authorization_and_double_spend() {
        let (logic, dir) = fresh_logic("redeem-with-key");
        let sk = SecretKey::new(&mut rand::thread_rng());
        let wrong = SecretKey::new(&mut rand::thread_rng());
        let (input, sighash) = signed_input(3, &sk.public_key(&SECP256K1), |o| {
            logic.issue_with_key(&sk, o).unwrap()
        });

        assert_eq!(
            logic.verify_note(&input),
            Err(MintInputError::InvalidAmountTier(Amount::from_units(3)))
        );
        assert_eq!(logic.verify_note_with_key(&sk, &input), Ok(()));
        assert_eq!(
            logic.verify_note_with_key(&wrong, &input),
            Err(MintInputError::InvalidSignature)
        );

        assert_eq!(
            logic.redeem_with_key(&wrong, &input, sighash),
            Err(MintInputError::InvalidSignature)
        );
        assert_eq!(
            logic.redeem_with_key(&sk, &input, [0u8; 32]),
            Err(MintInputError::InvalidSpendAuthorization)
        );
        assert!(!logic.is_spent(input.note.nonce).unwrap());

        assert_eq!(logic.redeem_with_key(&sk, &input, sighash), Ok(()));
        assert!(logic.is_spent(input.note.nonce).unwrap());
        assert_eq!(
            logic.redeem_with_key(&sk, &input, sighash),
            Err(MintInputError::SpentCoin)
        );
        assert_eq!(
            logic.audit_totals().unwrap(),
            (Amount::from_units(3), Amount::from_units(3))
        );
        drop(logic);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn table_methods_behave_as_before() {
        let (logic, dir) = fresh_logic("table");
        let pk = logic.public_keys()[&Amount::from_units(4)];
        let (input, _) = signed_input(4, &pk, |o| logic.issue(o).unwrap());
        assert_eq!(logic.verify_note(&input), Ok(()));
        assert_eq!(logic.melt(&[input], b"test"), Ok(Amount::from_units(4)));
        assert_eq!(
            logic.audit_totals().unwrap(),
            (Amount::from_units(4), Amount::from_units(4))
        );
        drop(logic);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
