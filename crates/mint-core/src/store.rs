//! Durable state this mint keeps: the spent-nonce set (double-spend
//! prevention), the used-blind-nonce set (stops a client from accidentally
//! burning a note by reusing a blinding factor), and running issued/redeemed
//! totals for the `/audit` endpoint. The totals are `u128`, stored as 16 bytes
//! big-endian.
//!
//! A thin wrapper around `sled`, a pure-Rust embedded key-value store, so
//! this crate needs no C/C++ toolchain to build.
//!
//! `MintLogic`'s callers are expected to serialize
//! mutating calls (`issue`/`redeem`/`swap`/`melt`), see [`crate::state::AppState`], which
//! holds `MintLogic` behind a single `std::sync::Mutex`. That's what makes
//! the read-then-write sequences of the callers (check a note, then claim
//! it) safe: there's exactly one in-process writer at a time. The claims
//! themselves ([`Store::claim_issue`], [`Store::claim_redeem`]) are sled
//! transactions, so a nonce mark and its total never part.

use std::fmt;
use std::path::Path;

use mint_types::{Amount, BlindNonce, Nonce};
use sled::transaction::{ConflictableTransactionError, TransactionError, TransactionalTree};

const NONCE_PREFIX: u8 = 0x10;
const BLIND_NONCE_PREFIX: u8 = 0x16;
const ISSUED_TOTAL_KEY: [u8; 1] = [0x20];
const REDEEMED_TOTAL_KEY: [u8; 1] = [0x21];
/// A stored total: a `u128`, big-endian.
const TOTAL_LEN: usize = 16;

pub struct Store {
    db: sled::Db,
}

/// Why a claim transaction (issue or redeem) stopped without writing anything.
#[derive(Debug)]
enum ClaimAbort {
    /// The stored total is not 16 bytes.
    CorruptTotal(usize),
    /// Adding the amount would overflow the named total ("issued" or "redeemed").
    Overflow(&'static str),
    /// A test stopped the transaction between its two writes.
    #[cfg(test)]
    Injected,
}

impl fmt::Display for ClaimAbort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimAbort::CorruptTotal(n) => {
                write!(f, "corrupt total: expected {TOTAL_LEN} bytes, got {n}")
            }
            ClaimAbort::Overflow(which) => write!(f, "the {which} total would overflow"),
            #[cfg(test)]
            ClaimAbort::Injected => write!(f, "injected failure between the two writes"),
        }
    }
}

type Aborted = ConflictableTransactionError<ClaimAbort>;

/// The total stored under `key`, read inside a transaction. A missing total is
/// zero; a stored total of any length but 16 bytes aborts.
fn tx_total(tx: &TransactionalTree, key: &[u8]) -> Result<u128, Aborted> {
    match tx.get(key)? {
        Some(bytes) => <[u8; TOTAL_LEN]>::try_from(bytes.as_ref())
            .map(u128::from_be_bytes)
            .map_err(|_| {
                ConflictableTransactionError::Abort(ClaimAbort::CorruptTotal(bytes.len()))
            }),
        None => Ok(0),
    }
}

/// `total` plus `amount`, or an abort if that would overflow.
fn tx_add(total: u128, amount: Amount, which: &'static str) -> Result<u128, Aborted> {
    total
        .checked_add(u128::from(amount.units))
        .ok_or(ConflictableTransactionError::Abort(ClaimAbort::Overflow(
            which,
        )))
}

/// The answer of a claim: `true` if it claimed the nonce, `false` if the
/// nonce was already marked.
fn claimed(outcome: Result<bool, TransactionError<ClaimAbort>>) -> anyhow::Result<bool> {
    match outcome {
        Ok(newly_claimed) => Ok(newly_claimed),
        Err(TransactionError::Abort(why)) => Err(anyhow::anyhow!("{why}")),
        Err(TransactionError::Storage(e)) => Err(e.into()),
    }
}

/// A test-only way to stop `claim_issue` or `claim_redeem` between its two writes.
#[cfg(test)]
pub(crate) mod failpoint {
    use std::cell::Cell;

    use sled::transaction::ConflictableTransactionError;

    use super::ClaimAbort;

    thread_local! {
        pub static ABORT_BETWEEN_THE_WRITES: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn between_the_writes() -> Result<(), ConflictableTransactionError<ClaimAbort>> {
        if ABORT_BETWEEN_THE_WRITES.with(|f| f.get()) {
            Err(ConflictableTransactionError::Abort(ClaimAbort::Injected))
        } else {
            Ok(())
        }
    }
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            db: sled::open(path)?,
        })
    }

    fn nonce_key(nonce: &Nonce) -> Vec<u8> {
        let mut key = Vec::with_capacity(34);
        key.push(NONCE_PREFIX);
        key.extend_from_slice(&nonce.0.serialize());
        key
    }

    fn blind_nonce_key(blind_nonce: &BlindNonce) -> Vec<u8> {
        let mut key = Vec::with_capacity(34);
        key.push(BLIND_NONCE_PREFIX);
        key.extend_from_slice(&blind_nonce.0.serialize());
        key
    }

    pub fn is_nonce_spent(&self, nonce: &Nonce) -> anyhow::Result<bool> {
        Ok(self.db.contains_key(Self::nonce_key(nonce))?)
    }

    pub fn is_blind_nonce_used(&self, blind_nonce: &BlindNonce) -> anyhow::Result<bool> {
        Ok(self.db.contains_key(Self::blind_nonce_key(blind_nonce))?)
    }

    /// Claims `blind_nonce` and adds `amount` to the issued total as one
    /// sled transaction: both writes happen or neither does. Returns `true`
    /// if this call claimed the nonce, `false` if it was already used (nothing
    /// is written then).
    ///
    /// *Why one transaction:* with two separate writes, a crash between them
    /// left the nonce used and the total short, and no retry could repair it,
    /// because a retry sees the nonce used and treats the output as already
    /// issued. The mark and the total are in the same sled tree, so one
    /// transaction covers them.
    ///
    /// Errors, all with nothing written: the stored issued total is not 16
    /// bytes (`corrupt total: expected 16 bytes, got N`), or adding `amount`
    /// would overflow it (`the issued total would overflow`), or the storage
    /// fails.
    ///
    /// Only the two reads and two writes are inside the transaction. sled may
    /// run a transaction's closure more than once when it conflicts, so
    /// nothing else (signing, logging, counters) may go in it.
    pub fn claim_issue(&self, blind_nonce: &BlindNonce, amount: Amount) -> anyhow::Result<bool> {
        let nonce_key = Self::blind_nonce_key(blind_nonce);
        claimed(self.db.transaction(|tx| {
            if tx.get(nonce_key.as_slice())?.is_some() {
                return Ok(false);
            }
            let total = tx_add(tx_total(tx, &ISSUED_TOTAL_KEY)?, amount, "issued")?;
            tx.insert(nonce_key.as_slice(), &[0u8; 0][..])?;
            #[cfg(test)]
            failpoint::between_the_writes()?;
            tx.insert(&ISSUED_TOTAL_KEY[..], &total.to_be_bytes()[..])?;
            Ok(true)
        }))
    }

    /// Marks `nonce` spent and adds `amount` to the redeemed total as one sled
    /// transaction, the redeem side of [`Store::claim_issue`]. Returns `true` if
    /// this call spent the nonce, `false` if it was already spent (the
    /// double-spend case, **extremely safety critical**; nothing is written
    /// then).
    ///
    /// *Why one transaction:* with two separate writes, a crash between them
    /// left the note spent and the redeemed total short for good, so the
    /// outstanding supply was overstated and nothing could repair it. The
    /// spent mark and the total are in the same sled tree, so one transaction
    /// covers them.
    ///
    /// Errors, all with nothing written: the stored redeemed total is not 16
    /// bytes (`corrupt total: expected 16 bytes, got N`), or adding `amount`
    /// would overflow it (`the redeemed total would overflow`), or the storage
    /// fails. As with `claim_issue`, only the reads and writes of the
    /// transaction go inside it, since sled may run the closure again.
    pub fn claim_redeem(&self, nonce: &Nonce, amount: Amount) -> anyhow::Result<bool> {
        let nonce_key = Self::nonce_key(nonce);
        claimed(self.db.transaction(|tx| {
            if tx.get(nonce_key.as_slice())?.is_some() {
                return Ok(false);
            }
            let total = tx_add(tx_total(tx, &REDEEMED_TOTAL_KEY)?, amount, "redeemed")?;
            tx.insert(nonce_key.as_slice(), &[0u8; 0][..])?;
            #[cfg(test)]
            failpoint::between_the_writes()?;
            tx.insert(&REDEEMED_TOTAL_KEY[..], &total.to_be_bytes()[..])?;
            Ok(true)
        }))
    }

    fn read_total(&self, key: &[u8]) -> anyhow::Result<u128> {
        match self.db.get(key)? {
            Some(bytes) => {
                let arr: [u8; TOTAL_LEN] = bytes.as_ref().try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "corrupt total: expected {TOTAL_LEN} bytes, got {}",
                        bytes.len()
                    )
                })?;
                Ok(u128::from_be_bytes(arr))
            }
            None => Ok(0),
        }
    }

    pub fn issued_total(&self) -> anyhow::Result<u128> {
        self.read_total(&ISSUED_TOTAL_KEY)
    }

    pub fn redeemed_total(&self) -> anyhow::Result<u128> {
        self.read_total(&REDEEMED_TOTAL_KEY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{SECP256K1, SecretKey};

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("mint-core-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn blind_nonce() -> BlindNonce {
        BlindNonce(SecretKey::new(&mut rand::thread_rng()).public_key(SECP256K1))
    }

    #[test]
    fn claim_issue_marks_the_nonce_and_adds_the_amount_once() {
        let d = dir("claim");
        let store = Store::open(&d).unwrap();
        let b = blind_nonce();
        assert!(store.claim_issue(&b, Amount::from_units(4)).unwrap());
        assert!(store.is_blind_nonce_used(&b).unwrap());
        assert_eq!(store.issued_total().unwrap(), 4);
        // a second claim of the same nonce changes nothing
        assert!(!store.claim_issue(&b, Amount::from_units(4)).unwrap());
        assert_eq!(store.issued_total().unwrap(), 4);
        drop(store);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn many_claims_add_up_and_every_nonce_is_used() {
        let d = dir("many");
        let store = Store::open(&d).unwrap();
        let nonces: Vec<BlindNonce> = (0..200).map(|_| blind_nonce()).collect();
        for b in &nonces {
            assert!(store.claim_issue(b, Amount::from_units(3)).unwrap());
        }
        assert_eq!(store.issued_total().unwrap(), 600);
        assert!(nonces.iter().all(|b| store.is_blind_nonce_used(b).unwrap()));
        drop(store);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_failure_between_the_two_writes_writes_neither_and_survives_a_restart() {
        let d = dir("crash");
        let store = Store::open(&d).unwrap();
        let first = blind_nonce();
        assert!(store.claim_issue(&first, Amount::from_units(2)).unwrap());

        // the crash: stop after the nonce is written and before the total is
        failpoint::ABORT_BETWEEN_THE_WRITES.with(|f| f.set(true));
        let lost = blind_nonce();
        let err = store.claim_issue(&lost, Amount::from_units(5)).unwrap_err();
        assert!(err.to_string().contains("injected"), "{err}");
        failpoint::ABORT_BETWEEN_THE_WRITES.with(|f| f.set(false));

        // neither write happened: the nonce is unused and the total is unchanged
        assert!(!store.is_blind_nonce_used(&lost).unwrap());
        assert_eq!(store.issued_total().unwrap(), 2);

        // and the same after a restart
        drop(store);
        let store = Store::open(&d).unwrap();
        assert!(!store.is_blind_nonce_used(&lost).unwrap());
        assert!(store.is_blind_nonce_used(&first).unwrap());
        assert_eq!(store.issued_total().unwrap(), 2);

        // the retry then claims it and adds it exactly once
        assert!(store.claim_issue(&lost, Amount::from_units(5)).unwrap());
        assert_eq!(store.issued_total().unwrap(), 7);
        drop(store);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn totals_are_16_bytes_and_hold_more_than_u64_max() {
        // Fails with u64 totals (before 0.3.0): the second issue is refused with
        // "the issued total would overflow", and an 8-byte total cannot hold it.
        let d = dir("wide");
        let store = Store::open(&d).unwrap();
        let big = Amount::from_units(u64::MAX);
        for _ in 0..3 {
            assert!(store.claim_issue(&blind_nonce(), big).unwrap());
        }
        // 3 * (2^64 - 1)
        assert_eq!(store.issued_total().unwrap(), 55_340_232_221_128_654_845);
        assert_eq!(
            store.db.get(&ISSUED_TOTAL_KEY[..]).unwrap().unwrap().len(),
            16
        );
        drop(store);
        let store = Store::open(&d).unwrap();
        assert_eq!(store.issued_total().unwrap(), 55_340_232_221_128_654_845);
        drop(store);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_total_of_the_old_8_byte_format_or_an_overflow_is_an_error_and_writes_nothing() {
        // Fails if a reader for the old 8-byte totals comes back, or if a claim
        // writes its mark before the total is checked (not one transaction).
        let d = dir("bad-total");
        let store = Store::open(&d).unwrap();
        let (b, n) = (
            blind_nonce(),
            Nonce(SecretKey::new(&mut rand::thread_rng()).public_key(SECP256K1)),
        );
        let one = Amount::from_units(1);
        for key in [ISSUED_TOTAL_KEY, REDEEMED_TOTAL_KEY] {
            store.db.insert(&key[..], &7u64.to_be_bytes()[..]).unwrap();
        }
        let err = store.claim_issue(&b, one).unwrap_err();
        assert_eq!(err.to_string(), "corrupt total: expected 16 bytes, got 8");
        let err = store.claim_redeem(&n, one).unwrap_err();
        assert_eq!(err.to_string(), "corrupt total: expected 16 bytes, got 8");
        assert!(store.issued_total().is_err() && store.redeemed_total().is_err());
        assert!(!store.is_blind_nonce_used(&b).unwrap() && !store.is_nonce_spent(&n).unwrap());

        for key in [ISSUED_TOTAL_KEY, REDEEMED_TOTAL_KEY] {
            store
                .db
                .insert(&key[..], &u128::MAX.to_be_bytes()[..])
                .unwrap();
        }
        let err = store.claim_issue(&b, one).unwrap_err();
        assert_eq!(err.to_string(), "the issued total would overflow");
        let err = store.claim_redeem(&n, one).unwrap_err();
        assert_eq!(err.to_string(), "the redeemed total would overflow");
        assert!(!store.is_blind_nonce_used(&b).unwrap() && !store.is_nonce_spent(&n).unwrap());
        assert_eq!(
            (
                store.issued_total().unwrap(),
                store.redeemed_total().unwrap()
            ),
            (u128::MAX, u128::MAX)
        );
        drop(store);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
