//! Durable state this mint keeps: the spent-nonce set (double-spend
//! prevention), the used-blind-nonce set (stops a client from accidentally
//! burning a note by reusing a blinding factor), and running issued/redeemed
//! totals for the `/audit` endpoint.
//!
//! A thin wrapper around `sled`, a pure-Rust embedded key-value store, so
//! this crate needs no C/C++ toolchain to build.
//!
//! `MintLogic`'s callers are expected to serialize
//! mutating calls (`issue`/`redeem`/`swap`/`melt`), see `server::AppState`, which
//! holds `MintLogic` behind a single `std::sync::Mutex`. That's what makes
//! the read-then-write sequences below (check a nonce isn't spent, then
//! mark it) safe: there's exactly one in-process writer at a time. A
//! multi-process or multi-writer deployment would need real transactions
//! here; a single `mintd` process does not.

use std::fmt;
use std::path::Path;

use mint_types::{Amount, BlindNonce, Nonce};
use sled::transaction::{ConflictableTransactionError, TransactionError};

const NONCE_PREFIX: u8 = 0x10;
const BLIND_NONCE_PREFIX: u8 = 0x16;
const ISSUED_TOTAL_KEY: [u8; 1] = [0x20];
const REDEEMED_TOTAL_KEY: [u8; 1] = [0x21];

pub struct Store {
    db: sled::Db,
}

/// Why the issue transaction stopped without writing anything.
#[derive(Debug)]
enum IssueAbort {
    /// The stored issued total is not 8 bytes.
    CorruptTotal(usize),
    /// Adding the amount would overflow the issued total.
    Overflow,
    /// A test stopped the transaction between its two writes.
    #[cfg(test)]
    Injected,
}

impl fmt::Display for IssueAbort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssueAbort::CorruptTotal(n) => {
                write!(f, "corrupt total: expected 8 bytes, got {n}")
            }
            IssueAbort::Overflow => write!(f, "the issued total would overflow"),
            #[cfg(test)]
            IssueAbort::Injected => write!(f, "injected failure between the two writes"),
        }
    }
}

/// A test-only way to stop `claim_issue` between its two writes.
#[cfg(test)]
pub(crate) mod failpoint {
    use std::cell::Cell;

    use sled::transaction::ConflictableTransactionError;

    use super::IssueAbort;

    thread_local! {
        pub static ABORT_BETWEEN_THE_WRITES: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn between_the_writes() -> Result<(), ConflictableTransactionError<IssueAbort>> {
        if ABORT_BETWEEN_THE_WRITES.with(|f| f.get()) {
            Err(ConflictableTransactionError::Abort(IssueAbort::Injected))
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

    /// Marks `nonce` spent. Returns `true` if this call is the one that
    /// spent it, `false` if it was already spent (the double-spend case --
    /// **extremely safety critical**).
    pub fn mark_nonce_spent(&self, nonce: &Nonce) -> anyhow::Result<bool> {
        let prior = self.db.insert(Self::nonce_key(nonce), &[][..])?;
        Ok(prior.is_none())
    }

    pub fn is_blind_nonce_used(&self, blind_nonce: &BlindNonce) -> anyhow::Result<bool> {
        Ok(self.db.contains_key(Self::blind_nonce_key(blind_nonce))?)
    }

    /// Returns `true` if this call is the one that claimed `blind_nonce`,
    /// `false` if it was already used.
    ///
    /// This writes the mark alone. `MintLogic::issue_with_key` does not use it:
    /// it uses [`Store::claim_issue`], which also adds to the issued total in
    /// the same transaction.
    pub fn mark_blind_nonce_used(&self, blind_nonce: &BlindNonce) -> anyhow::Result<bool> {
        let prior = self
            .db
            .insert(Self::blind_nonce_key(blind_nonce), &[][..])?;
        Ok(prior.is_none())
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
    /// Only the two reads and two writes are inside the transaction. sled may
    /// run a transaction's closure more than once when it conflicts, so
    /// nothing else (signing, logging, counters) may go in it.
    pub fn claim_issue(&self, blind_nonce: &BlindNonce, amount: Amount) -> anyhow::Result<bool> {
        let nonce_key = Self::blind_nonce_key(blind_nonce);
        let outcome = self.db.transaction(|tx| {
            if tx.get(nonce_key.as_slice())?.is_some() {
                return Ok(false);
            }
            let prior: u64 = match tx.get(&ISSUED_TOTAL_KEY[..])? {
                Some(bytes) => match <[u8; 8]>::try_from(bytes.as_ref()) {
                    Ok(arr) => u64::from_be_bytes(arr),
                    Err(_) => {
                        return Err(ConflictableTransactionError::Abort(
                            IssueAbort::CorruptTotal(bytes.len()),
                        ));
                    }
                },
                None => 0,
            };
            let Some(total) = prior.checked_add(amount.units) else {
                return Err(ConflictableTransactionError::Abort(IssueAbort::Overflow));
            };
            tx.insert(nonce_key.as_slice(), &[0u8; 0][..])?;
            #[cfg(test)]
            failpoint::between_the_writes()?;
            tx.insert(&ISSUED_TOTAL_KEY[..], &total.to_be_bytes()[..])?;
            Ok(true)
        });
        match outcome {
            Ok(newly_claimed) => Ok(newly_claimed),
            Err(TransactionError::Abort(why)) => Err(anyhow::anyhow!("{why}")),
            Err(TransactionError::Storage(e)) => Err(e.into()),
        }
    }

    fn read_total(&self, key: &[u8]) -> anyhow::Result<Amount> {
        match self.db.get(key)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.as_ref().try_into().map_err(|_| {
                    anyhow::anyhow!("corrupt total: expected 8 bytes, got {}", bytes.len())
                })?;
                Ok(Amount::from_units(u64::from_be_bytes(arr)))
            }
            None => Ok(Amount::ZERO),
        }
    }

    fn write_total(&self, key: &[u8], total: Amount) -> anyhow::Result<()> {
        self.db.insert(key, &total.units.to_be_bytes())?;
        Ok(())
    }

    pub fn issued_total(&self) -> anyhow::Result<Amount> {
        self.read_total(&ISSUED_TOTAL_KEY)
    }

    pub fn redeemed_total(&self) -> anyhow::Result<Amount> {
        self.read_total(&REDEEMED_TOTAL_KEY)
    }

    pub fn add_issued(&self, amount: Amount) -> anyhow::Result<()> {
        let total = self.issued_total()? + amount;
        self.write_total(&ISSUED_TOTAL_KEY, total)
    }

    pub fn add_redeemed(&self, amount: Amount) -> anyhow::Result<()> {
        let total = self.redeemed_total()? + amount;
        self.write_total(&REDEEMED_TOTAL_KEY, total)
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
        BlindNonce(SecretKey::new(&mut rand::thread_rng()).public_key(&SECP256K1))
    }

    #[test]
    fn claim_issue_marks_the_nonce_and_adds_the_amount_once() {
        let d = dir("claim");
        let store = Store::open(&d).unwrap();
        let b = blind_nonce();
        assert!(store.claim_issue(&b, Amount::from_units(4)).unwrap());
        assert!(store.is_blind_nonce_used(&b).unwrap());
        assert_eq!(store.issued_total().unwrap(), Amount::from_units(4));
        // a second claim of the same nonce changes nothing
        assert!(!store.claim_issue(&b, Amount::from_units(4)).unwrap());
        assert_eq!(store.issued_total().unwrap(), Amount::from_units(4));
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
        assert_eq!(store.issued_total().unwrap(), Amount::from_units(600));
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
        assert_eq!(store.issued_total().unwrap(), Amount::from_units(2));

        // and the same after a restart
        drop(store);
        let store = Store::open(&d).unwrap();
        assert!(!store.is_blind_nonce_used(&lost).unwrap());
        assert!(store.is_blind_nonce_used(&first).unwrap());
        assert_eq!(store.issued_total().unwrap(), Amount::from_units(2));

        // the retry then claims it and adds it exactly once
        assert!(store.claim_issue(&lost, Amount::from_units(5)).unwrap());
        assert_eq!(store.issued_total().unwrap(), Amount::from_units(7));
        drop(store);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_database_written_the_old_way_opens_and_keeps_counting() {
        let d = dir("old-db");
        let store = Store::open(&d).unwrap();
        // the old two-step issue
        let old = blind_nonce();
        assert!(store.mark_blind_nonce_used(&old).unwrap());
        store.add_issued(Amount::from_units(6)).unwrap();
        drop(store);

        let store = Store::open(&d).unwrap();
        assert!(store.is_blind_nonce_used(&old).unwrap());
        assert_eq!(store.issued_total().unwrap(), Amount::from_units(6));
        assert!(!store.claim_issue(&old, Amount::from_units(6)).unwrap());
        assert!(store.claim_issue(&blind_nonce(), Amount::from_units(1)).unwrap());
        assert_eq!(store.issued_total().unwrap(), Amount::from_units(7));
        drop(store);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_corrupt_total_or_an_overflow_is_an_error_and_writes_nothing() {
        let d = dir("bad-total");
        let store = Store::open(&d).unwrap();
        store.db.insert(&ISSUED_TOTAL_KEY[..], &[1u8, 2][..]).unwrap();
        let b = blind_nonce();
        let err = store.claim_issue(&b, Amount::from_units(1)).unwrap_err();
        assert!(err.to_string().contains("corrupt total"), "{err}");
        assert!(!store.is_blind_nonce_used(&b).unwrap());

        store
            .db
            .insert(&ISSUED_TOTAL_KEY[..], &u64::MAX.to_be_bytes()[..])
            .unwrap();
        let err = store.claim_issue(&b, Amount::from_units(1)).unwrap_err();
        assert!(err.to_string().contains("overflow"), "{err}");
        assert!(!store.is_blind_nonce_used(&b).unwrap());
        assert_eq!(store.issued_total().unwrap(), Amount::from_units(u64::MAX));
        drop(store);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
