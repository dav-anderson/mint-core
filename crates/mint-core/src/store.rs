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

use std::path::Path;

use mint_types::{Amount, BlindNonce, Nonce};

const NONCE_PREFIX: u8 = 0x10;
const BLIND_NONCE_PREFIX: u8 = 0x16;
const ISSUED_TOTAL_KEY: [u8; 1] = [0x20];
const REDEEMED_TOTAL_KEY: [u8; 1] = [0x21];

pub struct Store {
    db: sled::Db,
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
    pub fn mark_blind_nonce_used(&self, blind_nonce: &BlindNonce) -> anyhow::Result<bool> {
        let prior = self
            .db
            .insert(Self::blind_nonce_key(blind_nonce), &[][..])?;
        Ok(prior.is_none())
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
