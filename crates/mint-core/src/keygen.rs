//! Single-party key generation.

use std::collections::BTreeMap;

use mint_types::{Amount, MintConfig};
use secp256k1::{SecretKey, SECP256K1};

/// Generate a fresh keypair set, one per denomination tier.
pub fn generate(denominations: &[Amount]) -> MintConfig {
    let sk: BTreeMap<Amount, SecretKey> = denominations
        .iter()
        .map(|&amount| (amount, SecretKey::new(&mut rand::thread_rng())))
        .collect();

    MintConfig { sk }
}

/// Derive the public keys (one per denomination) that clients need in order
/// to blind their withdrawal/swap requests against this mint. Safe to
/// publish; `MintConfig.sk` itself must never leave the server.
pub fn public_keys(cfg: &MintConfig) -> BTreeMap<Amount, secp256k1::PublicKey> {
    cfg.sk
        .iter()
        .map(|(&amount, sk)| (amount, sk.public_key(&SECP256K1)))
        .collect()
}
