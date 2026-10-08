//! Startup configuration: where to store data, and the admin credential
//! gating unilateral issuance. Loaded entirely from environment variables.

use std::path::PathBuf;

use mint_types::Amount;

pub struct Settings {
    pub bind_addr: String,
    pub data_dir: PathBuf,
    /// Bearer-style token required for `admin_issue`. There is no default:
    /// refusing to start without one is deliberate, since this is the
    /// entire unilateral-issuance mechanism, an unauthenticated version of
    /// it is an unauthenticated money printer.
    pub admin_token: String,
    pub max_denomination: Amount,
}

impl Settings {
    pub fn from_env() -> anyhow::Result<Self> {
        let bind_addr =
            std::env::var("MINT_BIND").unwrap_or_else(|_| "127.0.0.1:3000".into());
        let data_dir = std::env::var("MINT_DATA_DIR").unwrap_or_else(|_| "./data".into());
        let admin_token = std::env::var("MINT_ADMIN_TOKEN").map_err(|_| {
            anyhow::anyhow!(
                "MINT_ADMIN_TOKEN must be set -- it's the only thing gating unilateral \
                 issuance. Generate one yourself, e.g.: openssl rand -hex 32"
            )
        })?;

        // A plain count of this mint's own unit. Default gives a
        // denomination ladder of 1, 2, 4, ... up to 2^20.
        let max_denomination_units: u64 = std::env::var("MINT_MAX_DENOMINATION")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1_048_576);

        Ok(Self {
            bind_addr,
            data_dir: PathBuf::from(data_dir),
            admin_token,
            max_denomination: Amount::from_units(max_denomination_units),
        })
    }
}
