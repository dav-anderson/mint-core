//! Startup: load or generate this mint's keypair, open the store.

use std::path::Path;
use std::sync::Mutex;

use mint_core::MintLogic;
use mint_core::store::Store;
use mint_types::MintConfig;
use tracing::info;

use crate::config::Settings;

const KEYS_FILENAME: &str = "mint_keys.json";

pub struct AppState {
    /// A single mutex around all mutating operations. This is a
    /// single-process, single-writer server. Only one request mutates state at a
    /// time. See `mint-core::store`'s doc comment for why that's what makes
    /// its read-then-write sequences safe.
    pub logic: Mutex<MintLogic>,
    pub admin_token: String,
}

impl AppState {
    pub async fn init(settings: &Settings) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&settings.data_dir)?;

        let cfg = load_or_generate_config(settings)?;

        let db_path = settings.data_dir.join("db");
        let store = Store::open(&db_path)?;

        Ok(Self {
            logic: Mutex::new(MintLogic::new(cfg, store)),
            admin_token: settings.admin_token.clone(),
        })
    }
}

fn load_or_generate_config(settings: &Settings) -> anyhow::Result<MintConfig> {
    let path = settings.data_dir.join(KEYS_FILENAME);

    if path.exists() {
        info!(?path, "loading existing mint keys");
        let bytes = std::fs::read(&path)?;
        let cfg: MintConfig = serde_json::from_slice(&bytes)?;
        return Ok(cfg);
    }

    info!(?path, "no existing keys found, generating a new mint keypair");
    let denominations = mint_types::gen_denominations(
        mint_types::DEFAULT_DENOMINATION_BASE,
        settings.max_denomination,
    );
    let cfg = mint_core::keygen::generate(&denominations);

    write_keys_restricted(&path, &cfg)?;
    info!(
        denominations = denominations.len(),
        max = %settings.max_denomination,
        "generated {} denomination tiers up to {}",
        denominations.len(),
        settings.max_denomination,
    );

    Ok(cfg)
}

/// Write the keyfile with 0600 permissions where possible. It is the
/// entire secret behind every note this mint will ever issue.
/// Losing it means losing the ability to redeem outstanding notes; leaking
/// it means anyone can forge notes indistinguishable from real ones.
fn write_keys_restricted(path: &Path, cfg: &MintConfig) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(cfg)?;
    std::fs::write(path, bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}
