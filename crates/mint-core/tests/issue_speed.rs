//! A quick benchmark of `MintLogic::issue_with_key`, for comparing a build
//! before and after a change to how issuing writes its state.
//!
//! It is ignored by default, so a plain `cargo test` skips it. Run it in
//! release mode:
//!
//! ```text
//! cargo test --release --offline -p mint-core --test issue_speed -- --ignored --nocapture
//! ```
//!
//! It uses only the public API, so the same file runs against an older tag
//! (see `bench-issue.sh` in the sandbox-mint folder). Each run issues
//! `ISSUES` outputs one after another into a fresh database, five times, and
//! prints issues a second for each run and the median. Sled flushes in the
//! background, so this measures the call, not a disk sync per issue.

use std::time::Instant;

use mint_core::{MintLogic, keygen, store::Store};
use mint_types::{Amount, BlindNonce, DEFAULT_DENOMINATION_BASE, MintOutput, gen_denominations};
use secp256k1::{SECP256K1, SecretKey};

const ISSUES: usize = 20_000;
const RUNS: usize = 5;

#[test]
#[ignore = "benchmark: run with --release --ignored --nocapture"]
fn issue_with_key_speed() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let mut rates = Vec::new();
    for run in 0..RUNS {
        let dir = std::env::temp_dir().join(format!(
            "mint-core-issue-speed-{}-{run}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = keygen::generate(&gen_denominations(
            DEFAULT_DENOMINATION_BASE,
            Amount::from_units(8),
        ));
        let logic = MintLogic::new(cfg, Store::open(&dir).unwrap());
        // The blind nonces are made before the clock starts.
        let outputs: Vec<MintOutput> = (0..ISSUES)
            .map(|_| MintOutput {
                amount: Amount::from_units(4),
                blind_nonce: BlindNonce(
                    SecretKey::new(&mut rand::thread_rng()).public_key(SECP256K1),
                ),
            })
            .collect();
        let start = Instant::now();
        for o in &outputs {
            logic.issue_with_key(&sk, o).unwrap();
        }
        let secs = start.elapsed().as_secs_f64();
        let (issued, _) = logic.audit_totals().unwrap();
        assert_eq!(issued, 4 * ISSUES as u128);
        let rate = ISSUES as f64 / secs;
        println!(
            "run {run}: {ISSUES} issues in {secs:.3} s = {rate:.0} issues/s ({:.1} us each)",
            1e6 * secs / ISSUES as f64
        );
        rates.push(rate);
        drop(logic);
        let _ = std::fs::remove_dir_all(&dir);
    }
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!("median: {:.0} issues/s", rates[RUNS / 2]);
}
