# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-10-25

Breaking: `Amount` loses `Add` and `AddAssign`, the totals are `u128` and stored differently, and four `Store` functions are gone. A database written by v0.2.0 or earlier still opens with `Store::open`, but every claim (`claim_issue`, `claim_redeem`) and every read of a total (`audit_totals`) on it is an error and writes nothing (clean break; no reader or migration for the old totals). The mints (esp-mint 0.9.0, psp-mint 0.7.0) read the totals at start, so they refuse to start on such a database.

### Fixed
- **A generation stopped issuing at `u64::MAX` units (ROADMAP item 31, P1-02).** The issued and redeemed totals were `u64`, stored as 8 bytes; an issue that would pass `u64::MAX` (about $18.4M at 10^-12 USD per unit) was refused with "the issued total would overflow", and so was every later issue in that generation. The totals are now `u128`, stored as 16 bytes big-endian, with checked adds. A stored total of any other length is an error (`corrupt total: expected 16 bytes, got N`) and writes nothing, as is an add that would overflow `u128`. `Store::issued_total`, `Store::redeemed_total` and `MintLogic::audit_totals` return `u128`.
- **A redeem was two writes (P1-03).** `redeem_with_key` marked the nonce spent, then added to the redeemed total in a separate write; a crash between them left the note spent and the total short for good. The new `Store::claim_redeem(nonce, amount)` does both in one sled transaction, as `claim_issue` has done for the issue side since v0.1.3: it reads the spent mark and the total, answers `false` (`SpentCoin`) if the note is spent, errors on a corrupt or overflowing total, and otherwise writes both. Only those reads and writes are inside it. `redeem_with_key`, `swap` and `melt` use it. The test failpoint between the two writes now serves both claims.
- **Amount sums could wrap.** `Amount` had unchecked `+` and `+=`: in a release build `swap` accepted outputs `[2^63, 2^63, 1]` (which wrap to 1) against a one-unit input. `swap` and `melt` sum in `u128`, and `melt` refuses a total that does not fit an `Amount` before it redeems anything. `SwapError::Unbalanced` carries `u128` totals.

### Removed
- `Add` and `AddAssign` for `Amount` (mint-types). Use `Amount::checked_add` (new, returns `Option<Amount>`) or add `units` in `u128`.
- `Store::add_issued`, `Store::add_redeemed`, `Store::mark_nonce_spent` and `Store::mark_blind_nonce_used`: after `claim_redeem`, none has a caller in this crate or in any mint repo. The test `a_database_written_the_old_way_opens_and_keeps_counting` went with them.

### Changed
- `MintLogic::audit_totals` returns `(u128, u128)`.

### Tests
- Added: the `u64::MAX` boundary and one unit more (`a_generation_issues_up_to_u64_max_and_one_unit_more`), totals past `u64::MAX` that are 16 bytes and read back after a restart, a crash between the two writes of a redeem (`a_crash_between_the_two_writes_of_a_redeem_leaves_the_note_unspent_and_the_total_right`). `a_corrupt_total_or_an_overflow_is_an_error_and_writes_nothing` became `a_total_of_the_old_8_byte_format_or_an_overflow_is_an_error_and_writes_nothing`, for both totals, with the overflow at `u128::MAX`.

## [0.2.0]

### Removed
- **The `server` crate (`mint-server`, the `mintd` binary and `examples/smoke_test.rs`).** It was the standalone mint this workspace started as; nothing runs it. The mint repos used only its `AppState` and some JSON types from it, and it pulled `axum`, `tokio`, `tracing`, `tracing-subscriber` and `subtle` into this workspace. The workspace dependencies only it used are gone too (`axum`, `tokio`, `tracing`, `tracing-subscriber`, `serde_json`). Breaking: `mint_server::state::AppState` and `mint_server::api::*` no longer exist. `KeysResponse`, `CheckStateRequest` and `CheckStateResponse` are in `sp_wire::keys`, `MeltRequest` and `MeltResponse` in `sp_wire::melt`, and `AuditResponse` was only ever `{issued, redeemed, outstanding}`, which each mint builds itself.
- `AppState::admin_token` (only `mintd`'s `/admin/issue` read it) and `AppState::init` with `Settings` and the keyfile loading, which are each mint's own startup.

### Added
- `mint_core::state::AppState { logic: Mutex<MintLogic> }`, moved from `mint-server` with its doc comment on the single-writer rule.

### Changed
- `cargo fmt` (edition 2024) and `cargo clippy -D warnings` are clean across the workspace: import order and long lines in `keygen.rs`, `lib.rs`, `store.rs`, `tests/issue_speed.rs`, `mint-types` and `bdhke`; doc comments in `mint-types` no longer have a blank line after them; `&SECP256K1` is `SECP256K1` where a reference is expected. No behaviour change.
- `rust-version` 1.85 to 1.93. README: the `server` row, the HTTP API, wire format, running and smoke-test sections are gone.
## [0.1.3]

### Fixed
- `mint-core`: `MintLogic::issue_with_key` (and so `issue`) now marks the blind nonce used and adds to the issued total in one sled transaction (`Store::claim_issue`). Before, they were two separate writes, and a crash between them left the nonce used and the issued total short by that output. A retry could not repair it, because the retry sees the nonce already used and treats the output as issued. The mark and the total are keys in the same sled tree, so one transaction covers both. Only those two reads and two writes are inside the transaction, because sled may run a transaction's closure more than once on a conflict.
- The signature is made after the transaction commits. A stop after the commit and before the caller has the signature leaves the nonce used and the total right; the caller signs again (deterministic) and adds nothing.
- This stops new drift. It does not repair totals that are already short: nothing in a database records which outputs were counted, so there is nothing to recompute from.
- An issued total that would overflow `u64` is now an error and writes nothing (before, it panicked in debug builds and wrapped in release builds). A stored total that is not 8 bytes is an error and writes nothing.

### Added
- `Store::claim_issue`. `mark_blind_nonce_used` and `add_issued` are kept, unchanged, for callers that used them.
- Tests: an injected failure between the two writes (neither is written, also after a restart), a database written the old two-step way opens and keeps counting, a corrupt or overflowing total writes nothing, and 200 claims add up.
- `tests/issue_speed.rs`, an ignored benchmark of `issue_with_key`.

## [0.1.2]

### Added
- `mint-core`: `MintLogic::issue_with_key`, `verify_note_with_key` and `redeem_with_key`. They take the signing key from the caller instead of looking it up by amount, for mints whose key depends on more than the amount. `issue`, `verify_note`, `swap` and `melt` behave as before.

## [0.1.1]

### Added
- `mint-core`: `MintLogic::is_blind_nonce_used`, a read-only check that lets a caller refuse a batch of outputs before `issue` burns any of them.

## [0.1.0]

First tagged release.

### Added
- `bdhke`: the blind-signature primitive (hash to curve, blind, sign, unblind, verify) with test vectors.
- `mint-types`: notes, nonces, amounts, `transaction_sighash` and `melt_sighash`.
- `mint-core`: `MintLogic` with issue, swap and melt, backed by a sled store.
- `mint-server`: the Axum HTTP API (`/keys`, `/admin/issue`, `/swap`, `/melt`, `/check-state`, `/audit`) and the `mintd` binary.

[Unreleased]: https://github.com/dav-anderson/mint-core/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/dav-anderson/mint-core/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/dav-anderson/mint-core/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/dav-anderson/mint-core/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/dav-anderson/mint-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/dav-anderson/mint-core/releases/tag/v0.1.0
