# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/dav-anderson/mint-core/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/dav-anderson/mint-core/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/dav-anderson/mint-core/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/dav-anderson/mint-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/dav-anderson/mint-core/releases/tag/v0.1.0
