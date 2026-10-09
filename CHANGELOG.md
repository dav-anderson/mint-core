# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/dav-anderson/mint-core/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/dav-anderson/mint-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/dav-anderson/mint-core/releases/tag/v0.1.0
