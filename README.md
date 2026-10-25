# mint-core

Shared utilities for Chaumian ecash mints. The PSP, ESP and FSP mints each live in their own repo, depend on this one, and add their own issuance middleware on top.

The mint can issue notes arbitrarily, with
no requirement that they be backed by a real-world deposit. Two users can
transact with each other through it without the mint being able to link who
sent what to whom.

This workspace's only cryptographic dependencies are the `secp256k1` and `sha2` crates.

## What's in here

| Crate | What it is |
|---|---|
| `crypto/bdhke` | The blind-signature primitive: `hash_to_curve`, `blind_message`, `sign_message`, `unblind_message`, `verify_message`. ~150 lines, tested against test vectors borrowed from Cashu's NUT-00 spec. |
| `crates/mint-types` | `Amount` (a plain opaque unit count), `Note`/`Nonce`/`BlindNonce`, `MintInput`/`MintOutput`, the `transaction_sighash` and `melt_sighash` spend-authorization schemes (see below), denomination generation, `MintConfig`. |
| `crates/mint-core` | `MintLogic`: `verify_note`, `verify_spend_authorization`, `redeem`, `issue`, `swap`, `melt`, plus `store::Store` -- a thin wrapper around `sled` (a pure-Rust embedded KV store, chosen specifically so this crate needs no C/C++ toolchain to build), and `state::AppState`: `MintLogic` behind a single `std::sync::Mutex`, which the mint repos share between their API, listeners and scanners (this is a single-writer design -- see `AppState`'s doc comment and `store.rs` for why that's the whole correctness story, not a shortcut). |

## On backing

`MintLogic::issue`, the function that blind-signs a note into existence,
is **unconditional**, on purpose. Nothing in this codebase cryptographically enforces that issued value is backed by anything. Deciding when to call it is the job of each mint repo's middleware.

The entire mechanism separating "arbitrary issuance" from "a bug that lets
anyone print money" is in the callers: `issue()` is the one function that signs
a note into existence, so a mint must call it only for something it has checked
(a payment, a burn, a swap). `swap` is the other way in, and it explicitly
checks `input_total >= output_total` before issuing anything (see
`MintLogic::swap`). `melt` never calls `issue()` at all. This crate has no
server and no administrator route: a mint repo that exposes `issue()` to anyone
has made itself a mint anyone can print from.

The `issued`/`redeemed` totals (`MintLogic::audit_totals`) are `u128`, stored as
16 bytes big-endian (since v0.3.0; they were `u64`, and a generation stopped
issuing when its issued total reached `u64::MAX`, about 1.8e19 units). Every add
is checked: a total that would overflow is an error and writes nothing. A stored
total of any other length is an error too, and there is no reader for the
8-byte totals of v0.2.0 and earlier: such a database still opens, but every
claim and every read of a total on it is an error and writes nothing (the mints
read the totals at start, so they refuse to start on it). The totals
are bookkeeping, not a solvency proof: nothing here is independently verifiable
by a party who isn't the mint operator.

**The redeemed total and the spent mark are one write** (since v0.3.0). `redeem_with_key` (and so `swap` and `melt`) marks the note's nonce spent and adds its amount to the redeemed total in a single sled transaction (`Store::claim_redeem`), the same shape as the issue side below. Before, they were two writes, and a crash between them left the note spent and the redeemed total short for good, so the outstanding supply was overstated. A second redeem of a spent note is `SpentCoin` and adds nothing.

**The issued total and the blind-nonce mark are one write** (since v0.1.3). `issue` and `issue_with_key` mark the output's blind nonce used and add its amount to the issued total in a single sled transaction (`Store::claim_issue`), then sign. Before, they were two writes, and a crash between them left the total short by that output for good (a retry sees the nonce used and treats the output as issued). The fix stops new drift. It does not repair a total that is already short. sled is a stand-in for the storage the mints will have in the AIR, and that storage must keep the same rule: the nonce mark and the total update are one atomic step.

## Spend authorization

A note's mint signature proves it's genuine; it says nothing about who's
currently allowed to spend it, to which outputs. Without a separate check,
anyone who had ever *seen* a note's data (a relay, a compromised swap
endpoint, a logging mistake) could submit it as an input paired with outputs
of their own choosing and steal it before its rightful holder did. This is
fixed by giving every note's `Nonce` double duty: it's both the note's
identity (its serialized bytes are what gets hashed to a curve point for
BDHKE) *and* a secp256k1 keypair, whose private half only the holder knows.

Spending a note means Schnorr-signing `transaction_sighash(inputs, outputs)` which is a hash committing to the *entire* swap request, not just "I own this
note" in isolation. Verified in `MintLogic::verify_spend_authorization`, checked for every input before `swap` touches storage.

A melt signs `melt_sighash(inputs, memo)` instead. It is domain-separated, so a swap signature can't be replayed as a melt or the other way round. The `memo` lets the caller tie the burn to something outside this mint, for example a hash of outputs issued elsewhere. `melt` checks every input before burning any of them. 

**If you write your own client based on this implementation logic, treat `MintInput` construction and the sighash functions as the single most security-critical code path in this repo.**

## Notes on BDHKE

Plain BDHKE is **not publicly verifiable**. Given only the mint's public key for a denomination, there is no way to confirm a signature is genuine. Doing so would require either the mint's own private key, or an additional non-interactive proof (a "DLEQ proof"). This implementation does not implement one. This carries two consequences worth knowing:

- **Server-side, nothing is lost.** `MintLogic::verify_note` runs where the
  private key already lives (the mint itself, at redemption time), so the
  check that actually matters for the mint's own security, rejecting
  forged or altered notes presented as inputs, remains intact.
- **Client-side, offline self-verification is not available.** A holder
  can't cryptographically confirm a freshly-received note is genuine without
  asking the mint. In practice, the check for whether or not a note can
  actually be redeemed happens the moment they try to spend it.

If you want offline verification, a DLEQ proof is a
well-specified, moderate addition: the mint computes `e = hash(R1, R2, A,
C')` and `s = r + e*a mod n` alongside its signature; the client recomputes
`R1 = sG - eA`, `R2 = sB' - eC'`, and checks `e == hash(R1, R2, A, C')`.

This is an accountability property (the mint can't quietly sign with an
undisclosed key), however, this is not a forgery-prevention mechanism. Forgery prevention is handled by `verify_note`.

## What you get for privacy, regardless of issuance policy

Blind signatures mean the mint cryptographically cannot link a note it
signs to the note that's later redeemed, this assumption holds no matter how
arbitrary or centralized the issuance policy. What actually
carries privacy in practice:

- **Fixed denominations.** `gen_denominations` produces a power-of-two
  ladder rather than signing exact requested amounts. An odd, distinctive
  amount showing up at issuance and again at redemption is a correlation
  fingerprint which no cryptography would protect against.
- **Anonymity set.** A blind signature makes a note unlinkable to its
  signing operation; it doesn't manufacture a crowd to hide in. How users will actually swap notes in practice (rather than hold the exact note they were
  issued) is a product question, not a code one, but it's the determination that
  decides whether this privacy is real or theoretical.
- **Metadata at the edges.** The cryptography protects the note; it says
  nothing about IP addresses, request timing, or server logs correlating an
  issuance with a swap moments later from the same
  client.

## Scaling considerations

In the mint repos, every mutating request (`issue`, `swap`, `melt`) and every read (keys,
check-state, audit) goes through one `std::sync::Mutex` around
`MintLogic` (`state::AppState`). This is what makes the single-writer correctness argument in
`store.rs` hold, but it serializes all API traffic globally, not just
requests touching the same note.

In practice this is unlikely to matter at single-operator scale. Lock hold
time per request is a few scalar multiplications on secp256k1 plus a couple
of `sled` operations, microseconds to low milliseconds. The bottleneck
becomes real only under high concurrent load, where reads queue up behind
unrelated writes even though they don't need to.

A database with real transactions or row-level locking avoids this by pushing
the double-spend check into the database instead of one process-wide lock. Two
requests touching different notes run in parallel; only requests colliding on
the same note actually serialize.

`Mutex::lock()` blocks rather than fails. There is no request queue and no
fairness guarantee across waiters; concurrent requests pile up as blocked
tasks and get serviced one at a time, adding latency but not getting
dropped. The one case that legitimately fails is two concurrent
redemptions of the same nonce: the second to acquire the lock sees
`claim_redeem` return `false` and gets `SpentCoin`. That is correct
behavior, not a symptom of contention.

If this ever needs to scale past single-operator traffic, the paths worth
considering are: `tokio::sync::Mutex` to stop blocking the async runtime's
OS thread, an `RwLock` (or dropping the lock entirely) for the read-only
endpoints so they stop queuing behind writes, or moving the double-spend
check onto `sled`'s own atomic compare-and-swap per key instead of an
app-level lock, so only requests that actually collide on the same nonce
serialize against each other.

## Deferred / not built

- **A real client library.** `ecash-wallet` is the wallet for the Service Points mints. This workspace has no client.
- **DLEQ proofs (offline note verification).** See above.
- **Wallet recovery from seed.**
- **A pre-check in `swap`.** `melt` checks every input before burning any. `swap` does not yet, so a bad later input can fail after an earlier one is already burned.
- **Terms-bound notes.** Signing keys derived per denomination and terms (service, redeemable-after date), plus a verify call so a third party can check a note.
- **Fast-path throughput.** An in-memory spent set with batched writes, for mints that must accept very high request rates.

## Testing

```sh
cargo test --workspace
```

This runs the `bdhke` test vectors (borrowed from Cashu's NUT-00 spec). The other crates have no unit tests yet. Needs Rust 1.93 or newer (the workspace uses edition 2024).

## Versioning

Semantic Versioning. All three crates share one version, set in the root `Cargo.toml` and recorded in `CHANGELOG.md`. Releases are git tags named `vMAJOR.MINOR.PATCH`. Breaking means a change to the on-disk store or keyfile format, or the public Rust API. Before 1.0, a minor bump may break and a patch bump will not. The mint repos should depend on a tag:

```toml
mint-core = { git = "https://github.com/dav-anderson/mint-core", tag = "v0.3.0" }
```
