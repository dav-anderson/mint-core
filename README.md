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
| `crypto/bdhke` | The blind-signature primitive: `hash_to_curve`, `blind_message`, `sign_message`, `unblind_message`, `verify_message`. ~150 lines, zero vestigial multi-party code, tested against NUT-00's published test vectors. |
| `crates/mint-types` | `Amount` (a plain opaque unit count), `Note`/`Nonce`/`BlindNonce`, `MintInput`/`MintOutput`, the `transaction_sighash` and `melt_sighash` spend-authorization schemes (see below), denomination generation, `MintConfig`. |
| `crates/mint-core` | `MintLogic`: `verify_note`, `verify_spend_authorization`, `redeem`, `issue`, `swap`, `melt`, plus `store::Store` -- a thin wrapper around `sled` (a pure-Rust embedded KV store, chosen specifically so this crate needs no C/C++ toolchain to build). |
| `server` | `mintd` (crate `mint-server`): one process, an Axum HTTP API, `MintLogic` behind a single `std::sync::Mutex` (this is a single-writer server -- see `state.rs`'s doc comment for why that's the whole correctness story, not a shortcut). The mint repos reuse this crate. |

## HTTP API

| Route | What it does |
|---|---|
| `GET /keys` | Public key for each denomination. Clients need these to blind requests. |
| `POST /admin/issue` | Unilateral issuance. Requires the admin bearer token. |
| `POST /swap` | Redeem inputs, issue outputs. Inputs must cover outputs. Any surplus is burned, which is how a request pays for itself. |
| `POST /melt` | Redeem inputs, issue nothing. Returns the total burned. The `memo` is bound into the spend signature. No admin token, the spend signatures are the authorization. |
| `POST /check-state` | Whether each given nonce has been spent. |
| `GET /audit` | Running `issued`, `redeemed` and `outstanding` totals. |

## On backing

`MintLogic::issue`, the function that blind-signs a note into existence,
is **unconditional**, on purpose. Nothing in this codebase cryptographically enforces that issued value is backed by anything. Deciding when to call it is the job of each mint repo's middleware.

The entire mechanism separating "arbitrary issuance" from "a bug that lets
anyone print money" is: `/admin/issue` requires a bearer token and is the
only caller of `issue()` that doesn't also require spending real input
value; `/swap` is the only other caller, and it explicitly checks
`input_total >= output_total` before issuing anything (see
`MintLogic::swap`). `/melt` never calls `issue()` at all.

Guard `MINT_ADMIN_TOKEN` accordingly, it is the only thing standing between this being "a mint you control" and "a mint anyone can print from."

The `/audit` endpoint's `issued`/`redeemed`/`outstanding` totals are
bookkeeping, not a solvency proof: nothing here is independently verifiable
by a party who isn't the administrator/mint operator.

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

Plain BDHKE is **not publicly verifiable**. Given only the mint's public key for a denomination, there is no way to confirm a signature is genuine. Doing so would require either the mint's own private key, or an additional non-interactive proof (Cashu calls this a NUT-12 "DLEQ proof"). This implementation does not implement DLEQ proof. This carries two consequences worth knowing:

- **Server-side, nothing is lost.** `MintLogic::verify_note` runs where the
  private key already lives (the mint itself, at redemption time), so the
  check that actually matters for the mint's own security, rejecting
  forged or altered notes presented as inputs, remains intact.
- **Client-side, offline self-verification is not available.** A holder
  can't cryptographically confirm a freshly-received note is genuine without
  asking the mint. In practice, the check for whether or not a note can
  actually be redeemed happens the moment they try to spend it (see
  `server/examples/smoke_test.rs`, which relies on a successful `/swap` as
  its proof rather than an offline check). This mirrors how Cashu
  wallets behave without NUT-12 DLEQ proofs.

If you want offline verification, NUT-12's DLEQ proof is a
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
  `/admin/issue` call with a `/swap` call moments later from the same
  client.

## Scaling considerations

Every mutating request (`issue`, `swap`, `melt`) and every read (`get_keys`,
`check_state`, `audit`) goes through one `std::sync::Mutex` around
`MintLogic`. This is what makes the single-writer correctness argument in
`store.rs` hold, but it serializes all API traffic globally, not just
requests touching the same note.

In practice this is unlikely to matter at single-operator scale. Lock hold
time per request is a few scalar multiplications on secp256k1 plus a couple
of `sled` operations, microseconds to low milliseconds. The bottleneck
becomes real only under high concurrent load, where reads queue up behind
unrelated writes even though they don't need to.

Production Cashu implementations (CDK, Nutshell) avoid this by pushing the
double-spend check into a real database's transaction or row-locking
machinery instead of one process-wide lock. Two requests touching different
notes run in parallel; only requests colliding on the same note actually
serialize.

`Mutex::lock()` blocks rather than fails. There is no request queue and no
fairness guarantee across waiters; concurrent requests pile up as blocked
tasks and get serviced one at a time, adding latency but not getting
dropped. The one case that legitimately fails is two concurrent
redemptions of the same nonce: the second to acquire the lock sees
`mark_nonce_spent` return `false` and gets `SpentCoin`. That is correct
behavior, not a symptom of contention.

If this ever needs to scale past single-operator traffic, the paths worth
considering are: `tokio::sync::Mutex` to stop blocking the async runtime's
OS thread, an `RwLock` (or dropping the lock entirely) for the read-only
endpoints so they stop queuing behind writes, or moving the double-spend
check onto `sled`'s own atomic compare-and-swap per key instead of an
app-level lock, so only requests that actually collide on the same nonce
serialize against each other.

## Deferred / not built

- **A real client library.** `server/examples/smoke_test.rs` proves the
  protocol round-trips (issue -> unblind -> swap -> check-state) in under
  200 lines, but it's a script, not a wallet: there is no persistent note storage, no
  denomination selection / change-making, no offline note serialization
  format for handing a note to someone out of band.
- **DLEQ proofs (offline note verification).** See above.
- **Wallet recovery from seed.**
- **A pre-check in `swap`.** `melt` checks every input before burning any. `swap` does not yet, so a bad later input can fail after an earlier one is already burned.
- **Terms-bound notes.** Signing keys derived per denomination and terms (service, redeemable-after date), plus a verify call so a third party can check a note.
- **Fast-path throughput.** An in-memory spent set with batched writes, for mints that must accept very high request rates.

## Running it

```sh
export MINT_ADMIN_TOKEN=$(openssl rand -hex 32)
cargo run --bin mintd
# in another shell:
MINT_ADMIN_TOKEN=$MINT_ADMIN_TOKEN cargo run --example smoke_test -p mint-server
```

Config is entirely environment variables (see `server/src/config.rs`):
`MINT_DATA_DIR` (default `./data`), `MINT_BIND` (default
`127.0.0.1:3000`), `MINT_ADMIN_TOKEN` (required, no default --
refusing to start without one is deliberate), `MINT_MAX_DENOMINATION`
(default `1048576`, a plain unit count -- no bitcoin conversion happens
anywhere in this codebase).

The keypair is generated on first run and written to
`<data_dir>/mint_keys.json` with `0600` permissions. It is the entire secret
behind every note this mint will ever issue or redeem -- back it up, and
never let a redeploy silently regenerate it out from under existing notes.
