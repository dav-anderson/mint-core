//! End-to-end check against a running `mintd`: issue a note out of
//! thin air via `/admin/issue`, then swap it for a fresh note the way two
//! users transferring ecash would.
//!
//! Start the server first, then:
//!
//! ```sh
//! MINT_ADMIN_TOKEN=devtoken cargo run --example smoke_test -p mint-server
//! ```
//!
//! `MINT_URL` (default `http://127.0.0.1:3000`) points it elsewhere.
//!
//! Note what this script does *not* do: after issuance, it does not
//! self-verify Alice's note before spending it. Plain BDHKE isn't publicly
//! verifiable (see `mint-types`'s module doc comment), so there's no
//! offline check to run here, the swap succeeding *is* the proof the note
//! was genuine, same as it is for a real Cashu wallet without a DLEQ proof.

use mint_types::{BlindNonce, MintInput, MintOutput, Nonce, transaction_sighash};
use rand::rngs::OsRng;
use mint_server::api::{
    CheckStateRequest, CheckStateResponse, IssueRequest, IssueResponse, KeysResponse,
    SwapRequest, SwapResponse,
};
use secp256k1::{Keypair, SECP256K1};

/// Generate a fresh (Nonce, secret keypair) pair the way a real wallet
/// would: the *receiver* of a note picks this, not the mint.
fn new_note_identity() -> (Nonce, Keypair) {
    let keypair = Keypair::new(&SECP256K1, &mut OsRng);
    (Nonce(keypair.public_key()), keypair)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base = std::env::var("MINT_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".into());
    let admin_token = std::env::var("MINT_ADMIN_TOKEN")
        .map_err(|_| anyhow::anyhow!("MINT_ADMIN_TOKEN must be set"))?;
    let http = reqwest::Client::new();

    // 1. Learn the mint's public keys.
    let keys: KeysResponse = http
        .get(format!("{base}/keys"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let denomination = *keys
        .keys
        .keys()
        .next()
        .expect("mint has at least one denomination");
    println!("mint's smallest denomination: {denomination}");

    // 2. Issue: the operator arbitrarily creates one note of that
    //    denomination out of nothing, for a wallet identity Alice controls.
    let (alice_nonce, alice_keypair) = new_note_identity();
    let (blind_point, alice_blinding_key) =
        bdhke::blind_message(&alice_nonce.as_hash_preimage(), None);
    let blind_nonce = BlindNonce(blind_point);

    let issue_resp: IssueResponse = http
        .post(format!("{base}/admin/issue"))
        .bearer_auth(&admin_token)
        .json(&IssueRequest {
            output: MintOutput {
                amount: denomination,
                blind_nonce,
            },
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    // Alice unblinds locally, the mint never sees this step, which is
    // exactly why it can't link the note it just signed to what happens to
    // it next.
    let alice_signature = bdhke::unblind_message(
        &issue_resp.outcome.0,
        &alice_blinding_key,
        &keys.keys[&denomination],
    );
    let alice_note = mint_types::Note {
        nonce: alice_nonce,
        signature: alice_signature,
    };
    println!("issued a note out of nothing for Alice (unverifiable offline, see doc comment)");

    // 3. Swap: Alice hands the note to Bob (out of band, just the Note
    //    data). Bob picks a fresh identity and blinds a withdrawal request;
    //    Alice is the one who must sign the swap, since she's the one
    //    proving she's authorized to spend her note.
    let (bob_nonce, _bob_keypair) = new_note_identity();
    let (bob_blind_point, bob_blinding_key) =
        bdhke::blind_message(&bob_nonce.as_hash_preimage(), None);
    let bob_blind_nonce = BlindNonce(bob_blind_point);

    let unsigned_input = MintInput {
        amount: denomination,
        note: alice_note,
        // placeholder, replaced below once we know the real sighash
        spend_signature: secp256k1::schnorr::Signature::from_slice(&[0u8; 64])
            .expect("64 zero bytes is a validly-shaped (if meaningless) signature"),
    };
    let outputs = vec![MintOutput {
        amount: denomination,
        blind_nonce: bob_blind_nonce,
    }];
    let sighash = transaction_sighash(std::slice::from_ref(&unsigned_input), &outputs);
    let spend_signature = SECP256K1.sign_schnorr(&sighash, &alice_keypair);
    let inputs = vec![MintInput {
        spend_signature,
        ..unsigned_input
    }];

    let swap_resp: SwapResponse = http
        .post(format!("{base}/swap"))
        .json(&SwapRequest { inputs, outputs })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    // Getting a successful response at all is the proof Alice's note was
    // genuine: `swap` runs `verify_note` (which needs the mint's own
    // secret key) before it runs anything else.
    println!("swap accepted, Alice's note was genuine and is now spent");

    let bob_signature = bdhke::unblind_message(
        &swap_resp.outcomes[0].0,
        &bob_blinding_key,
        &keys.keys[&denomination],
    );
    let bob_note = mint_types::Note {
        nonce: bob_nonce,
        signature: bob_signature,
    };
    let _ = bob_note; // Bob now holds a fresh, unlinkable note of his own.
    println!("Bob holds a fresh note for the same amount, transfer complete");

    // 4. Confirm Alice's original nonce is now spent (double-spend
    //    protection actually engaged).
    let check_resp: CheckStateResponse = http
        .post(format!("{base}/check-state"))
        .json(&CheckStateRequest {
            nonces: vec![alice_nonce],
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(check_resp.spent[0], "Alice's spent note should show as spent");
    println!("confirmed Alice's original note is now spent, double-spend protection works");

    println!(
        "\nsmoke test passed: unilateral issuance + unlinkable transfer + double-spend protection all round-tripped correctly over HTTP."
    );
    Ok(())
}
