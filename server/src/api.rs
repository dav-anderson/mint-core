//! Request/response dispatch for the mint's operations: key discovery,
//! issuing new notes, the swap/transfer that gives ecash its privacy
//! property, checking whether a note has been spent, and an audit view
//! of running totals.
//!
//! These are plain, synchronous functions, not network handlers. Every
//! request/response type here still derives `Serialize`/`Deserialize`, so
//! a caller on the other side of whatever local mechanism is in use can
//! treat these exactly as JSON payloads, the same shape they'd be if this
//! were served over HTTP, just without this crate doing any socket I/O
//! itself.
//!
//! `MintLogic`'s methods are plain (non-async) calls behind a
//! `std::sync::Mutex` (see `state::AppState`'s doc comment); each function
//! takes the lock, does its work, and drops it before returning.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::response::{IntoResponse, Response};

use mint_types::{Amount, MintInput, MintOutput, MintOutputOutcome, Nonce};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::state::AppState;

pub type SharedState = Arc<AppState>;

// ---- keys -------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct KeysResponse {
    /// Denomination -> this mint's public key for that denomination.
    /// Clients need these to blind their withdrawal/swap requests. There is
    /// deliberately no way for a client to verify a note against these keys
    /// alone, see `mint-types`'s module doc comment on why plain BDHKE
    /// isn't publicly verifiable.
    pub keys: BTreeMap<Amount, secp256k1::PublicKey>,
}

pub async fn get_keys(State(state): State<SharedState>) -> Json<KeysResponse> {
    let logic = state.logic.lock().expect("mutex not poisoned");
    Json(KeysResponse {
        keys: logic.public_keys().clone(),
    })
}

// ---- admin issue ------------------------------------------------

#[derive(Deserialize, Serialize)]
pub struct IssueRequest {
    pub output: MintOutput,
}

#[derive(Serialize, Deserialize)]
pub struct IssueResponse {
    pub outcome: MintOutputOutcome,
}

/// The unilateral-issuance operation. `admin_token` is whatever the
/// caller received over its own transport, this function only compares
/// it, it does not know or care how it arrived.
pub async fn admin_issue(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, ApiError> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    require_admin(&state, token)?;

    let logic = state.logic.lock().expect("mutex not poisoned");
    let outcome = logic
        .issue(&req.output)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    Ok(Json(IssueResponse { outcome }))
}

fn require_admin(state: &AppState, provided: &str) -> Result<(), ApiError> {
    // Constant-time comparison: an early-exit == here would let a
    // sufficiently patient attacker recover the admin token one byte at a
    // time via response timing.
    let ok = provided.len() == state.admin_token.len()
        && bool::from(provided.as_bytes().ct_eq(state.admin_token.as_bytes()));

    if ok {
        Ok(())
    } else {
        Err(ApiError::unauthorized("invalid admin token"))
    }
}

// ---- swap --------------------------------------------------------

#[derive(Deserialize, Serialize)]
pub struct SwapRequest {
    pub inputs: Vec<MintInput>,
    pub outputs: Vec<MintOutput>,
}

#[derive(Serialize, Deserialize)]
pub struct SwapResponse {
    pub outcomes: Vec<MintOutputOutcome>,
}

/// The transfer primitive: redeem `inputs`, issue `outputs`, and only if
/// inputs cover outputs. This is what a sender and receiver use to hand
/// ecash to each other, see `mint-core::MintLogic::swap` for why this
/// (and not `admin_issue`) is the operation that enforces balance.
pub async fn swap(
    State(state): State<SharedState>,
    Json(req): Json<SwapRequest>,
) -> Result<Json<SwapResponse>, ApiError> {
    let logic = state.logic.lock().expect("mutex not poisoned");
    let outcomes = logic
        .swap(&req.inputs, &req.outputs)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    Ok(Json(SwapResponse { outcomes }))
}

// ---- melt ---------------------------------------------------------

#[derive(Deserialize, Serialize)]
pub struct MeltRequest {
    pub inputs: Vec<MintInput>,
    pub memo: String,
}

#[derive(Serialize, Deserialize)]
pub struct MeltResponse {
    pub burned: Amount,
}

pub async fn melt(
    State(state): State<SharedState>,
    Json(req): Json<MeltRequest>,
) -> Result<Json<MeltResponse>, ApiError> {
    let logic = state.logic.lock().expect("mutex not poisoned");
    let burned = logic
        .melt(&req.inputs, req.memo.as_bytes())
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    Ok(Json(MeltResponse { burned }))
}

// ---- check-state --------------------------------------------------

#[derive(Deserialize, Serialize)]
pub struct CheckStateRequest {
    pub nonces: Vec<Nonce>,
}

#[derive(Serialize, Deserialize)]
pub struct CheckStateResponse {
    /// Same order as the request. `true` == already spent. Note this only
    /// tells you whether a nonce is in the spent-set, not whether it was
    /// ever validly issued, see the README on why offline note
    /// verification isn't available without a DLEQ proof.
    pub spent: Vec<bool>,
}

pub async fn check_state(
    State(state): State<SharedState>,
    Json(req): Json<CheckStateRequest>,
) -> Result<Json<CheckStateResponse>, ApiError> {
    let logic = state.logic.lock().expect("mutex not poisoned");
    let mut spent = Vec::with_capacity(req.nonces.len());
    for nonce in req.nonces {
        spent.push(logic.is_spent(nonce).map_err(|e| ApiError::internal(e.to_string()))?);
    }
    Ok(Json(CheckStateResponse { spent }))
}

// ---- audit ----------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct AuditResponse {
    pub issued: Amount,
    pub redeemed: Amount,
    pub outstanding: Amount,
}

pub async fn audit(State(state): State<SharedState>) -> Result<Json<AuditResponse>, ApiError> {
    let logic = state.logic.lock().expect("mutex not poisoned");
    let (issued, redeemed) = logic
        .audit_totals()
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(AuditResponse {
        issued,
        redeemed,
        // Saturating: `issue` is unconditional (see admin_issue's doc
        // comment), so a misconfigured deployment that redeems more than it
        // ever issued is a bug to see reflected as zero, not a panic.
        outstanding: Amount::from_units(issued.units.saturating_sub(redeemed.units)),
    }))
}

// ---- errors ---------------------------------------------------------------

/// A status/message pair mirroring the shape an HTTP error response would
/// take, so a caller sitting on top of these functions can produce the
/// same wire-visible error body whether or not anything actually travels
/// over IP.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.message })).into_response()
    }
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}
