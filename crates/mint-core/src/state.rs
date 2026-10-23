//! The shared state of a mint process.

use std::sync::Mutex;

use crate::MintLogic;

/// A mint's [`MintLogic`] behind one mutex, for a mint's API, listeners and
/// scanners to share.
pub struct AppState {
    /// A single mutex around all mutating operations. This is a
    /// single-process, single-writer server. Only one request mutates state at a
    /// time. See `mint-core::store`'s doc comment for why that's what makes
    /// its read-then-write sequences safe.
    pub logic: Mutex<MintLogic>,
}
