//! Result transform hook: inspect or rewrite server messages sent to the client.
//!
//! A plugin attaches a transform to a statement in its
//! [`crate::StatementOutput::with_transform`]. PgDog then calls
//! [`crate::Plugin::transform`] for each message of that statement whose code
//! the plugin asked for, after multi-shard results have been merged, sorted and
//! aggregated, i.e., with exactly the messages the client would receive.
//!
//! The plugin can forward the message unchanged, replace its body, or fail the
//! statement. Failing closes the client connection, since some rows may
//! already have been sent.
//!
//! ### Example
//!
//! ```
//! use pgdog_plugin::prelude::*;
//!
//! pgdog_plugin::plugin!(MyPlugin);
//!
//! struct MyPlugin;
//!
//! impl Plugin for MyPlugin {
//!     extern "C-unwind" fn version() -> PdStr<'static> {
//!         env!("CARGO_PKG_VERSION").into()
//!     }
//!
//!     fn capabilities() -> Capabilities {
//!         Capabilities::STATEMENT | Capabilities::TRANSFORM
//!     }
//!
//!     fn statement(_context: StatementContext<'_>) -> StatementOutput {
//!         StatementOutput::cont().with_transform(1, MessageCodes::none().with('E'))
//!     }
//!
//!     fn transform(context: TransformContext<'_>) -> TransformOutput {
//!         // Hide error details from the client.
//!         if context.code == b'E' {
//!             return TransformOutput::replace(b"SERROR\0C42501\0Mdenied\0\0".to_vec());
//!         }
//!         TransformOutput::forward()
//!     }
//! }
//! ```
use crate::{PdBuf, PdSlice};

/// Context passed to [`crate::Plugin::transform`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TransformContext<'a> {
    /// Handle returned with the statement's [`crate::StatementOutput`].
    pub handle: u64,
    /// Message code, e.g. `b'D'` for DataRow.
    pub code: u8,
    /// Message body, without the code and length header.
    pub payload: PdSlice<'a, u8>,
    /// Result column format codes from the client's `Bind`; empty for simple
    /// queries, where every column is text. Follows the protocol: one code applies
    /// to all columns, otherwise there is one per column.
    pub result_formats: PdSlice<'a, i16>,
}

pub(crate) const TRANSFORM_FORWARD: u8 = 0;
pub(crate) const TRANSFORM_REPLACE: u8 = 1;
pub(crate) const TRANSFORM_FAIL: u8 = 2;

/// Output of [`crate::Plugin::transform`].
#[repr(C)]
#[derive(Debug)]
pub struct TransformOutput {
    action: u8,
    payload: PdBuf,
}

impl TransformOutput {
    /// Send the message unchanged.
    pub fn forward() -> Self {
        Self {
            action: TRANSFORM_FORWARD,
            payload: PdBuf::empty(),
        }
    }

    /// Replace the message body. PgDog adds the code and length header.
    pub fn replace(payload: Vec<u8>) -> Self {
        Self {
            action: TRANSFORM_REPLACE,
            payload: PdBuf::from(payload),
        }
    }

    /// Abort the statement and close the client connection.
    pub fn fail() -> Self {
        Self {
            action: TRANSFORM_FAIL,
            payload: PdBuf::empty(),
        }
    }

    /// Release plugin-owned memory. Runs inside the plugin.
    pub(crate) fn free(&mut self) {
        // SAFETY: Called from the plugin's vtable entry, i.e. by the
        // binary that allocated this buffer.
        unsafe { self.payload.free() }
    }

    pub(crate) fn action(&self) -> u8 {
        self.action
    }

    pub(crate) fn payload(&self) -> &PdBuf {
        &self.payload
    }
}

/// What PgDog should do with a server message, as decoded from [`TransformOutput`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformAction {
    /// Send it unchanged.
    Forward,
    /// Send this body instead.
    Replace(Vec<u8>),
    /// Abort the statement and close the client connection.
    Fail,
}
