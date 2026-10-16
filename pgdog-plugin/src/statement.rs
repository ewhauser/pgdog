//! Statement hook: rewrite or block statements before PgDog parses them.
//!
//! PgDog calls [`crate::Plugin::statement`] for every `Query`, `Parse`, `Bind` and
//! fast-path `FunctionCall` a client sends, before its own query parser,
//! rewrite engine and router run. A plugin can:
//!
//! - let the statement through unchanged ([`StatementOutput::cont`]),
//! - replace its SQL ([`StatementOutput::rewrite`]); everything downstream in PgDog,
//!   including sharding, sees the new SQL,
//! - reject it with an error ([`StatementOutput::block`]).
//!
//! Any of these can carry a result transform ([`StatementOutput::with_transform`]),
//! which makes PgDog pass the statement's server messages to [`crate::Plugin::transform`].
//!
//! ### Prepared statements
//!
//! For `Bind`, `sql` is the statement's **original** SQL, as the client
//! prepared it, not a previous rewrite. The `variant_tag` returned with a
//! rewrite identifies which rewrite was applied. If a later `Bind` returns a
//! different tag, PgDog re-prepares the statement with the new SQL, so
//! long-lived prepared statements follow plugin configuration changes.
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
//!         Capabilities::STATEMENT
//!     }
//!
//!     fn statement(context: StatementContext<'_>) -> StatementOutput {
//!         if context.sql.contains("secret_table") && &*context.identity.user != "admin" {
//!             return StatementOutput::block("42501", "permission denied");
//!         }
//!         StatementOutput::cont()
//!     }
//! }
//! ```
use crate::{PdBuf, PdStr};

/// Who is running the statement. All values come from the client's
/// authenticated session, except where noted.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Identity<'a> {
    /// PgDog user the client authenticated as.
    pub user: PdStr<'a>,
    /// PgDog database the client connected to.
    pub database: PdStr<'a>,
    /// `application_name`. **Set by the client, not authenticated.**
    pub application_name: PdStr<'a>,
    /// Client IP address, empty if unknown.
    pub client_addr: PdStr<'a>,
    /// Identity from the client's TLS certificate (SAN DNS name, or subject CN),
    /// empty if the client didn't present one.
    pub tls_identity: PdStr<'a>,
    /// Unique identifier of the client connection.
    pub session_id: u64,
}

/// The protocol message that carried the statement.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    /// Simple protocol `Query`. May contain several statements.
    Query = 0,
    /// Extended protocol `Parse`.
    Parse = 1,
    /// Extended protocol `Bind`. `sql` is the prepared statement's original SQL.
    Bind = 2,
    /// Fast-path `FunctionCall`. `sql` is empty; the plugin can only block it.
    FunctionCall = 3,
}

/// Context passed to [`crate::Plugin::statement`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatementContext<'a> {
    /// Client identity.
    pub identity: Identity<'a>,
    /// Message that carried the statement.
    pub kind: StatementKind,
    /// SQL text, exactly as the client sent it.
    pub sql: PdStr<'a>,
    /// Prepared statement name used by the client. Empty for the unnamed
    /// statement and for simple queries.
    pub statement_name: PdStr<'a>,
    /// Session `search_path`, empty if the client didn't set one.
    pub search_path: PdStr<'a>,
    /// Is the client inside a transaction?
    pub in_transaction: bool,
}

/// Bit set of protocol message codes, e.g. `'D'` (DataRow).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MessageCodes([u64; 2]);

impl MessageCodes {
    /// No messages.
    pub const fn none() -> Self {
        Self([0, 0])
    }

    /// Add a message code. Codes are ASCII; others are ignored.
    pub const fn with(mut self, code: char) -> Self {
        let code = code as u32;
        if code < 128 {
            self.0[(code / 64) as usize] |= 1 << (code % 64);
        }
        self
    }

    /// Is the message code in the set?
    pub const fn contains(&self, code: char) -> bool {
        let code = code as u32;
        code < 128 && self.0[(code / 64) as usize] & (1 << (code % 64)) != 0
    }

    /// Is the set empty?
    pub const fn is_empty(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0
    }
}

pub(crate) const ACTION_CONTINUE: u8 = 0;
pub(crate) const ACTION_REWRITE: u8 = 1;
pub(crate) const ACTION_BLOCK: u8 = 2;
pub(crate) const ACTION_PANIC: u8 = 3;

/// Output of [`crate::Plugin::statement`].
///
/// Memory in this struct belongs to the plugin; PgDog copies it and returns it
/// through the vtable to be freed by the plugin.
#[repr(C)]
#[derive(Debug)]
pub struct StatementOutput {
    action: u8,
    sql: PdBuf,
    variant_tag: u64,
    sqlstate: [u8; 5],
    message: PdBuf,
    transform: u64,
    transform_codes: MessageCodes,
}

impl StatementOutput {
    /// Let the statement through unchanged.
    pub fn cont() -> Self {
        Self {
            action: ACTION_CONTINUE,
            sql: PdBuf::empty(),
            variant_tag: 0,
            sqlstate: [0; 5],
            message: PdBuf::empty(),
            transform: 0,
            transform_codes: MessageCodes::none(),
        }
    }

    /// Replace the statement's SQL.
    ///
    /// `variant_tag` identifies this rewrite. Return the same tag for the same
    /// rewrite; a different tag on a later `Bind` makes PgDog re-prepare the
    /// statement. Rewrites of a `Parse` or `Bind` must keep the number and types of
    /// bind parameters unchanged.
    pub fn rewrite(sql: impl Into<String>, variant_tag: u64) -> Self {
        Self {
            action: ACTION_REWRITE,
            sql: PdBuf::from(sql.into()),
            variant_tag,
            ..Self::cont()
        }
    }

    /// Reject the statement. The client receives an `ErrorResponse` with the given
    /// SQLSTATE (5 ASCII characters, e.g. `"42501"`) and message.
    pub fn block(sqlstate: &str, message: impl Into<String>) -> Self {
        let mut code = *b"42501";
        if sqlstate.len() == 5 && sqlstate.is_ascii() {
            code.copy_from_slice(sqlstate.as_bytes());
        }
        Self {
            action: ACTION_BLOCK,
            sqlstate: code,
            message: PdBuf::from(message.into()),
            ..Self::cont()
        }
    }

    /// Attach a result transform. PgDog will call [`crate::Plugin::transform`] with
    /// `handle` for every server message of this statement whose code is in
    /// `codes`, then [`crate::Plugin::release_transform`] when the statement is done.
    ///
    /// `handle` must not be zero.
    pub fn with_transform(mut self, handle: u64, codes: MessageCodes) -> Self {
        self.transform = handle;
        self.transform_codes = codes;
        self
    }

    pub(crate) fn panicked() -> Self {
        Self {
            action: ACTION_PANIC,
            ..Self::cont()
        }
    }

    /// Release plugin-owned memory. Runs inside the plugin.
    pub(crate) fn free(&mut self) {
        // SAFETY: Called from the plugin's vtable entry, i.e. by the
        // binary that allocated these buffers.
        unsafe {
            self.sql.free();
            self.message.free();
        }
    }

    pub(crate) fn action(&self) -> u8 {
        self.action
    }

    pub(crate) fn sql(&self) -> &PdBuf {
        &self.sql
    }

    pub(crate) fn variant_tag(&self) -> u64 {
        self.variant_tag
    }

    pub(crate) fn sqlstate(&self) -> &[u8; 5] {
        &self.sqlstate
    }

    pub(crate) fn message(&self) -> &PdBuf {
        &self.message
    }

    pub(crate) fn transform(&self) -> Option<Transform> {
        (self.transform != 0).then_some(Transform {
            handle: self.transform,
            codes: self.transform_codes,
        })
    }
}

/// A result transform attached to a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transform {
    /// Opaque handle created by the plugin.
    pub handle: u64,
    /// Server messages to pass to the plugin.
    pub codes: MessageCodes,
}

/// What PgDog should do with a statement, as decoded from [`StatementOutput`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementAction {
    /// Send the statement unchanged.
    Continue,
    /// Send `sql` instead.
    Rewrite {
        /// Replacement SQL.
        sql: String,
        /// Identifies the rewrite.
        variant_tag: u64,
    },
    /// Return an error to the client.
    Block {
        /// SQLSTATE error code.
        sqlstate: String,
        /// Error message.
        message: String,
    },
}

/// Statement decision, owned by PgDog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementDecision {
    /// What to do with the statement.
    pub action: StatementAction,
    /// Transform attached to the statement, if any.
    pub transform: Option<Transform>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_message_codes() {
        let codes = MessageCodes::none().with('D').with('T').with('1');
        assert!(codes.contains('D'));
        assert!(codes.contains('T'));
        assert!(codes.contains('1'));
        assert!(!codes.contains('C'));
        assert!(!codes.contains('é'));
        assert!(MessageCodes::none().is_empty());
        assert!(!codes.is_empty());
    }

    #[test]
    fn test_block_sqlstate() {
        let mut output = StatementOutput::block("XX000", "nope");
        assert_eq!(output.sqlstate(), b"XX000");
        assert_eq!(output.message().as_str(), Some("nope"));
        output.free();

        // Invalid codes fall back to insufficient_privilege.
        let mut output = StatementOutput::block("bad", "nope");
        assert_eq!(output.sqlstate(), b"42501");
        output.free();
    }
}
