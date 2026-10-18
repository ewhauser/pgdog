//! Statement hook: rewrite or deny statements before PgDog parses them.
//!
//! PgDog calls [`crate::Plugin::statement`] for every simple `Query` and
//! extended protocol `Parse` a client sends, before its own query parser,
//! rewrite engine and router run, with the SQL to check: in this version it is
//! the client's SQL, and a later version may pass SQL an earlier plugin already
//! rewrote. The plugin returns a [`Verdict`]:
//!
//! - [`Verdict::Allow`]: send the statement unchanged;
//! - [`Verdict::Rewrite`]: send different SQL instead, optionally transforming
//!   some of its result columns with [`crate::Plugin::transform_rows`]. Everything
//!   downstream in PgDog, including sharding, sees the new SQL;
//! - [`Verdict::Deny`]: return an error to the client.
//!
//! Fast-path function calls carry no SQL; PgDog asks
//! [`crate::Plugin::function_call`] instead.
//!
//! ### Determinism
//!
//! A verdict must depend only on the [`crate::Session`] and the SQL, and stay
//! the same until [`crate::Plugin::generation`] changes. PgDog relies on this to
//! decide when to ask again: a prepared statement is checked when it's prepared,
//! and again at `Bind` only if the generation or the session's `search_path`
//! changed since. If the new verdict sends different SQL, PgDog re-prepares the
//! statement transparently.
//!
//! ### Rewrites
//!
//! A rewrite of a `Parse` must keep the statement's bind parameters, since the
//! client binds values for the statement it prepared: PgDog denies a rewrite
//! whose highest parameter number (`$n`) differs from the original's.
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
//!     fn statement(session: &Session<'_>, sql: &str) -> Verdict {
//!         if sql.contains("secret_table") && &*session.user != "admin" {
//!             return Verdict::Deny(Deny::insufficient_privilege("permission denied"));
//!         }
//!         Verdict::Allow
//!     }
//! }
//! ```
use crate::{PdBuf, PdVec};

/// A Postgres SQLSTATE error code: five ASCII digits or uppercase letters.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SqlState([u8; 5]);

impl SqlState {
    /// `42501`.
    pub const INSUFFICIENT_PRIVILEGE: Self = Self(*b"42501");
    /// `0A000`.
    pub const FEATURE_NOT_SUPPORTED: Self = Self(*b"0A000");
    /// `XX000`.
    pub const INTERNAL_ERROR: Self = Self(*b"XX000");

    /// Parse a SQLSTATE. `None` unless it's five ASCII digits or uppercase letters.
    pub fn new(code: &str) -> Option<Self> {
        let bytes: [u8; 5] = code.as_bytes().try_into().ok()?;
        bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
            .then_some(Self(bytes))
    }

    /// The code as a string.
    pub fn as_str(&self) -> &str {
        // SAFETY: Only constructed from ASCII.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

/// An error returned to the client instead of running a statement.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deny {
    /// SQLSTATE of the error.
    pub sqlstate: SqlState,
    /// Error message.
    pub message: String,
}

impl Deny {
    /// Deny with the given SQLSTATE and message.
    pub fn new(sqlstate: SqlState, message: impl Into<String>) -> Self {
        Self {
            sqlstate,
            message: message.into(),
        }
    }

    /// Deny with `insufficient_privilege` (42501).
    pub fn insufficient_privilege(message: impl Into<String>) -> Self {
        Self::new(SqlState::INSUFFICIENT_PRIVILEGE, message)
    }
}

/// Identifies one of the plugin's column transforms. Its meaning is up to the
/// plugin, except for [`TransformId::NULL`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TransformId(pub u64);

impl TransformId {
    /// Replace the column's values with NULL. PgDog applies it itself, without
    /// calling [`crate::Plugin::transform_rows`], to a column of any type.
    pub const NULL: Self = Self(u64::MAX);
}

/// A result column PgDog passes to [`crate::Plugin::transform_rows`].
///
/// `type_oid` is the column's type in the rewritten statement, as Postgres
/// reports it in `RowDescription` (the base type, for domains). Transforms
/// receive values of that type and must return values of the same type, in the format
/// the client asked for (see [`crate::TransformColumn::format`]). PgDog checks the
/// type when it sees the statement's `RowDescription`, and fails the statement
/// if it differs.
#[non_exhaustive]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ColumnTransform {
    /// Which result set of the statement, counting from 0. Only simple queries
    /// with several statements have more than one: it's the statement's
    /// position in the (rewritten) query, counting every statement, including
    /// ones that return no rows.
    pub result: u16,
    /// Column position in the result set, counting from 0.
    pub column: u16,
    /// Transform to apply.
    pub transform: TransformId,
    /// Type OID of the column.
    pub type_oid: u32,
    /// The transform may block, e.g. on a network call. PgDog runs batches with
    /// a blocking transform on a thread pool for blocking work.
    pub blocking: bool,
}

impl ColumnTransform {
    /// Transform a column of type `type_oid` in the first result set.
    pub fn new(column: u16, transform: TransformId, type_oid: u32) -> Self {
        Self {
            result: 0,
            column,
            transform,
            type_oid,
            blocking: false,
        }
    }

    /// Replace a column's values with NULL, whatever its type. PgDog applies it
    /// itself: the plugin never sees the values.
    pub fn null(column: u16) -> Self {
        Self {
            result: 0,
            column,
            transform: TransformId::NULL,
            type_oid: 0,
            blocking: false,
        }
    }

    /// This column is replaced with NULL by PgDog.
    pub fn is_null(&self) -> bool {
        self.transform == TransformId::NULL
    }

    /// Transform a column of a later result set of a multi-statement query.
    pub fn in_result(mut self, result: u16) -> Self {
        self.result = result;
        self
    }

    /// The transform may block.
    pub fn blocking(mut self) -> Self {
        self.blocking = true;
        self
    }
}

/// What PgDog should do with a statement.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Send the statement unchanged.
    Allow,
    /// Send `sql` instead, and transform `columns` of its results.
    #[non_exhaustive]
    Rewrite {
        /// Replacement SQL. May be the original SQL, to only transform columns.
        sql: String,
        /// Result columns to pass to [`crate::Plugin::transform_rows`], or to replace
        /// with NULL. Requires [`crate::Capabilities::TRANSFORM`].
        columns: Vec<ColumnTransform>,
        /// Replace the message of the statement's errors and notices with a
        /// generic one, keeping their severity, SQLSTATE and position. For
        /// statements that compute with values the client mustn't see, whose
        /// errors could quote them. Requires [`crate::Capabilities::TRANSFORM`].
        redact_errors: bool,
    },
    /// Return an error to the client.
    Deny(Deny),
}

impl Verdict {
    /// Send `sql` instead, without transforming any columns.
    pub fn rewrite(sql: impl Into<String>) -> Self {
        Self::transform(sql, vec![])
    }

    /// Send `sql` instead, and transform `columns` of its results. `sql` may be
    /// the original SQL, to only transform columns.
    pub fn transform(sql: impl Into<String>, columns: Vec<ColumnTransform>) -> Self {
        Self::Rewrite {
            sql: sql.into(),
            columns,
            redact_errors: false,
        }
    }

    /// Redact the statement's errors and notices: sets `redact_errors` of a
    /// [`Verdict::Rewrite`]. Leaves [`Verdict::Allow`] and [`Verdict::Deny`]
    /// unchanged.
    pub fn redact_errors(mut self, redact: bool) -> Self {
        if let Self::Rewrite { redact_errors, .. } = &mut self {
            *redact_errors = redact;
        }
        self
    }
}

/// Whether a fast-path function call may run.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// Let it run.
    Allow,
    /// Return an error to the client.
    Deny(Deny),
}

pub(crate) const VERDICT_ALLOW: u8 = 0;
pub(crate) const VERDICT_REWRITE: u8 = 1;
pub(crate) const VERDICT_DENY: u8 = 2;
pub(crate) const VERDICT_PANIC: u8 = 3;

/// [`Verdict`] or [`Access`] as it crosses the plugin boundary.
///
/// Memory in this struct belongs to the plugin; PgDog copies it and returns it
/// through the vtable to be freed by the plugin.
#[repr(C)]
#[derive(Debug)]
pub struct VerdictOutput {
    action: u8,
    sql: PdBuf,
    columns: PdVec<ColumnTransform>,
    redact_errors: bool,
    sqlstate: SqlState,
    message: PdBuf,
}

impl VerdictOutput {
    fn new(action: u8) -> Self {
        Self {
            action,
            sql: PdBuf::empty(),
            columns: PdVec::empty(),
            redact_errors: false,
            sqlstate: SqlState::INTERNAL_ERROR,
            message: PdBuf::empty(),
        }
    }

    fn deny(deny: Deny) -> Self {
        Self {
            sqlstate: deny.sqlstate,
            message: PdBuf::from(deny.message),
            ..Self::new(VERDICT_DENY)
        }
    }

    pub(crate) fn panicked() -> Self {
        Self::new(VERDICT_PANIC)
    }

    /// Release plugin-owned memory. Runs inside the plugin.
    pub(crate) fn free(&mut self) {
        // SAFETY: Called from the plugin's vtable entry, i.e. by the
        // binary that allocated these buffers.
        unsafe {
            self.sql.free();
            self.columns.free();
            self.message.free();
        }
    }

    pub(crate) fn action(&self) -> u8 {
        self.action
    }

    pub(crate) fn sql(&self) -> &PdBuf {
        &self.sql
    }

    pub(crate) fn columns(&self) -> &[ColumnTransform] {
        self.columns.as_slice()
    }

    pub(crate) fn redact_errors(&self) -> bool {
        self.redact_errors
    }

    pub(crate) fn denied(&self) -> Deny {
        Deny {
            sqlstate: self.sqlstate,
            message: String::from_utf8_lossy(self.message.as_bytes()).into_owned(),
        }
    }
}

impl From<Verdict> for VerdictOutput {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self::new(VERDICT_ALLOW),
            Verdict::Rewrite {
                sql,
                columns,
                redact_errors,
            } => Self {
                sql: PdBuf::from(sql),
                columns: PdVec::from(columns),
                redact_errors,
                ..Self::new(VERDICT_REWRITE)
            },
            Verdict::Deny(deny) => Self::deny(deny),
        }
    }
}

impl From<Access> for VerdictOutput {
    fn from(access: Access) -> Self {
        match access {
            Access::Allow => Self::new(VERDICT_ALLOW),
            Access::Deny(deny) => Self::deny(deny),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sqlstate() {
        assert_eq!(
            SqlState::new("42501"),
            Some(SqlState::INSUFFICIENT_PRIVILEGE)
        );
        assert_eq!(SqlState::new("0A000").unwrap().as_str(), "0A000");
        assert_eq!(SqlState::new("bad"), None);
        assert_eq!(SqlState::new("4250a"), None);
        assert_eq!(SqlState::new("425011"), None);
    }

    #[test]
    fn test_verdict_output() {
        let verdict = Verdict::transform(
            "SELECT 1",
            vec![
                ColumnTransform::new(2, TransformId(7), 25).blocking(),
                ColumnTransform::null(3),
            ],
        )
        .redact_errors(true);
        assert_eq!(
            verdict,
            Verdict::Rewrite {
                sql: "SELECT 1".into(),
                columns: vec![
                    ColumnTransform::new(2, TransformId(7), 25).blocking(),
                    ColumnTransform::null(3),
                ],
                redact_errors: true,
            }
        );
        assert_eq!(Verdict::Allow.redact_errors(true), Verdict::Allow);
        let mut output = VerdictOutput::from(verdict);
        assert_eq!(output.action(), VERDICT_REWRITE);
        assert_eq!(output.sql().as_str(), Some("SELECT 1"));
        assert_eq!(
            output.columns(),
            &[
                ColumnTransform::new(2, TransformId(7), 25).blocking(),
                ColumnTransform::null(3)
            ]
        );
        assert!(output.redact_errors());
        assert!(output.columns()[1].is_null());
        output.free();

        let mut output = VerdictOutput::from(Access::Deny(Deny::insufficient_privilege("no")));
        assert_eq!(output.action(), VERDICT_DENY);
        assert_eq!(output.denied(), Deny::insufficient_privilege("no"));
        output.free();
    }
}
