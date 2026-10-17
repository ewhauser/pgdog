//! Error redaction: remove values from errors and notices before clients see them.
//!
//! Postgres errors can contain the data a statement touched: a unique violation's
//! `Key (ssn)=(123-45-6789) already exists`, a check constraint's
//! `Failing row contains (...)`, or a cast error's
//! `invalid input syntax for type integer: "123-45-6789"`. PgDog passes every
//! `ErrorResponse` and `NoticeResponse` Postgres sends to a client through
//! [`crate::Plugin::redact_error`], which can replace its fields.
//!
//! The severity and SQLSTATE always reach the client unchanged, so clients keep
//! handling errors correctly.
//!
//! ### Example
//!
//! ```
//! use pgdog_plugin::prelude::*;
//! use pgdog_plugin::redact::field;
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
//!         Capabilities::ERRORS
//!     }
//!
//!     fn redact_error(session: &Session<'_>, error: &ErrorFields<'_>) -> Redaction {
//!         if &*session.user == "admin" || error.get(field::DETAIL).is_none() {
//!             return Redaction::Keep;
//!         }
//!         Redaction::Replace(error.without(&[field::DETAIL]))
//!     }
//! }
//! ```
use crate::{PdBuf, PdSlice, PdStr};

/// Field codes of `ErrorResponse` and `NoticeResponse`.
pub mod field {
    /// Localized severity, e.g. `ERROR`.
    pub const SEVERITY: u8 = b'S';
    /// Severity, never localized.
    pub const SEVERITY_NONLOCALIZED: u8 = b'V';
    /// SQLSTATE.
    pub const SQLSTATE: u8 = b'C';
    /// Primary message.
    pub const MESSAGE: u8 = b'M';
    /// Detail.
    pub const DETAIL: u8 = b'D';
    /// Hint.
    pub const HINT: u8 = b'H';
    /// Cursor position in the statement.
    pub const POSITION: u8 = b'P';
    /// Cursor position in an internally generated statement.
    pub const INTERNAL_POSITION: u8 = b'p';
    /// Internally generated statement.
    pub const INTERNAL_QUERY: u8 = b'q';
    /// Call stack context.
    pub const WHERE: u8 = b'W';
    /// Schema name.
    pub const SCHEMA: u8 = b's';
    /// Table name.
    pub const TABLE: u8 = b't';
    /// Column name.
    pub const COLUMN: u8 = b'c';
    /// Data type name.
    pub const DATA_TYPE: u8 = b'd';
    /// Constraint name.
    pub const CONSTRAINT: u8 = b'n';
    /// Source file.
    pub const FILE: u8 = b'F';
    /// Source line.
    pub const LINE: u8 = b'L';
    /// Source routine.
    pub const ROUTINE: u8 = b'R';
}

/// One field of an error or notice.
#[non_exhaustive]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ErrorField<'a> {
    /// Field code, see [`field`].
    pub code: u8,
    /// Field value. Bytes that aren't valid UTF-8 are replaced.
    pub value: PdStr<'a>,
}

impl<'a> ErrorField<'a> {
    /// A field with the given code, see [`field`].
    pub fn new(code: u8, value: PdStr<'a>) -> Self {
        Self { code, value }
    }
}

/// An `ErrorResponse` or `NoticeResponse` sent by Postgres.
#[non_exhaustive]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ErrorFields<'a> {
    /// This is a `NoticeResponse`.
    pub notice: bool,
    fields: PdSlice<'a, ErrorField<'a>>,
}

impl<'a> ErrorFields<'a> {
    /// Create from fields, in the order Postgres sent them.
    pub fn new(notice: bool, fields: &'a [ErrorField<'a>]) -> Self {
        Self {
            notice,
            fields: PdSlice::from(fields),
        }
    }

    /// All fields, in the order Postgres sent them.
    pub fn fields(&self) -> &'a [ErrorField<'a>] {
        self.fields.as_slice()
    }

    /// Value of a field, if present.
    pub fn get(&self, code: u8) -> Option<&'a str> {
        self.fields()
            .iter()
            .find(|field| field.code == code)
            .map(|field| field.value.as_str())
    }

    /// The SQLSTATE.
    pub fn sqlstate(&self) -> Option<&'a str> {
        self.get(field::SQLSTATE)
    }

    /// The primary message.
    pub fn message(&self) -> Option<&'a str> {
        self.get(field::MESSAGE)
    }

    /// All fields except those in `codes`, as a replacement.
    pub fn without(&self, codes: &[u8]) -> Vec<(u8, String)> {
        self.fields()
            .iter()
            .filter(|field| !codes.contains(&field.code))
            .map(|field| (field.code, field.value.to_string()))
            .collect()
    }
}

/// What to do with an error or notice.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redaction {
    /// Send it unchanged.
    Keep,
    /// Send these fields instead. PgDog keeps the original severity and
    /// SQLSTATE whatever this contains.
    Replace(Vec<(u8, String)>),
}

pub(crate) const REDACT_KEEP: u8 = 0;
pub(crate) const REDACT_REPLACE: u8 = 1;
pub(crate) const REDACT_PANIC: u8 = 2;

/// [`Redaction`] as it crosses the plugin boundary. Memory belongs to the plugin.
#[repr(C)]
#[derive(Debug)]
pub struct RedactionOutput {
    action: u8,
    /// Fields encoded like the body of an `ErrorResponse`: code, value, NUL.
    fields: PdBuf,
}

impl RedactionOutput {
    pub(crate) fn panicked() -> Self {
        Self {
            action: REDACT_PANIC,
            fields: PdBuf::empty(),
        }
    }

    /// Release plugin-owned memory. Runs inside the plugin.
    pub(crate) fn free(&mut self) {
        // SAFETY: Called from the plugin's vtable entry, i.e. by the
        // binary that allocated this buffer.
        unsafe { self.fields.free() }
    }

    pub(crate) fn action(&self) -> u8 {
        self.action
    }

    /// Decode the replacement fields.
    pub(crate) fn fields(&self) -> Option<Vec<(u8, String)>> {
        let mut fields = vec![];
        let mut rest = self.fields.as_bytes();
        while let Some((&code, tail)) = rest.split_first() {
            let end = tail.iter().position(|byte| *byte == 0)?;
            fields.push((code, String::from_utf8_lossy(&tail[..end]).into_owned()));
            rest = &tail[end + 1..];
        }
        Some(fields)
    }
}

impl From<Redaction> for RedactionOutput {
    fn from(redaction: Redaction) -> Self {
        match redaction {
            Redaction::Keep => Self {
                action: REDACT_KEEP,
                fields: PdBuf::empty(),
            },
            Redaction::Replace(fields) => {
                let mut encoded = vec![];
                // Codes must be non-zero and values can't contain NUL.
                for (code, value) in fields.iter().filter(|(code, _)| *code != 0) {
                    encoded.push(*code);
                    encoded.extend(value.bytes().filter(|byte| *byte != 0));
                    encoded.push(0);
                }
                Self {
                    action: REDACT_REPLACE,
                    fields: PdBuf::from(encoded),
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_error_fields() {
        let fields = [
            ErrorField::new(field::SQLSTATE, "23505".into()),
            ErrorField::new(field::DETAIL, "Key (ssn)=(123) already exists.".into()),
        ];
        let error = ErrorFields::new(false, &fields);
        assert_eq!(error.sqlstate(), Some("23505"));
        assert_eq!(error.message(), None);
        assert_eq!(error.without(&[field::DETAIL]), [(b'C', "23505".into())]);
    }

    #[test]
    fn test_redaction_output() {
        let mut output = RedactionOutput::from(Redaction::Replace(vec![
            (field::MESSAGE, "hidden\0value".into()),
            (0, "ignored".into()),
            (field::HINT, String::new()),
        ]));
        assert_eq!(output.action(), REDACT_REPLACE);
        assert_eq!(
            output.fields().unwrap(),
            [
                (field::MESSAGE, "hiddenvalue".into()),
                (field::HINT, String::new())
            ]
        );
        output.free();
    }
}
