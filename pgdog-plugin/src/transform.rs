//! Column transforms: result values computed by the plugin, outside the database.
//!
//! A [`crate::Verdict::Rewrite`] can name result columns to transform. PgDog
//! collects the statement's `DataRow`s in batches and calls
//! [`crate::Plugin::transform_rows`] once per batch, with the values of those
//! columns only, column by
//! column. The plugin writes one output value per input value into
//! [`TransformOutput`], in the same order: all rows of the first column, then all
//! rows of the second, and so on.
//!
//! A batch is the rows that are already available from the server, up to a
//! limit, so batching never makes the client wait for rows that haven't
//! arrived. Rows are always forwarded in order.
//!
//! Use transforms for values that can't be computed in SQL, e.g. a keyed hash
//! whose key must not appear in the statement, tokens from a vault, or masked
//! values.
//!
//! Values are in the format the client asked for: text for simple queries,
//! and what the client's `Bind` requested for the extended protocol. Transforms
//! return values of the column's type in the same format. [`crate::types`]
//! decodes and encodes common types in both formats.
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
//!     fn statement(_session: &Session<'_>, sql: &str) -> Verdict {
//!         // Transform the first column, a text column (type OID 25).
//!         Verdict::transform(sql, vec![ColumnTransform::new(0, TransformId(1), 25)])
//!     }
//!
//!     fn transform_rows(batch: &TransformBatch<'_>, out: &mut TransformOutput) -> Result<(), TransformError> {
//!         for column in batch.columns() {
//!             for value in column.values() {
//!                 // Keep NULLs, hide everything else. Text is the same bytes
//!                 // in both formats.
//!                 out.push(value.map(|_| b"***".as_slice()));
//!             }
//!         }
//!         Ok(())
//!     }
//! }
//! ```
use std::{marker::PhantomData, ptr, slice};

use crate::{PdBuf, PdSlice, PdVec, TransformId};
use pgdog_postgres_types::Format;

/// A column value, borrowed from PgDog's `DataRow` for the duration of
/// [`crate::Plugin::transform_rows`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Value<'a> {
    data: *const u8,
    /// `-1` for NULL.
    len: i32,
    _lifetime: PhantomData<&'a [u8]>,
}

impl<'a> Value<'a> {
    /// A value, or NULL.
    pub fn new(value: Option<&'a [u8]>) -> Self {
        match value {
            Some(value) => Self {
                data: value.as_ptr(),
                len: value.len() as i32,
                _lifetime: PhantomData,
            },
            None => Self {
                data: ptr::null(),
                len: -1,
                _lifetime: PhantomData,
            },
        }
    }

    /// The value's bytes, `None` for NULL.
    pub fn get(&self) -> Option<&'a [u8]> {
        match self.len {
            ..0 => None,
            0 => Some(&[]),
            // SAFETY: Only constructed from a slice that outlives 'a.
            len => Some(unsafe { slice::from_raw_parts(self.data, len as usize) }),
        }
    }
}

/// Values of one transformed column, one per row of the batch.
#[non_exhaustive]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TransformColumn<'a> {
    /// Column position in the result set.
    pub column: u16,
    /// Transform to apply, from the statement's [`crate::ColumnTransform`].
    pub transform: TransformId,
    /// Type OID of the column, from the statement's [`crate::ColumnTransform`].
    pub type_oid: u32,
    /// Format of the values, which transformed values must use too.
    pub format: Format,
    values: PdSlice<'a, Value<'a>>,
}

impl<'a> TransformColumn<'a> {
    /// Create a column of a batch.
    pub fn new(
        transform: &crate::ColumnTransform,
        format: Format,
        values: &'a [Value<'a>],
    ) -> Self {
        Self {
            column: transform.column,
            transform: transform.transform,
            type_oid: transform.type_oid,
            format,
            values: PdSlice::from(values),
        }
    }

    /// The column's values, in row order. `None` is NULL.
    pub fn values(&self) -> impl ExactSizeIterator<Item = Option<&'a [u8]>> + 'a {
        self.values.as_slice().iter().map(Value::get)
    }
}

/// A batch of rows to transform.
#[non_exhaustive]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TransformBatch<'a> {
    /// Number of rows.
    pub rows: u32,
    columns: PdSlice<'a, TransformColumn<'a>>,
}

impl<'a> TransformBatch<'a> {
    /// Create a batch. Every column must have `rows` values.
    pub fn new(rows: u32, columns: &'a [TransformColumn<'a>]) -> Self {
        Self {
            rows,
            columns: PdSlice::from(columns),
        }
    }

    /// The columns to transform, in the order of the statement's
    /// [`crate::ColumnTransform`]s.
    pub fn columns(&self) -> &'a [TransformColumn<'a>] {
        self.columns.as_slice()
    }
}

/// Transformed values written by [`crate::Plugin::transform_rows`]: one per input value,
/// column by column, in the order of [`TransformBatch::columns`].
#[derive(Debug, Default)]
pub struct TransformOutput {
    data: Vec<u8>,
    lengths: Vec<i32>,
}

impl TransformOutput {
    /// Output with room for `values` values of `bytes` bytes in total.
    pub fn with_capacity(values: usize, bytes: usize) -> Self {
        Self {
            data: Vec::with_capacity(bytes),
            lengths: Vec::with_capacity(values),
        }
    }

    /// Add the next value. `None` is NULL.
    pub fn push(&mut self, value: Option<&[u8]>) {
        match value {
            Some(value) => {
                self.data.extend_from_slice(value);
                self.lengths.push(value.len() as i32);
            }
            None => self.lengths.push(-1),
        }
    }

    /// Number of values written so far.
    pub fn len(&self) -> usize {
        self.lengths.len()
    }

    /// No values written yet.
    pub fn is_empty(&self) -> bool {
        self.lengths.is_empty()
    }
}

/// The plugin couldn't transform a batch. PgDog fails the statement and closes the
/// client connection, since earlier rows may already be with the client.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformError(pub String);

impl TransformError {
    /// Create an error. The message is logged, not sent to the client.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

pub(crate) const TRANSFORM_OK: u8 = 0;
pub(crate) const TRANSFORM_ERROR: u8 = 1;
pub(crate) const TRANSFORM_PANIC: u8 = 2;

/// Output of [`crate::Plugin::transform_rows`] as it crosses the plugin boundary.
/// Memory belongs to the plugin.
#[repr(C)]
#[derive(Debug)]
pub struct TransformResult {
    status: u8,
    data: PdBuf,
    lengths: PdVec<i32>,
    message: PdBuf,
}

impl TransformResult {
    pub(crate) fn panicked() -> Self {
        Self {
            status: TRANSFORM_PANIC,
            data: PdBuf::empty(),
            lengths: PdVec::empty(),
            message: PdBuf::empty(),
        }
    }

    /// Release plugin-owned memory. Runs inside the plugin.
    pub(crate) fn free(&mut self) {
        // SAFETY: Called from the plugin's vtable entry, i.e. by the
        // binary that allocated these buffers.
        unsafe {
            self.data.free();
            self.lengths.free();
            self.message.free();
        }
    }

    pub(crate) fn status(&self) -> u8 {
        self.status
    }

    pub(crate) fn data(&self) -> &[u8] {
        self.data.as_bytes()
    }

    pub(crate) fn lengths(&self) -> &[i32] {
        self.lengths.as_slice()
    }

    pub(crate) fn message(&self) -> String {
        String::from_utf8_lossy(self.message.as_bytes()).into_owned()
    }
}

impl From<Result<TransformOutput, TransformError>> for TransformResult {
    fn from(result: Result<TransformOutput, TransformError>) -> Self {
        match result {
            Ok(output) => Self {
                status: TRANSFORM_OK,
                data: PdBuf::from(output.data),
                lengths: PdVec::from(output.lengths),
                message: PdBuf::empty(),
            },
            Err(err) => Self {
                status: TRANSFORM_ERROR,
                data: PdBuf::empty(),
                lengths: PdVec::empty(),
                message: PdBuf::from(err.0),
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_value() {
        assert_eq!(Value::new(Some(b"abc")).get(), Some(b"abc".as_slice()));
        assert_eq!(Value::new(Some(b"")).get(), Some(b"".as_slice()));
        assert_eq!(Value::new(None).get(), None);
    }

    #[test]
    fn test_mask_output() {
        let mut output = TransformOutput::default();
        output.push(Some(b"ab"));
        output.push(None);
        output.push(Some(b""));
        assert_eq!(output.len(), 3);

        let mut result = TransformResult::from(Ok(output));
        assert_eq!(result.status(), TRANSFORM_OK);
        assert_eq!(result.data(), b"ab");
        assert_eq!(result.lengths(), &[2, -1, 0]);
        result.free();
    }
}
