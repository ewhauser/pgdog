//! In-process plugin for testing plugin hooks.
//!
//! It only acts on statements and errors containing one of its markers, so
//! loading it doesn't change the behavior of unrelated tests running in the
//! same process.
use std::sync::atomic::{AtomicU64, Ordering};

use pgdog_plugin::{
    Capabilities, ColumnTransform, Deny, ErrorFields, PdStr, Plugin, PluginVtable, Redaction,
    Session, TransformBatch, TransformError, TransformId, TransformOutput, Verdict,
    types::{DataType, Datum},
};

use super::{LoadedPlugin, PLUGINS, Plugins};

/// Statements containing this are denied.
pub(crate) const BLOCK: &str = "pgdog_test_block";
/// This is replaced with [`REWRITTEN`].
pub(crate) const REWRITE: &str = "pgdog_test_rewrite";
pub(crate) const REWRITTEN: &str = "pgdog_test_rewritten";
/// This is replaced with `pgdog_test_versioned_{VERSION}`. [`VERSION`] is also
/// the plugin's generation.
pub(crate) const VERSIONED: &str = "pgdog_test_version";
/// The first column of these statements is replaced with NULL by PgDog, and
/// the second, text, uppercased by the plugin.
pub(crate) const MASK_NULL: &str = "pgdog_test_null_mask";
/// Errors and notices of these statements are redacted.
pub(crate) const REDACT_ERRORS: &str = "pgdog_test_redact_errors";
/// The first column of these statements, text, is uppercased by the plugin.
pub(crate) const TRANSFORM: &str = "pgdog_test_mask";
/// The first column of these statements, an integer, is incremented by the plugin.
pub(crate) const MASK_INT: &str = "pgdog_test_int_mask";
/// Like [`TRANSFORM`], with a blocking mask.
pub(crate) const MASK_BLOCKING: &str = "pgdog_test_slow_mask";
/// The first column of the second result set is uppercased.
pub(crate) const MASK_SECOND: &str = "pgdog_test_second_mask";
/// The first column of these statements is masked, and masking fails.
pub(crate) const MASK_FAIL: &str = "pgdog_test_failing_mask";
/// These statements get a parameter the client didn't prepare.
pub(crate) const BAD_PARAMS: &str = "pgdog_test_bad_params";
/// Errors containing this are redacted: the marker is replaced with [`REDACTED`],
/// and the plugin tries to change the SQLSTATE.
pub(crate) const SECRET: &str = "pgdog_test_secret";
pub(crate) const REDACTED: &str = "[redacted]";
/// Redacting errors containing this panics.
pub(crate) const REDACT_PANIC: &str = "pgdog_test_redact_panic";

/// Simulates a plugin configuration change.
pub(crate) static VERSION: AtomicU64 = AtomicU64::new(1);
/// Number of times the statement hook saw [`VERSIONED`].
pub(crate) static VERSIONED_CALLS: AtomicU64 = AtomicU64::new(0);
/// Number of batches masked.
pub(crate) static MASK_BATCHES: AtomicU64 = AtomicU64::new(0);

pub(crate) const UPPERCASE: TransformId = TransformId(1);
const FAIL: TransformId = TransformId(2);
const INCREMENT: TransformId = TransformId(3);
/// Replaces text with 64 bytes, like a hex digest: longer than most values.
pub(crate) const DIGEST: TransformId = TransformId(4);
/// What [`DIGEST`] masks values to.
pub(crate) const DIGEST_VALUE: [u8; 64] = [b'f'; 64];

const TEXT: u32 = 25;
const INTEGER: u32 = 23;

struct TestPlugin;

impl Plugin for TestPlugin {
    extern "C-unwind" fn version() -> PdStr<'static> {
        "0".into()
    }

    fn capabilities() -> Capabilities {
        Capabilities::STATEMENT | Capabilities::TRANSFORM | Capabilities::ERRORS
    }

    fn statement(session: &Session<'_>, sql: &str) -> Verdict {
        let mask = |mask: ColumnTransform| Verdict::transform(sql, vec![mask]);

        if sql.contains(BLOCK) {
            Verdict::Deny(Deny::insufficient_privilege(format!(
                "blocked for {}",
                &*session.user
            )))
        } else if sql.contains(MASK_NULL) {
            // The second column through the plugin, the first replaced with NULL.
            Verdict::transform(
                sql,
                vec![
                    ColumnTransform::null(0),
                    ColumnTransform::new(1, UPPERCASE, TEXT),
                ],
            )
        } else if sql.contains(REDACT_ERRORS) {
            Verdict::rewrite(sql).redact_errors(true)
        } else if sql.contains(MASK_FAIL) {
            mask(ColumnTransform::new(0, FAIL, TEXT))
        } else if sql.contains(MASK_BLOCKING) {
            mask(ColumnTransform::new(0, UPPERCASE, TEXT).blocking())
        } else if sql.contains(MASK_SECOND) {
            mask(ColumnTransform::new(0, UPPERCASE, TEXT).in_result(1))
        } else if sql.contains(MASK_INT) {
            mask(ColumnTransform::new(0, INCREMENT, INTEGER))
        } else if sql.contains(TRANSFORM) {
            mask(ColumnTransform::new(0, UPPERCASE, TEXT))
        } else if sql.contains(BAD_PARAMS) {
            Verdict::rewrite(format!("{sql}, $9::int"))
        } else if sql.contains(REWRITE) {
            Verdict::rewrite(sql.replace(REWRITE, REWRITTEN))
        } else if sql.contains(VERSIONED) {
            VERSIONED_CALLS.fetch_add(1, Ordering::Relaxed);
            let version = VERSION.load(Ordering::Relaxed);
            Verdict::rewrite(sql.replace(VERSIONED, &format!("pgdog_test_versioned_{version}")))
        } else {
            Verdict::Allow
        }
    }

    fn generation() -> u64 {
        VERSION.load(Ordering::Relaxed)
    }

    fn transform_rows(
        batch: &TransformBatch<'_>,
        out: &mut TransformOutput,
    ) -> Result<(), TransformError> {
        MASK_BATCHES.fetch_add(1, Ordering::Relaxed);
        for column in batch.columns() {
            if column.transform == FAIL {
                return Err(TransformError::new("test mask failed"));
            }
            if column.transform == DIGEST {
                for value in column.values() {
                    out.push(value.map(|_| DIGEST_VALUE.as_slice()));
                }
                continue;
            }
            for value in column.values() {
                let masked = match value {
                    None => None,
                    Some(value) if column.transform == INCREMENT => {
                        let datum = Datum::new(value, DataType::Integer, column.format, false)
                            .map_err(|err| TransformError::new(err.to_string()))?;
                        let Datum::Integer(n) = datum else {
                            return Err(TransformError::new("not an integer"));
                        };
                        let encoded = Datum::Integer(n + 1)
                            .encode(column.format)
                            .map_err(|err| TransformError::new(err.to_string()))?;
                        Some(encoded.to_vec())
                    }
                    Some(value) => Some(value.to_ascii_uppercase()),
                };
                out.push(masked.as_deref());
            }
        }
        Ok(())
    }

    fn redact_error(_session: &Session<'_>, error: &ErrorFields<'_>) -> Redaction {
        let fields = error.fields();
        if fields
            .iter()
            .any(|field| field.value.contains(REDACT_PANIC))
        {
            panic!("redaction failed");
        }
        if !fields.iter().any(|field| field.value.contains(SECRET)) {
            return Redaction::Keep;
        }
        let mut fields: Vec<_> = fields
            .iter()
            .map(|field| (field.code, field.value.replace(SECRET, REDACTED)))
            .collect();
        // Not allowed: PgDog keeps the original.
        fields.push((b'C', "00000".into()));
        Redaction::Replace(fields)
    }
}

static VTABLE: PluginVtable = PluginVtable::from_plugin::<TestPlugin>();

/// The test plugin, loaded.
pub(crate) fn test_plugin() -> &'static LoadedPlugin {
    load_test_plugin();
    super::plugins()
        .iter()
        .find(|plugin| plugin.name() == "test")
        .expect("test plugin is loaded")
}

/// Load the test plugin. Idempotent.
pub(crate) fn load_test_plugin() {
    PLUGINS.get_or_init(|| {
        let capabilities = VTABLE.capabilities();
        Plugins {
            list: vec![LoadedPlugin {
                name: "test".into(),
                vtable: &VTABLE,
                capabilities,
            }],
            capabilities,
            catalog_parts: Default::default(),
        }
    });
}
