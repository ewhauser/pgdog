//! Tests that the plugin works as expected.
//! The plugin uses the same version of pgdog-plugin as PgDog and the same rustc version,
//! so it should be loaded and executed.
//!
//! It also implements the statement, mask and error hooks, acting only on
//! statements and errors containing one of its markers (see `hooks_spec.rb`).

use pgdog_plugin::{
    Capabilities, ColumnMask, Context, Deny, ErrorFields, MaskBatch, MaskError, MaskId,
    MaskOutput, PdStr, Plugin, Redaction, Route, Session, Verdict, plugin,
};
use std::sync::OnceLock;

/// Replaced with [`REWRITTEN`].
const REWRITE: &str = "pgdog_plugin_rewrite";
const REWRITTEN: &str = "pgdog_plugin_rewritten";
/// Statements containing this are denied.
const BLOCK: &str = "pgdog_plugin_block";
/// The first column of the statement's rows is uppercased.
const UPPERCASE: &str = "pgdog_plugin_uppercase";
/// Replaced with [`REDACTED`] in errors.
const SECRET: &str = "pgdog_plugin_secret";
const REDACTED: &str = "[redacted]";

plugin!(TestPlugin);

static ROUTE_CALLED: OnceLock<()> = OnceLock::new();

struct TestPlugin;

impl Plugin for TestPlugin {
    extern "C-unwind" fn version() -> PdStr<'static> {
        "0".into()
    }

    fn capabilities() -> Capabilities {
        Capabilities::ROUTE | Capabilities::STATEMENT | Capabilities::MASK | Capabilities::ERRORS
    }

    fn statement(session: &Session<'_>, sql: &str) -> Verdict {
        if sql.contains(BLOCK) {
            Verdict::Deny(Deny::insufficient_privilege(format!(
                "blocked by test plugin for {}",
                &*session.user
            )))
        } else if sql.contains(REWRITE) {
            Verdict::rewrite(sql.replace(REWRITE, REWRITTEN))
        } else if sql.contains(UPPERCASE) {
            Verdict::Rewrite {
                sql: sql.to_owned(),
                columns: vec![ColumnMask::new(0, MaskId(1), 25)],
                redact_errors: false,
            }
        } else {
            Verdict::Allow
        }
    }

    fn mask_rows(batch: &MaskBatch<'_>, out: &mut MaskOutput) -> Result<(), MaskError> {
        for column in batch.columns() {
            for value in column.values() {
                out.push(value.map(|value| value.to_ascii_uppercase()).as_deref());
            }
        }
        Ok(())
    }

    fn redact_error(_session: &Session<'_>, error: &ErrorFields<'_>) -> Redaction {
        if !error.fields().iter().any(|field| field.value.contains(SECRET)) {
            return Redaction::Keep;
        }
        Redaction::Replace(
            error
                .fields()
                .iter()
                .map(|field| (field.code, field.value.replace(SECRET, REDACTED)))
                .collect(),
        )
    }

    fn route(context: Context<'_>) -> Route {
        // The checks below are for the parameterized statements of
        // extended_spec.rb; hooks_spec.rb sends other statements too.
        if context.parameters().parameters.is_empty() {
            return Route::unknown();
        }

        assert!(!context.read_only());
        assert!(context.has_primary());
        assert!(context.has_replicas());
        assert_eq!(context.shards(), 1);
        assert!(!context.sharded());
        assert!(!context.write_override());

        // Write to output file on first call only
        ROUTE_CALLED.get_or_init(|| {
            let file_path =
                std::path::Path::new(&env!("CARGO_MANIFEST_DIR")).join("route-called.test");
            std::fs::write(&file_path, "route method was called").unwrap();
        });

        Route::unknown()
    }
}
