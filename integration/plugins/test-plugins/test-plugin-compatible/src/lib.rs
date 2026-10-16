//! Tests that the plugin works as expected.
//! The plugin uses the same version of pgdog-plugin as PgDog and the same rustc version,
//! so it should be loaded and executed.
//!
//! It also implements the statement and transform hooks, acting only on
//! statements containing one of its markers (see `hooks_spec.rb`).

use pgdog_plugin::{
    Capabilities, Context, MessageCodes, PdStr, Plugin, Route, StatementContext, StatementOutput,
    TransformContext, TransformOutput, plugin,
};
use std::sync::OnceLock;

/// Replaced with [`REWRITTEN`].
const REWRITE: &str = "pgdog_plugin_rewrite";
const REWRITTEN: &str = "pgdog_plugin_rewritten";
/// Statements containing this are blocked.
const BLOCK: &str = "pgdog_plugin_block";
/// Text columns of the statement's rows are uppercased.
const UPPERCASE: &str = "pgdog_plugin_uppercase";

plugin!(TestPlugin);

static ROUTE_CALLED: OnceLock<()> = OnceLock::new();

struct TestPlugin;

impl Plugin for TestPlugin {
    extern "C-unwind" fn version() -> PdStr<'static> {
        "0".into()
    }

    fn capabilities() -> Capabilities {
        Capabilities::ROUTE | Capabilities::STATEMENT | Capabilities::TRANSFORM
    }

    fn statement(context: StatementContext<'_>) -> StatementOutput {
        let sql = &*context.sql;
        if sql.contains(BLOCK) {
            StatementOutput::block(
                "42501",
                format!("blocked by test plugin for {}", &*context.identity.user),
            )
        } else if sql.contains(REWRITE) {
            StatementOutput::rewrite(sql.replace(REWRITE, REWRITTEN), 0)
        } else if sql.contains(UPPERCASE) {
            StatementOutput::cont().with_transform(1, MessageCodes::none().with('D'))
        } else {
            StatementOutput::cont()
        }
    }

    fn transform(context: TransformContext<'_>) -> TransformOutput {
        match uppercase_row(
            context.payload.as_slice(),
            context.result_formats.as_slice(),
        ) {
            Some(row) => TransformOutput::replace(row),
            None => TransformOutput::fail(),
        }
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

/// Uppercase the text columns of a DataRow body. `None` if it's malformed.
fn uppercase_row(payload: &[u8], formats: &[i16]) -> Option<Vec<u8>> {
    let columns = i16::from_be_bytes(payload.get(..2)?.try_into().ok()?);
    let mut row = payload[..2].to_vec();
    let mut rest = &payload[2..];

    for column in 0..columns as usize {
        let len = i32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
        row.extend_from_slice(&rest[..4]);
        rest = &rest[4..];
        // NULL.
        if len < 0 {
            continue;
        }
        let value = rest.get(..len as usize)?;
        rest = &rest[len as usize..];

        let format = match formats {
            [] => 0,
            [format] => *format,
            formats => *formats.get(column)?,
        };
        if format == 0 {
            row.extend(value.to_ascii_uppercase());
        } else {
            row.extend_from_slice(value);
        }
    }

    Some(row)
}
