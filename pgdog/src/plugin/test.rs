//! In-process plugin for testing plugin hooks.
//!
//! It only acts on statements containing one of its markers, so loading it
//! doesn't change the behavior of unrelated tests running in the same process.
use std::sync::atomic::{AtomicU64, Ordering};

use pgdog_plugin::{
    Capabilities, MessageCodes, PdStr, Plugin, PluginVtable, StatementContext, StatementOutput,
    TransformContext, TransformOutput,
};

use super::{LoadedPlugin, PLUGINS, Plugins};

/// Statements containing this are blocked.
pub(crate) const BLOCK: &str = "pgdog_test_block";
/// This is replaced with [`REWRITTEN`].
pub(crate) const REWRITE: &str = "pgdog_test_rewrite";
pub(crate) const REWRITTEN: &str = "pgdog_test_rewritten";
/// This is replaced with `pgdog_test_versioned_{VERSION}`, tagged with [`VERSION`].
pub(crate) const VERSIONED: &str = "pgdog_test_version";
/// Statements containing this get a transform that replaces every DataRow
/// with a single text column [`TRANSFORMED`].
pub(crate) const TRANSFORM: &str = "pgdog_test_transform";
pub(crate) const TRANSFORMED: &str = "transformed";
/// Statements containing this get a transform that fails.
pub(crate) const TRANSFORM_FAIL: &str = "pgdog_test_transform_fail";

/// Simulates a plugin configuration change.
pub(crate) static VERSION: AtomicU64 = AtomicU64::new(1);
/// Number of transform handles released.
pub(crate) static RELEASED: AtomicU64 = AtomicU64::new(0);

const HANDLE_REPLACE: u64 = 1;
const HANDLE_FAIL: u64 = 2;

struct TestPlugin;

impl Plugin for TestPlugin {
    extern "C-unwind" fn version() -> PdStr<'static> {
        "0".into()
    }

    fn capabilities() -> Capabilities {
        Capabilities::STATEMENT | Capabilities::TRANSFORM
    }

    fn statement(context: StatementContext<'_>) -> StatementOutput {
        let sql = &*context.sql;
        if sql.contains(BLOCK) {
            StatementOutput::block("42501", format!("blocked for {}", &*context.identity.user))
        } else if sql.contains(TRANSFORM_FAIL) {
            StatementOutput::cont().with_transform(HANDLE_FAIL, MessageCodes::none().with('D'))
        } else if sql.contains(TRANSFORM) {
            StatementOutput::cont().with_transform(HANDLE_REPLACE, MessageCodes::none().with('D'))
        } else if sql.contains(REWRITE) {
            StatementOutput::rewrite(sql.replace(REWRITE, REWRITTEN), 0)
        } else if sql.contains(VERSIONED) {
            let version = VERSION.load(Ordering::Relaxed);
            StatementOutput::rewrite(
                sql.replace(VERSIONED, &format!("pgdog_test_versioned_{version}")),
                version,
            )
        } else {
            StatementOutput::cont()
        }
    }

    fn transform(context: TransformContext<'_>) -> TransformOutput {
        if context.handle == HANDLE_FAIL {
            return TransformOutput::fail();
        }
        // DataRow with one text column.
        let mut body = 1_i16.to_be_bytes().to_vec();
        body.extend((TRANSFORMED.len() as i32).to_be_bytes());
        body.extend(TRANSFORMED.as_bytes());
        TransformOutput::replace(body)
    }

    fn release_transform(_handle: u64) {
        RELEASED.fetch_add(1, Ordering::Relaxed);
    }
}

static VTABLE: PluginVtable = PluginVtable::from_plugin::<TestPlugin>();

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
        }
    });
}
