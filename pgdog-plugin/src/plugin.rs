//! PgDog's plugin interface.
//!
//! This loads the shared library using [`libloading`] and exposes
//! a safe interface to the plugin's methods.
//!

use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

use crate::{
    Capabilities, Config, Context, PdStr, Route, StatementAction, StatementContext,
    StatementDecision, StatementOutput, TransformAction, TransformContext, TransformOutput,
    parameters::{Parameters, RawParameters},
    statement::{ACTION_BLOCK, ACTION_CONTINUE, ACTION_PANIC, ACTION_REWRITE},
    transform::{TRANSFORM_FAIL, TRANSFORM_FORWARD, TRANSFORM_REPLACE},
};
use libloading::{Library, Symbol, library_filename};

/// Plugin interface.
///
/// This is the vtable of a struct which implements [`Plugin`]
// !IMPORTANT!
// Any changes to this struct *must* come with a change to the crate's minor
// version
#[derive(Debug)]
#[repr(C)]
pub struct PluginVtable {
    // SAFETY: It is critically important that this continue to be the first
    // field on this struct, so that regardless of other breakign changes in
    // the future, we can detect the use of an outdated version
    /// Plugin API version.
    pgdog_plugin_api_version: extern "C-unwind" fn() -> PdStr<'static>,
    /// Compiler version.
    rustc_version: extern "C-unwind" fn() -> PdStr<'static>,
    /// Plugin version
    plugin_version: extern "C-unwind" fn() -> PdStr<'static>,
    /// Initialization routine.
    init: extern "C-unwind" fn(),
    /// Shutdown routine.
    fini: extern "C-unwind" fn(),
    /// Configure plugin.
    config: extern "C-unwind" fn(Config<'_>) -> bool,
    /// Route query.
    route: extern "C-unwind" fn(
        u64,
        bool,
        bool,
        bool,
        bool,
        &pg_raw_parse::nodes::RawStmt,
        RawParameters<'_>,
    ) -> Route,
    /// Logging initialization.
    logging_init: extern "C-unwind" fn(Config<'_>),
    /// Hooks implemented by the plugin.
    capabilities: extern "C-unwind" fn() -> u64,
    /// Rewrite or block a statement.
    statement: extern "C-unwind" fn(&StatementContext<'_>) -> StatementOutput,
    /// Free the output of `statement`.
    free_statement_output: extern "C-unwind" fn(&mut StatementOutput),
    /// Transform a server message.
    transform: extern "C-unwind" fn(&TransformContext<'_>) -> TransformOutput,
    /// Free the output of `transform`.
    free_transform_output: extern "C-unwind" fn(&mut TransformOutput),
    /// Release a transform handle.
    release_transform: extern "C-unwind" fn(u64),
    /// Receive a schema snapshot.
    schema: extern "C-unwind" fn(PdStr<'_>, u64, PdStr<'_>),
    /// Reload configuration.
    reload: extern "C-unwind" fn() -> bool,
}

/// A plugin hook didn't return a usable result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookError {
    /// The hook panicked. The panic was caught inside the plugin.
    Panicked,
    /// The hook returned output PgDog can't use.
    InvalidOutput(&'static str),
}

impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Panicked => write!(f, "plugin hook panicked"),
            Self::InvalidOutput(reason) => {
                write!(f, "plugin hook returned invalid output: {reason}")
            }
        }
    }
}

impl std::error::Error for HookError {}

pub trait Plugin {
    /// The version of your plugin. You can simply return
    /// `env!("CARGO_PKG_VERSION").into()`
    extern "C-unwind" fn version() -> PdStr<'static>;

    /// Execute plugin's initialization routine.
    /// Returns true if the route exists and was executed, false otherwise.
    extern "C-unwind" fn init() {}
    /// Execute plugin's shutdown routine.
    extern "C-unwind" fn fini() {}
    /// Pass configuration to the plugin. Return false if loading configuration
    /// failed
    extern "C-unwind" fn config(_config: Config<'_>) -> bool {
        true
    }
    /// Execute plugin's route routine. Determines where a statement should be sent.
    /// Returns a route if the routine is defined, or `None` if not.
    ///
    /// ### Arguments
    ///
    /// * `context`: Statement context created by PgDog's query router.
    fn route(_context: Context<'_>) -> Route {
        Route::unknown()
    }

    #[doc(hidden)]
    extern "C-unwind" fn route_raw(
        shards: u64,
        has_replicas: bool,
        has_primary: bool,
        in_transaction: bool,
        write_override: bool,
        query: &pg_raw_parse::nodes::RawStmt,
        params: RawParameters<'_>,
    ) -> Route {
        let context = Context {
            shards,
            has_replicas,
            has_primary,
            in_transaction,
            write_override,
            query,
            params: Parameters::from_raw(params),
        };
        Self::route(context)
    }

    /// Returns the Rust compiler version used to build the plugin.
    /// This version must match the compiler version used to build
    /// PgDog, or the plugin won't be loaded.
    extern "C-unwind" fn rustc_version() -> PdStr<'static> {
        crate::RUSTC_VERSION.into()
    }

    /// Get plugin API version based on `pgdog-plugin` crate version.
    /// This version must match the version used when building pgdog main executable,
    /// otherwise the plugin won't be loaded.
    extern "C-unwind" fn plugin_api_version() -> PdStr<'static> {
        crate::VERSION.into()
    }

    /// Initialize plugin logging with PgDog's log configuration.
    extern "C-unwind" fn logging_init(config: Config<'_>) {
        crate::logging::init(config)
    }

    /// Hooks this plugin implements. PgDog only calls hooks listed here.
    ///
    /// Defaults to [`Capabilities::ROUTE`], which is how plugins
    /// behaved before capabilities existed.
    fn capabilities() -> Capabilities {
        Capabilities::ROUTE
    }

    #[doc(hidden)]
    extern "C-unwind" fn capabilities_raw() -> u64 {
        Self::capabilities().bits()
    }

    /// Inspect a statement before PgDog parses it, and rewrite or block it.
    /// Requires [`Capabilities::STATEMENT`]. See [`crate::statement`].
    fn statement(_context: StatementContext<'_>) -> StatementOutput {
        StatementOutput::cont()
    }

    #[doc(hidden)]
    extern "C-unwind" fn statement_raw(context: &StatementContext<'_>) -> StatementOutput {
        let context = *context;
        // Panics are caught here, inside the plugin, so the panic
        // payload is freed by the allocator that created it.
        catch_unwind(AssertUnwindSafe(|| Self::statement(context)))
            .unwrap_or_else(|_| StatementOutput::panicked())
    }

    #[doc(hidden)]
    extern "C-unwind" fn free_statement_output(output: &mut StatementOutput) {
        output.free()
    }

    /// Inspect or rewrite a server message of a statement the plugin attached
    /// a transform to. Requires [`Capabilities::TRANSFORM`]. See [`crate::transform`].
    fn transform(_context: TransformContext<'_>) -> TransformOutput {
        TransformOutput::forward()
    }

    #[doc(hidden)]
    extern "C-unwind" fn transform_raw(context: &TransformContext<'_>) -> TransformOutput {
        let context = *context;
        catch_unwind(AssertUnwindSafe(|| Self::transform(context)))
            .unwrap_or_else(|_| TransformOutput::fail())
    }

    #[doc(hidden)]
    extern "C-unwind" fn free_transform_output(output: &mut TransformOutput) {
        output.free()
    }

    /// The statement a transform was attached to is done. PgDog calls this exactly
    /// once per transform handle.
    fn release_transform(_handle: u64) {}

    #[doc(hidden)]
    extern "C-unwind" fn release_transform_raw(handle: u64) {
        let _ = catch_unwind(AssertUnwindSafe(|| Self::release_transform(handle)));
    }

    /// Receive a snapshot of a database's schema, serialized as JSON.
    /// Requires [`Capabilities::SCHEMA`].
    ///
    /// Called when PgDog loads or reloads the schema. `epoch` increases with every
    /// snapshot PgDog takes, across all databases.
    fn schema(_database: &str, _epoch: u64, _snapshot: &str) {}

    #[doc(hidden)]
    extern "C-unwind" fn schema_raw(database: PdStr<'_>, epoch: u64, snapshot: PdStr<'_>) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            Self::schema(&database, epoch, &snapshot)
        }));
    }

    /// Reload the plugin's configuration. Called when PgDog reloads its own.
    /// Return false if the new configuration is invalid; the plugin should keep
    /// using its previous one.
    fn reload() -> bool {
        true
    }

    #[doc(hidden)]
    extern "C-unwind" fn reload_raw() -> bool {
        catch_unwind(Self::reload).unwrap_or(false)
    }
}

impl PluginVtable {
    #[doc(hidden)]
    pub const fn from_plugin<T: Plugin>() -> Self {
        Self {
            init: T::init,
            fini: T::fini,
            config: T::config,
            route: T::route_raw,
            rustc_version: T::rustc_version,
            plugin_version: T::version,
            pgdog_plugin_api_version: T::plugin_api_version,
            logging_init: T::logging_init,
            capabilities: T::capabilities_raw,
            statement: T::statement_raw,
            free_statement_output: T::free_statement_output,
            transform: T::transform_raw,
            free_transform_output: T::free_transform_output,
            release_transform: T::release_transform_raw,
            schema: T::schema_raw,
            reload: T::reload_raw,
        }
    }

    /// Load plugin's shared library using a cross-platform naming convention.
    ///
    /// Plugin has to be in `LD_LIBRARY_PATH`, in a standard location
    /// for the operating system, or be provided as an absolute or relative path,
    /// including the platform-specific extension.
    ///
    /// ### Example
    ///
    /// ```no_run
    /// use pgdog_plugin::PluginVtable;
    ///
    /// let plugin_lib = PluginVtable::library("/home/pgdog/plugin.so").unwrap();
    /// let plugin_lib = PluginVtable::library("plugin.so").unwrap();
    /// ```
    ///
    pub fn library<P: AsRef<Path>>(name: P) -> Result<Library, libloading::Error> {
        if name.as_ref().extension().is_some() {
            let name = name.as_ref().display().to_string();
            unsafe { Library::new(&name) }
        } else {
            let name = library_filename(name.as_ref());
            unsafe { Library::new(name) }
        }
    }

    /// Load standard plugin methods from the plugin library. Returns None
    /// if the vtable symbol was not defined (e.g. it was compiled for
    /// pgdog_plugin 0.3.0 or earlier, or did not call the plugin macro)
    pub fn load<'a>(library: &'a Library) -> Option<&'a Self> {
        // SAFETY: This symbol should have been generated by our macro, meaning
        // it is never visible to outside code
        unsafe {
            let symbol: Symbol<'a, *const Self> = library.get(b"PGDOG_PLUGIN_VTABLE\0").ok()?;
            Some(&**symbol)
        }
    }

    pub fn init(&self) {
        (self.init)()
    }

    pub fn fini(&self) {
        (self.fini)()
    }

    pub fn config(&self, config: Config<'_>) -> bool {
        (self.config)(config)
    }

    pub fn route(&self, context: Context<'_>) -> Route {
        (self.route)(
            context.shards,
            context.has_replicas,
            context.has_primary,
            context.in_transaction,
            context.write_override,
            context.query,
            context.params.as_raw(),
        )
    }

    pub fn rustc_version(&self) -> PdStr<'static> {
        (self.rustc_version)()
    }

    pub fn plugin_version(&self) -> PdStr<'static> {
        (self.plugin_version)()
    }

    pub fn pgdog_plugin_api_version(&self) -> PdStr<'static> {
        (self.pgdog_plugin_api_version)()
    }

    pub fn logging_init(&self, config: Config<'_>) {
        (self.logging_init)(config)
    }

    /// Hooks the plugin implements.
    pub fn capabilities(&self) -> Capabilities {
        Capabilities::from_bits((self.capabilities)())
    }

    /// Run the statement hook. Plugin-owned output is copied and freed
    /// before returning.
    pub fn statement(
        &self,
        context: &StatementContext<'_>,
    ) -> Result<StatementDecision, HookError> {
        let mut output = (self.statement)(context);
        let decision = Self::decode_statement(&output);
        let transform = output.transform();
        (self.free_statement_output)(&mut output);

        match decision {
            Ok(action) => Ok(StatementDecision { action, transform }),
            Err(err) => {
                if let Some(transform) = transform {
                    self.release_transform(transform.handle);
                }
                Err(err)
            }
        }
    }

    fn decode_statement(output: &StatementOutput) -> Result<StatementAction, HookError> {
        match output.action() {
            ACTION_CONTINUE => Ok(StatementAction::Continue),
            ACTION_REWRITE => {
                let sql = output
                    .sql()
                    .as_str()
                    .ok_or(HookError::InvalidOutput("rewritten SQL is not valid UTF-8"))?;
                Ok(StatementAction::Rewrite {
                    sql: sql.to_owned(),
                    variant_tag: output.variant_tag(),
                })
            }
            ACTION_BLOCK => {
                let sqlstate = std::str::from_utf8(output.sqlstate())
                    .map_err(|_| HookError::InvalidOutput("SQLSTATE is not ASCII"))?;
                let message = String::from_utf8_lossy(output.message().as_bytes());
                Ok(StatementAction::Block {
                    sqlstate: sqlstate.to_owned(),
                    message: message.into_owned(),
                })
            }
            ACTION_PANIC => Err(HookError::Panicked),
            _ => Err(HookError::InvalidOutput("unknown statement action")),
        }
    }

    /// Run the transform hook. Plugin-owned output is copied and freed
    /// before returning.
    pub fn transform(&self, context: &TransformContext<'_>) -> Result<TransformAction, HookError> {
        let mut output = (self.transform)(context);
        let action = match output.action() {
            TRANSFORM_FORWARD => Ok(TransformAction::Forward),
            TRANSFORM_REPLACE => Ok(TransformAction::Replace(
                output.payload().as_bytes().to_vec(),
            )),
            TRANSFORM_FAIL => Ok(TransformAction::Fail),
            _ => Err(HookError::InvalidOutput("unknown transform action")),
        };
        (self.free_transform_output)(&mut output);
        action
    }

    /// Release a transform handle.
    pub fn release_transform(&self, handle: u64) {
        (self.release_transform)(handle)
    }

    /// Send a schema snapshot.
    pub fn schema(&self, database: &str, epoch: u64, snapshot: &str) {
        (self.schema)(database.into(), epoch, snapshot.into())
    }

    /// Reload plugin configuration.
    pub fn reload(&self) -> bool {
        (self.reload)()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Identity, MessageCodes, PdSlice, StatementKind};

    struct TestPlugin;

    impl Plugin for TestPlugin {
        extern "C-unwind" fn version() -> PdStr<'static> {
            "0".into()
        }

        fn capabilities() -> Capabilities {
            Capabilities::STATEMENT | Capabilities::TRANSFORM
        }

        fn statement(context: StatementContext<'_>) -> StatementOutput {
            match &*context.sql {
                "panic" => panic!("statement hook panicked"),
                "block" => StatementOutput::block("42501", "blocked"),
                "transform" => {
                    StatementOutput::cont().with_transform(7, MessageCodes::none().with('D'))
                }
                sql => {
                    StatementOutput::rewrite(format!("{sql} /* {} */", &*context.identity.user), 42)
                }
            }
        }

        fn transform(context: TransformContext<'_>) -> TransformOutput {
            match context.payload.as_slice() {
                b"panic" => panic!("transform hook panicked"),
                b"fail" => TransformOutput::fail(),
                b"keep" => TransformOutput::forward(),
                payload => TransformOutput::replace(payload.iter().rev().copied().collect()),
            }
        }
    }

    static VTABLE: PluginVtable = PluginVtable::from_plugin::<TestPlugin>();

    fn statement(sql: &str) -> Result<StatementDecision, HookError> {
        let context = StatementContext {
            identity: Identity {
                user: "alice".into(),
                ..Default::default()
            },
            kind: StatementKind::Query,
            sql: sql.into(),
            statement_name: "".into(),
            search_path: "".into(),
            in_transaction: false,
        };
        VTABLE.statement(&context)
    }

    fn transform(payload: &[u8]) -> Result<TransformAction, HookError> {
        VTABLE.transform(&TransformContext {
            handle: 7,
            code: b'D',
            payload: PdSlice::from(payload),
            result_formats: PdSlice::default(),
        })
    }

    #[test]
    fn test_capabilities() {
        assert_eq!(
            VTABLE.capabilities(),
            Capabilities::STATEMENT | Capabilities::TRANSFORM
        );
    }

    #[test]
    fn test_statement_hook() {
        assert_eq!(
            statement("SELECT 1").unwrap(),
            StatementDecision {
                action: StatementAction::Rewrite {
                    sql: "SELECT 1 /* alice */".into(),
                    variant_tag: 42,
                },
                transform: None,
            }
        );
        assert_eq!(
            statement("block").unwrap().action,
            StatementAction::Block {
                sqlstate: "42501".into(),
                message: "blocked".into(),
            }
        );
        let decision = statement("transform").unwrap();
        assert_eq!(decision.action, StatementAction::Continue);
        let transform = decision.transform.unwrap();
        assert_eq!(transform.handle, 7);
        assert!(transform.codes.contains('D'));
        assert_eq!(statement("panic"), Err(HookError::Panicked));
    }

    #[test]
    fn test_transform_hook() {
        assert_eq!(
            transform(b"abc").unwrap(),
            TransformAction::Replace(b"cba".to_vec())
        );
        assert_eq!(transform(b"keep").unwrap(), TransformAction::Forward);
        assert_eq!(transform(b"fail").unwrap(), TransformAction::Fail);
        // Panics fail closed.
        assert_eq!(transform(b"panic").unwrap(), TransformAction::Fail);
    }
}
