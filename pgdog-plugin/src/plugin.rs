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
    Access, Capabilities, Catalog, CatalogParts, Config, Context, PdStr, Route, Session, Verdict,
    catalog,
    mask::{MASK_ERROR, MASK_OK, MASK_PANIC, MaskBatch, MaskError, MaskOutput, MaskResult},
    parameters::{Parameters, RawParameters},
    redact::{ErrorFields, REDACT_KEEP, REDACT_PANIC, REDACT_REPLACE, Redaction, RedactionOutput},
    statement::{VERDICT_ALLOW, VERDICT_DENY, VERDICT_PANIC, VERDICT_REWRITE, VerdictOutput},
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
    /// Decide what a statement may do.
    statement: extern "C-unwind" fn(&Session<'_>, PdStr<'_>) -> VerdictOutput,
    /// Decide whether a fast-path function call may run.
    function_call: extern "C-unwind" fn(&Session<'_>, u32) -> VerdictOutput,
    /// Free the output of `statement` and `function_call`.
    free_verdict: extern "C-unwind" fn(&mut VerdictOutput),
    /// Generation of the plugin's verdicts.
    generation: extern "C-unwind" fn() -> u64,
    /// Mask a batch of rows.
    mask_rows: extern "C-unwind" fn(&MaskBatch<'_>) -> MaskResult,
    /// Free the output of `mask_rows`.
    free_mask_result: extern "C-unwind" fn(&mut MaskResult),
    /// Redact an error or notice.
    redact_error: extern "C-unwind" fn(&Session<'_>, &ErrorFields<'_>) -> RedactionOutput,
    /// Free the output of `redact_error`.
    free_redaction: extern "C-unwind" fn(&mut RedactionOutput),
    /// Catalog parts the plugin needs.
    catalog_parts: extern "C-unwind" fn() -> u32,
    /// Receive a database's catalog.
    catalog: CatalogFn,
    /// Reload configuration.
    reload: extern "C-unwind" fn() -> bool,
}

/// `Catalog` is a Rust type, passed by reference. That's sound because plugins
/// are built with the same compiler and `pgdog-plugin` version as PgDog,
/// like the AST passed to `route`.
#[allow(improper_ctypes_definitions)]
type CatalogFn = extern "C-unwind" fn(PdStr<'_>, &Catalog);

/// A plugin hook didn't return a usable result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookError {
    /// The hook panicked. The panic was caught inside the plugin.
    Panicked,
    /// The hook returned output PgDog can't use.
    InvalidOutput(&'static str),
    /// The hook reported an error.
    Failed(String),
}

impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Panicked => write!(f, "plugin hook panicked"),
            Self::InvalidOutput(reason) => {
                write!(f, "plugin hook returned invalid output: {reason}")
            }
            Self::Failed(reason) => write!(f, "plugin hook failed: {reason}"),
        }
    }
}

impl std::error::Error for HookError {}

/// A PgDog plugin.
///
/// # Concurrency
///
/// PgDog serves clients on many threads and calls hooks from all of them at
/// once. For one client, `statement`, `function_call`, `mask_rows` and
/// `redact_error` are called one at a time, in the order of the client's
/// messages and the server's responses. `catalog` and `reload` can run at any
/// time, concurrently with the other hooks.
///
/// Plugins must make their own state safe to share across threads. Hooks run
/// on PgDog's async workers, so they must not block, except `mask_rows` for
/// masks declared blocking with [`crate::ColumnMask::blocking`].
///
/// # Panics
///
/// Every hook catches panics inside the plugin. A panic fails closed: the
/// statement is denied, the result fails, or the error is reduced to its
/// severity and SQLSTATE.
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

    /// Decide what a statement may do: allow, rewrite or deny it. Called with
    /// the SQL of every simple `Query` and extended protocol `Parse`.
    /// Requires [`Capabilities::STATEMENT`]. See [`crate::statement`].
    fn statement(_session: &Session<'_>, _sql: &str) -> Verdict {
        Verdict::Allow
    }

    #[doc(hidden)]
    extern "C-unwind" fn statement_raw(session: &Session<'_>, sql: PdStr<'_>) -> VerdictOutput {
        // Panics are caught here, inside the plugin, so the panic
        // payload is freed by the allocator that created it.
        catch_unwind(AssertUnwindSafe(|| Self::statement(session, &sql).into()))
            .unwrap_or_else(|_| VerdictOutput::panicked())
    }

    /// Decide whether a fast-path function call may run. Fast-path calls carry
    /// no SQL, only the function's OID. Requires [`Capabilities::STATEMENT`].
    fn function_call(_session: &Session<'_>, _function: u32) -> Access {
        Access::Allow
    }

    #[doc(hidden)]
    extern "C-unwind" fn function_call_raw(session: &Session<'_>, function: u32) -> VerdictOutput {
        catch_unwind(AssertUnwindSafe(|| {
            Self::function_call(session, function).into()
        }))
        .unwrap_or_else(|_| VerdictOutput::panicked())
    }

    #[doc(hidden)]
    extern "C-unwind" fn free_verdict(output: &mut VerdictOutput) {
        output.free()
    }

    /// Generation of the plugin's verdicts. Change it whenever verdicts given
    /// earlier may no longer hold, e.g. after loading new configuration or a new
    /// catalog. PgDog then checks prepared statements again at their next `Bind`.
    ///
    /// Called at every `Bind` of a prepared statement, so it must be cheap.
    fn generation() -> u64 {
        0
    }

    #[doc(hidden)]
    extern "C-unwind" fn generation_raw() -> u64 {
        // A panic forces a re-check.
        catch_unwind(Self::generation).unwrap_or(u64::MAX)
    }

    /// Mask a batch of result rows. Write exactly one value into `out` for
    /// each value in `batch`, column by column. Requires [`Capabilities::MASK`].
    /// See [`crate::mask`].
    fn mask_rows(_batch: &MaskBatch<'_>, _out: &mut MaskOutput) -> Result<(), MaskError> {
        Err(MaskError::new("mask_rows isn't implemented"))
    }

    #[doc(hidden)]
    extern "C-unwind" fn mask_rows_raw(batch: &MaskBatch<'_>) -> MaskResult {
        catch_unwind(AssertUnwindSafe(|| {
            let values = batch.columns().len() * batch.rows as usize;
            let mut out = MaskOutput::with_capacity(values, values * 16);
            Self::mask_rows(batch, &mut out).map(|_| out).into()
        }))
        .unwrap_or_else(|_| MaskResult::panicked())
    }

    #[doc(hidden)]
    extern "C-unwind" fn free_mask_result(output: &mut MaskResult) {
        output.free()
    }

    /// Redact an error or notice Postgres sent to the client. Called for all of
    /// them, whatever statement caused them. Requires [`Capabilities::ERRORS`].
    /// See [`crate::redact`].
    fn redact_error(_session: &Session<'_>, _error: &ErrorFields<'_>) -> Redaction {
        Redaction::Keep
    }

    #[doc(hidden)]
    extern "C-unwind" fn redact_error_raw(
        session: &Session<'_>,
        error: &ErrorFields<'_>,
    ) -> RedactionOutput {
        catch_unwind(AssertUnwindSafe(|| {
            Self::redact_error(session, error).into()
        }))
        .unwrap_or_else(|_| RedactionOutput::panicked())
    }

    #[doc(hidden)]
    extern "C-unwind" fn free_redaction(output: &mut RedactionOutput) {
        output.free()
    }

    /// Optional catalog parts this plugin needs. Requires [`Capabilities::CATALOG`].
    fn catalog_parts() -> CatalogParts {
        CatalogParts::NONE
    }

    #[doc(hidden)]
    extern "C-unwind" fn catalog_parts_raw() -> u32 {
        catch_unwind(Self::catalog_parts)
            .unwrap_or(CatalogParts::NONE)
            .bits()
    }

    /// Receive the catalog of a database. Requires [`Capabilities::CATALOG`].
    /// See [`crate::catalog`].
    ///
    /// If loading fails, PgDog retries and sends nothing until it succeeds:
    /// plugins keep their previous catalog, and must decide for themselves what
    /// to do for a database they have no catalog for yet (a security plugin
    /// should fail closed).
    fn catalog(_database: &str, _catalog: &Catalog) {}

    #[doc(hidden)]
    #[allow(improper_ctypes_definitions)]
    extern "C-unwind" fn catalog_raw(database: PdStr<'_>, catalog: &Catalog) {
        let _ = catch_unwind(AssertUnwindSafe(|| Self::catalog(&database, catalog)));
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

/// Masked values of a batch, borrowed from the plugin until dropped.
pub struct MaskedValues<'a> {
    vtable: &'a PluginVtable,
    result: MaskResult,
    /// Start of each value in `result.data()`.
    offsets: Vec<usize>,
}

impl MaskedValues<'_> {
    /// The value at `index`, column by column. `None` is NULL.
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        let len = *self.result.lengths().get(index)?;
        let start = self.offsets[index];
        (len >= 0).then(|| &self.result.data()[start..start + len as usize])
    }

    /// Number of values.
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// No values.
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }
}

impl Drop for MaskedValues<'_> {
    fn drop(&mut self) {
        (self.vtable.free_mask_result)(&mut self.result)
    }
}

impl fmt::Debug for MaskedValues<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries((0..self.len()).map(|index| self.get(index)))
            .finish()
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
            function_call: T::function_call_raw,
            free_verdict: T::free_verdict,
            generation: T::generation_raw,
            mask_rows: T::mask_rows_raw,
            free_mask_result: T::free_mask_result,
            redact_error: T::redact_error_raw,
            free_redaction: T::free_redaction,
            catalog_parts: T::catalog_parts_raw,
            catalog: T::catalog_raw,
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
    pub fn statement(&self, session: &Session<'_>, sql: &str) -> Result<Verdict, HookError> {
        let mut output = (self.statement)(session, sql.into());
        let verdict = Self::decode_verdict(&output);
        (self.free_verdict)(&mut output);
        verdict
    }

    /// Run the fast-path function call hook.
    pub fn function_call(&self, session: &Session<'_>, function: u32) -> Result<Access, HookError> {
        let mut output = (self.function_call)(session, function);
        let verdict = Self::decode_verdict(&output);
        (self.free_verdict)(&mut output);
        match verdict? {
            Verdict::Allow => Ok(Access::Allow),
            Verdict::Deny(deny) => Ok(Access::Deny(deny)),
            Verdict::Rewrite { .. } => Err(HookError::InvalidOutput(
                "a function call can't be rewritten",
            )),
        }
    }

    fn decode_verdict(output: &VerdictOutput) -> Result<Verdict, HookError> {
        match output.action() {
            VERDICT_ALLOW => Ok(Verdict::Allow),
            VERDICT_REWRITE => {
                let sql = output
                    .sql()
                    .as_str()
                    .ok_or(HookError::InvalidOutput("rewritten SQL is not valid UTF-8"))?;
                Ok(Verdict::Rewrite {
                    sql: sql.to_owned(),
                    columns: output.columns().to_vec(),
                })
            }
            VERDICT_DENY => Ok(Verdict::Deny(output.denied())),
            VERDICT_PANIC => Err(HookError::Panicked),
            _ => Err(HookError::InvalidOutput("unknown verdict")),
        }
    }

    /// Generation of the plugin's verdicts.
    pub fn generation(&self) -> u64 {
        (self.generation)()
    }

    /// Run the mask hook. The masked values stay in plugin memory until the
    /// returned [`MaskedValues`] is dropped.
    pub fn mask_rows(&self, batch: &MaskBatch<'_>) -> Result<MaskedValues<'_>, HookError> {
        let result = (self.mask_rows)(batch);
        let mut values = MaskedValues {
            vtable: self,
            result,
            offsets: vec![],
        };

        match values.result.status() {
            MASK_OK => (),
            MASK_ERROR => return Err(HookError::Failed(values.result.message())),
            MASK_PANIC => return Err(HookError::Panicked),
            _ => return Err(HookError::InvalidOutput("unknown mask status")),
        }

        let expected = batch.columns().len() * batch.rows as usize;
        let lengths = values.result.lengths();
        if lengths.len() != expected {
            return Err(HookError::InvalidOutput(
                "mask_rows didn't return one value per input value",
            ));
        }

        let mut offsets = Vec::with_capacity(expected);
        let mut offset = 0;
        for len in lengths {
            offsets.push(offset);
            offset += (*len).max(0) as usize;
        }
        if offset != values.result.data().len() {
            return Err(HookError::InvalidOutput("mask_rows output is inconsistent"));
        }
        values.offsets = offsets;

        Ok(values)
    }

    /// Run the error redaction hook. Returns the replacement fields, if any.
    pub fn redact_error(
        &self,
        session: &Session<'_>,
        error: &ErrorFields<'_>,
    ) -> Result<Option<Vec<(u8, String)>>, HookError> {
        let mut output = (self.redact_error)(session, error);
        let result = match output.action() {
            REDACT_KEEP => Ok(None),
            REDACT_REPLACE => output
                .fields()
                .map(Some)
                .ok_or(HookError::InvalidOutput("malformed error fields")),
            REDACT_PANIC => Err(HookError::Panicked),
            _ => Err(HookError::InvalidOutput("unknown redaction")),
        };
        (self.free_redaction)(&mut output);
        result
    }

    /// Catalog parts the plugin needs.
    pub fn catalog_parts(&self) -> CatalogParts {
        CatalogParts::from_bits((self.catalog_parts)())
    }

    /// Send a database's catalog.
    pub fn catalog(&self, database: &str, catalog: &catalog::Catalog) {
        (self.catalog)(database.into(), catalog)
    }

    /// Reload plugin configuration.
    pub fn reload(&self) -> bool {
        (self.reload)()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        ColumnMask, Deny, MaskColumn, MaskId, SqlState, Value,
        redact::{ErrorField, field},
    };

    struct TestPlugin;

    impl Plugin for TestPlugin {
        extern "C-unwind" fn version() -> PdStr<'static> {
            "0".into()
        }

        fn capabilities() -> Capabilities {
            Capabilities::STATEMENT | Capabilities::MASK | Capabilities::ERRORS
        }

        fn statement(session: &Session<'_>, sql: &str) -> Verdict {
            match sql {
                "panic" => panic!("statement hook panicked"),
                "deny" => Verdict::Deny(Deny::insufficient_privilege("denied")),
                "mask" => Verdict::Rewrite {
                    sql: "SELECT 1".into(),
                    columns: vec![ColumnMask::new(1, MaskId(9))],
                },
                sql => Verdict::rewrite(format!("{sql} /* {} */", &*session.user)),
            }
        }

        fn function_call(_session: &Session<'_>, function: u32) -> Access {
            match function {
                0 => Access::Deny(Deny::new(SqlState::FEATURE_NOT_SUPPORTED, "no")),
                _ => Access::Allow,
            }
        }

        fn generation() -> u64 {
            7
        }

        fn mask_rows(batch: &MaskBatch<'_>, out: &mut MaskOutput) -> Result<(), MaskError> {
            for column in batch.columns() {
                for value in column.values() {
                    match value {
                        Some(b"panic") => panic!("mask hook panicked"),
                        Some(b"fail") => return Err(MaskError::new("can't mask")),
                        Some(b"short") => return Ok(()),
                        Some(value) => out.push(Some(&value.to_ascii_uppercase())),
                        None => out.push(None),
                    }
                }
            }
            Ok(())
        }

        fn redact_error(_session: &Session<'_>, error: &ErrorFields<'_>) -> Redaction {
            match error.message() {
                Some("panic") => panic!("redact hook panicked"),
                Some("keep") => Redaction::Keep,
                _ => Redaction::Replace(error.without(&[field::DETAIL])),
            }
        }
    }

    static VTABLE: PluginVtable = PluginVtable::from_plugin::<TestPlugin>();

    fn session() -> Session<'static> {
        Session {
            user: "alice".into(),
            ..Default::default()
        }
    }

    fn mask(values: &[Option<&[u8]>]) -> Result<Vec<Option<Vec<u8>>>, HookError> {
        let values: Vec<_> = values.iter().map(|value| Value::new(*value)).collect();
        let columns = [MaskColumn::new(0, MaskId(1), &values)];
        let batch = MaskBatch::new(values.len() as u32, &columns);
        let masked = VTABLE.mask_rows(&batch)?;
        Ok((0..masked.len())
            .map(|index| masked.get(index).map(|value| value.to_vec()))
            .collect())
    }

    #[test]
    fn test_capabilities() {
        assert_eq!(
            VTABLE.capabilities(),
            Capabilities::STATEMENT | Capabilities::MASK | Capabilities::ERRORS
        );
        assert_eq!(VTABLE.generation(), 7);
        assert_eq!(VTABLE.catalog_parts(), CatalogParts::NONE);
    }

    #[test]
    fn test_statement_hook() {
        let session = session();
        assert_eq!(
            VTABLE.statement(&session, "SELECT 1").unwrap(),
            Verdict::rewrite("SELECT 1 /* alice */")
        );
        assert_eq!(
            VTABLE.statement(&session, "deny").unwrap(),
            Verdict::Deny(Deny::insufficient_privilege("denied"))
        );
        assert_eq!(
            VTABLE.statement(&session, "mask").unwrap(),
            Verdict::Rewrite {
                sql: "SELECT 1".into(),
                columns: vec![ColumnMask::new(1, MaskId(9))],
            }
        );
        assert_eq!(
            VTABLE.statement(&session, "panic"),
            Err(HookError::Panicked)
        );
    }

    #[test]
    fn test_function_call_hook() {
        let session = session();
        assert_eq!(VTABLE.function_call(&session, 1).unwrap(), Access::Allow);
        assert_eq!(
            VTABLE.function_call(&session, 0).unwrap(),
            Access::Deny(Deny::new(SqlState::FEATURE_NOT_SUPPORTED, "no"))
        );
    }

    #[test]
    fn test_mask_hook() {
        assert_eq!(
            mask(&[Some(b"abc"), None, Some(b"")]).unwrap(),
            [Some(b"ABC".to_vec()), None, Some(vec![])]
        );
        assert_eq!(
            mask(&[Some(b"fail")]).unwrap_err(),
            HookError::Failed("can't mask".into())
        );
        assert_eq!(mask(&[Some(b"panic")]).unwrap_err(), HookError::Panicked);
        assert!(matches!(
            mask(&[Some(b"ok"), Some(b"short")]).unwrap_err(),
            HookError::InvalidOutput(_)
        ));
    }

    #[test]
    fn test_redact_hook() {
        let error = |message: &'static str| {
            vec![
                ErrorField {
                    code: field::SQLSTATE,
                    value: "23505".into(),
                },
                ErrorField {
                    code: field::MESSAGE,
                    value: message.into(),
                },
                ErrorField {
                    code: field::DETAIL,
                    value: "secret".into(),
                },
            ]
        };
        let session = session();

        let fields = error("duplicate");
        assert_eq!(
            VTABLE
                .redact_error(&session, &ErrorFields::new(false, &fields))
                .unwrap(),
            Some(vec![
                (field::SQLSTATE, "23505".into()),
                (field::MESSAGE, "duplicate".into())
            ])
        );
        let fields = error("keep");
        assert_eq!(
            VTABLE
                .redact_error(&session, &ErrorFields::new(false, &fields))
                .unwrap(),
            None
        );
        let fields = error("panic");
        assert_eq!(
            VTABLE.redact_error(&session, &ErrorFields::new(false, &fields)),
            Err(HookError::Panicked)
        );
    }
}
