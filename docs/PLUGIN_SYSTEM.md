# PgDog Plugin System - Overview & Essentials

This document summarizes PgDog's plugin system: architecture, execution flow, integration points, and key development guidelines. For full details, see the referenced source files.

PgDog plugins are Rust shared libraries loaded at runtime. They can route queries, allow, rewrite or deny statements before PgDog parses them, mask columns of the results, redact the errors Postgres returns, and receive the database catalog. FFI is used for safe communication, with strict version checks for safety.

This document describes plugin API 0.8 (`pgdog-plugin` 0.8). The hooks other than `route` are covered in [Hooks and capabilities](#hooks-and-capabilities).

## Architecture

PgDog's plugin system consists of four main crates:

- **pgdog-plugin**: User-facing plugin interface ([pgdog-plugin/](../pgdog-plugin)). Provides safe Rust APIs, FFI symbol management, and version checks.
- **pgdog-macros**: Procedural macros for generating required FFI functions (`plugin!`, `init`, `route`, `fini`). See [pgdog-macros/src/lib.rs](../pgdog-macros/src/lib.rs).
- **pgdog-plugin-build**: Build-time helpers for version pinning. See [pgdog-plugin-build/src/lib.rs](../pgdog-plugin-build/src/lib.rs).
- **pgdog**: Plugin loader and runtime manager. See [pgdog/src/plugin/mod.rs](../pgdog/src/plugin/mod.rs).

## Execution Workflow

**Startup:**

### Phase 1: Startup & Plugin Loading

```
PgDog starts
	↓
Read configuration (pgdog.toml)
	↓
load_from_config()
	├─ Extract plugin names from config.plugins[]
	└─ Call load()
		↓
		For each plugin:
		  ├─ Plugin::library(name)
		  │  └─ Use libloading to dlopen() shared library
		  │
		  ├─ Plugin::load(name, &lib)
		  │  ├─ Resolve pgdog_init symbol
		  │  ├─ Resolve pgdog_fini symbol
		  │  ├─ Resolve pgdog_route symbol
		  │  ├─ Resolve pgdog_rustc_version symbol
		  │  └─ Resolve pgdog_plugin_version symbol
		  │
		  ├─ VERSION CHECKS
		  │  ├─ Get PgDog's rustc version via comp::rustc_version()
		  │  ├─ Get plugin's rustc version via pgdog_rustc_version()
		  │  ├─ If mismatch: WARN and SKIP plugin
		  │  └─ If match: Continue
		  │
		  ├─ plugin.init()
		  │  └─ Call pgdog_init() if defined (synchronous)
		  │
		  └─ Log: "loaded {name} plugin (v{version}) [timing]ms"

Store plugins in static PLUGINS (OnceCell)
	↓
PgDog ready to serve connections
```

**Location**: [pgdog/src/plugin/mod.rs](../pgdog/src/plugin/mod.rs) lines 15-85

### Phase 2: Query Routing (Per Query)

```
Client sends query
	↓
PostgreSQL Frontend Parser
	├─ Tokenize and parse query
	└─ Generate AST
	   ↓
Query Router: QueryParser::parse()
	├─ Create RouterContext (shards, replicas, etc.)
	├─ Generate PdRouterContext for plugins
	│  └─ context.plugin_context(ast, bind_params)
	│     ├─ Pack bind parameters into PdParameters
	│     └─ Include cluster metadata (shards, replicas, transaction state)
	│
	├─ Call QueryParser::plugins()
	│  └─ For each loaded plugin:
	│     ├─ plugin.route(PdRouterContext)
	│     │  └─ Call pgdog_route(context, &mut output)
	│     │
	│     ├─ Parse returned PdRoute:
	│     │  ├─ Shard::Direct(n) → override shard to n
	│     │  ├─ Shard::All → broadcast to all shards
	│     │  ├─ Shard::Unknown → use default routing
	│     │  ├─ Shard::Blocked → block query
	│     │  ├─ ReadWrite::Read → send to replica
	│     │  ├─ ReadWrite::Write → send to primary
	│     │  └─ ReadWrite::Unknown → use default logic
	│     │
	│     ├─ Record plugin override (if any)
	│     └─ If route provided: BREAK (first plugin wins)
	│
	├─ Apply plugin overrides to routing decision
	└─ Continue with default routing logic
	   ↓
Select target shard/replica
	↓
Execute on database
```

**Locations**:
	- Context creation: [pgdog/src/frontend/router/parser/context.rs](../pgdog/src/frontend/router/parser/context.rs) lines 107-140
	- Plugin execution: [pgdog/src/frontend/router/parser/query/plugins.rs](../pgdog/src/frontend/router/parser/query/plugins.rs) lines 20-105

### Phase 3: Shutdown

```
PgDog receives shutdown signal
	↓
Call plugin::shutdown()
	└─ For each loaded plugin:
	   ├─ plugin.fini()
	   │  └─ Call pgdog_fini() if defined (synchronous)
	   └─ Log: "plugin {name} shutdown"
	↓
Clean up remaining resources
	↓
Process exits
```

**Location**: `pgdog/src/plugin/mod.rs` lines 77-83

## Hooks and capabilities

A plugin declares which hooks it implements by returning a set of [`Capabilities`](../pgdog-plugin/src/capabilities.rs) from `Plugin::capabilities()`. PgDog only calls the hooks a plugin asked for, so a routing-only plugin pays nothing for the others. The default is `Capabilities::ROUTE`, which is how plugins behaved before capabilities existed.

| Capability | Hooks | Called |
|---|---|---|
| `ROUTE` | `route(Context) -> Route` | For every statement PgDog routes, after parsing. |
| `STATEMENT` | `statement(&Session, sql) -> Verdict`, `function_call(&Session, oid) -> Access`, `generation() -> u64` | For every `Query` and `Parse`, and every fast-path function call, before PgDog parses, rewrites or routes the statement. In this version, at most one loaded plugin can have it. |
| `MASK` | `mask_rows(&MaskBatch, &mut MaskOutput)` | For batches of result rows with columns a verdict asked to mask. In this version, requires `STATEMENT`. |
| `ERRORS` | `redact_error(&Session, &ErrorFields) -> Redaction` | For every `ErrorResponse` and `NoticeResponse` Postgres sends to a client. |
| `CATALOG` | `catalog_parts() -> CatalogParts`, `catalog(database, &Catalog)` | When a database's schema finishes loading and changed. Makes PgDog load the schema even if `load_schema` would skip it. |

Every plugin also has `reload() -> bool`, called when PgDog reloads its own configuration (`SIGHUP`, or the admin `RELOAD` and `FORCE_RELOAD` commands). Returning `false` means the new configuration is invalid; the plugin should keep its previous one, and PgDog logs a warning.

Capability bits PgDog doesn't know are kept, not dropped, so an older host never misreads a newer plugin.

### Sessions

Hooks that run for a client get a [`Session`](../pgdog-plugin/src/session.rs): the user and database the client authenticated as, the identity from its verified TLS certificate, and its `search_path`. These are fixed for the session, except `search_path`; `SET ROLE` and setting `user` don't change them. `Session::client` holds what the client says about itself (`application_name` and its address), which is not authenticated and must not be used for access decisions.

### Statement hook

The plugin with `STATEMENT` is called for every simple `Query` and extended protocol `Parse` with the SQL to check (in this version it is the client's SQL; a later version may pass SQL an earlier plugin already rewrote), and returns a [`Verdict`](../pgdog-plugin/src/statement.rs):

- `Verdict::Allow`: send the statement unchanged;
- `Verdict::Rewrite { sql, columns, redact_errors }` (built with `Verdict::rewrite`, `Verdict::rewrite_masked` and `Verdict::redact_errors`): send `sql` instead, mask `columns` of its results (see [Masks](#masks)), and, if `redact_errors` is set, redact the statement's errors (see [Statement errors](#statement-errors)). `sql` can be the original statement, to only mask or redact. Everything downstream, including the prepared statements cache, the AST cache, the router and sharding, sees the new SQL;
- `Verdict::Deny(Deny { sqlstate, message })`: reject the statement with an `ErrorResponse`.

Fast-path function calls carry no SQL, only the function's OID; `function_call` allows or denies them.

Denied statements fail like statements Postgres rejects: the transaction, if any, is aborted (a later `COMMIT` reports `ROLLBACK`), and in the extended protocol everything up to the next `Sync` is discarded. A denied statement never reaches a server. A plugin that panics or returns invalid output denies the statement (`XX000`): the hook fails closed.

Verdicts must be deterministic: they depend only on the session and the SQL, until the plugin's `generation()` changes. PgDog relies on this for prepared statements:

- A statement is checked when it's prepared, and again at `Bind` only if the plugin's generation or the session's `search_path` changed since. `generation()` is called at every `Bind`, so it must be cheap.
- If the new verdict sends different SQL (e.g., the plugin reloaded its configuration), PgDog prepares the statement again with the new SQL, so long-lived prepared statements follow plugin changes. If it can't (the unnamed statement, or prepared statements aren't handled by PgDog), the `Bind` fails with `26000` and the client must prepare the statement again.
- A rewrite of a `Parse` must keep the statement's bind parameters: PgDog denies it (`XX000`) if its highest parameter number differs from the original's.

In this version, at most one loaded plugin can have `STATEMENT`: a rewrite changes the columns another plugin's masks would refer to, so verdicts of several plugins aren't combined. A second one fails to load.

The statement hook isn't called for admin database commands, and multi-statement queries PgDog splits internally are checked once, as the client sent them.

See [pgdog-plugin/src/statement.rs](../pgdog-plugin/src/statement.rs) and [pgdog/src/frontend/client/query_engine/statement_plugins/](../pgdog/src/frontend/client/query_engine/statement_plugins/).

### Masks

A rewrite can name result columns to mask with [`ColumnMask`](../pgdog-plugin/src/statement.rs): a column position, which result set it's in (only multi-statement queries have more than one: it's the statement's position in the query, counting every statement, including `BEGIN` or `SET`, even when PgDog answers them itself), a plugin-defined `MaskId`, the column's type OID, and whether the mask may block. Use masks for values computed in code rather than SQL, e.g. a keyed hash whose key must not appear in the statement, tokens from a vault, or noise added to a number. The plugin needs the `MASK` capability, which in this version requires `STATEMENT`, since only the statement plugin's verdicts name columns to mask.

`ColumnMask::null(column)` replaces a column's values with `NULL` without calling the plugin, whatever the column's type, e.g. for values computed from data the user can't see.

Masks keep the column's type: they get values of the declared type and return values of the same type. Values are in the format the client asked for, text for simple queries and what the client's `Bind` requested for the extended protocol; each `MaskColumn` carries its format, and masks return values in it. `pgdog_plugin::types` decodes and encodes common types in both formats. The type OID is the one Postgres reports in `RowDescription` (the base type, for domains; the catalog's `Column::type_oid`). PgDog checks it when it sees the statement's `RowDescription`, and fails the statement if it differs.

PgDog collects a statement's `DataRow`s in batches and calls `mask_rows` once per batch, with the values of the masked columns only, column by column. The plugin writes one value per input value into `MaskOutput`, in the same order. A batch is the rows already received from the server, up to 256 rows or 1 MiB, so batching never makes the client wait for rows that haven't arrived. Rows are forwarded in order, after multi-shard results have been merged, sorted and aggregated. Batches with a blocking mask run on Tokio's blocking thread pool.

Masks apply to what the verdict was given for:

- a `Query`: its results, until its `ReadyForQuery`;
- a `Parse`: `Describe` of the prepared statement, and every portal bound to it, until it's closed or replaced. Every `Execute` of a portal, including resumed ones, is masked, even when the portal is closed in the same request.

If masking fails (the plugin returns an error, panics, or returns the wrong number of values), PgDog cancels the query and closes the client connection with a `FATAL` error, since some rows may already have been sent.

See [pgdog-plugin/src/mask.rs](../pgdog-plugin/src/mask.rs).

### Error redaction

Postgres errors can contain the data a statement touched: a unique violation's `Key (ssn)=(123-45-6789) already exists`, a check constraint's `Failing row contains (...)`, or a cast error's `invalid input syntax for type integer: "123-45-6789"`. Plugins with `ERRORS` see every `ErrorResponse` and `NoticeResponse` Postgres sends to a client, whatever statement caused it, as a list of fields, and can replace them. Plugins run in config order, each seeing what the previous one returned.

The severity and SQLSTATE always reach the client unchanged, so clients keep handling errors correctly. A plugin that panics or returns invalid output fails closed: the error is reduced to its severity, SQLSTATE and a generic message.

See [pgdog-plugin/src/redact.rs](../pgdog-plugin/src/redact.rs).

### Statement errors

A rewrite with `redact_errors` asks PgDog to replace the message of every `ErrorResponse` and `NoticeResponse` the statement causes with a fixed one, keeping the severity, SQLSTATE, and the position and location fields. It applies to what masks apply to: a `Query` until its `ReadyForQuery`, and a `Parse`, its `Describe`s and the portals bound to it. Use it for statements that compute on values the user can't see, whose errors could contain them. The plugin needs the `MASK` capability. Statement redaction runs after `redact_error`, replacing the message it returned.

### Concurrency

PgDog serves clients on many threads and calls hooks from all of them at once. For one client, `statement`, `function_call`, `mask_rows` and `redact_error` are called one at a time, in the order of the client's messages and the server's responses. `catalog` and `reload` can run at any time, concurrently with the other hooks.

Plugins must make their own state safe to share across threads. Hooks run on PgDog's async workers, so they must not block, except `mask_rows` for masks declared blocking.

The authoritative version of these contracts is the documentation of the `Plugin` trait in [pgdog-plugin/src/plugin.rs](../pgdog-plugin/src/plugin.rs).

### Catalog

Plugins with `CATALOG` receive each database's [`Catalog`](../pgdog-plugin/src/catalog.rs): its relations and their columns, and the optional parts plugins ask for with `catalog_parts()`:

| Part | Contents |
|---|---|
| `COLUMNS` | Every column from `pg_attribute`, including those the role PgDog loads the schema with can't read, with type names and OIDs, comments and security labels. |
| `VIEWS` | Definitions and options of views and materialized views. |
| `FUNCTIONS` | Functions and procedures outside `pg_catalog`, and the names of the functions in `pg_catalog`. |
| `OPERATORS` | Operators outside `pg_catalog`. |

PgDog loads the union of what loaded plugins ask for, so plugins should check `Catalog::parts`. Names in view definitions, function bodies and type names are schema-qualified, independent of any `search_path`.

`Catalog` is a Rust type defined in `pgdog-plugin`, passed by reference and only valid during the call. That's sound across the plugin boundary because plugins are built with the same compiler and `pgdog-plugin` version as PgDog, like the AST passed to `route`.

A database's catalog is sent when its schema finishes loading and differs from the last one sent for it: at startup, after configuration reloads, and after DDL when `reload_schema_on_ddl` is enabled. If loading fails, PgDog retries and sends nothing until it succeeds: plugins keep their previous catalog, and must decide for themselves what to do for a database they have no catalog for yet. A security plugin should fail closed. A plugin whose verdicts depend on the catalog should change its `generation()` when it receives a new one.

### Required plugins

By default, PgDog logs a warning and starts without a plugin that fails to load. With `required = true` in its `[[plugins]]` entry, PgDog doesn't start if the plugin fails to load for any reason: the shared library is missing, it was built with a different compiler or plugin API version, it rejected its configuration, or another plugin already implements the statement hook.

```toml
[[plugins]]
name = "my_security_plugin"
config = "/etc/pgdog/my_security_plugin.toml"
required = true
```

Use this for plugins that enforce security policies, so PgDog never serves traffic without them.

## Plugin Development

1. **Create a Rust library** with `crate-type = ["cdylib"]` in `Cargo.toml`.
2. **Add dependencies:** `pgdog-plugin` and `pgdog-plugin-build`.
3. **Use macros:** Annotate your functions with `plugin!`, `init`, `route`, and `fini` macros. See `pgdog-macros` for details.
4. **Build:** `cargo build --release` produces a `.so`/`.dylib` file.
5. **Deploy:** Place the shared library in a system path, set `LD_LIBRARY_PATH`, or reference it in `pgdog.toml`.
6. **Verify:** Check PgDog logs for successful plugin loading.

See the [plugins/pgdog-example-plugin/](../plugins/pgdog-example-plugin/) for a full example.

## Integration Points

- **Context creation:** See [pgdog/src/frontend/router/parser/context.rs](../pgdog/src/frontend/router/parser/context.rs) for how plugin context is built.
- **Plugin execution:** See [pgdog/src/frontend/router/parser/query/plugins.rs](../pgdog/src/frontend/router/parser/query/plugins.rs) for plugin invocation logic.
- **Statement, mask and error hooks:** See [pgdog/src/frontend/client/query_engine/statement_plugins/](../pgdog/src/frontend/client/query_engine/statement_plugins/).
- **Catalog and reload:** See [pgdog/src/plugin/mod.rs](../pgdog/src/plugin/mod.rs) and [pgdog/src/plugin/catalog.rs](../pgdog/src/plugin/catalog.rs).
- **Configuration:** Plugins are listed in `pgdog.toml` (see [pgdog-config/src/users.rs](../pgdog-config/src/users.rs)). The `name` field can be a library name, relative, or absolute path. `config` is an optional path to a plugin-specific configuration file, and `required` makes PgDog refuse to start without the plugin.

## Safety & Compatibility

- **Rust version:** Plugins must be built with the exact same Rust compiler version as PgDog. Mismatches are skipped at load time.
- **pg_raw_parse version:** Plugins must use the same `pg_raw_parse` version as PgDog. (The compiler will automatically enforce this)
- **FFI safety:** All FFI types are `#[repr(C)]` and memory is managed to avoid UB. See [pgdog-plugin/src/bindings.rs](../pgdog-plugin/src/bindings.rs) and [pgdog-plugin/src/parameters.rs](../pgdog-plugin/src/parameters.rs).

## FFI & ABI Notes

- FFI boundary uses `#[repr(C)]` types for ABI safety. See [pgdog-plugin/src/bindings.rs](../pgdog-plugin/src/bindings.rs).
- Plugins reconstruct Rust types from FFI pointers; exact Rust and dependency versions are required.
- The FFI boundary is fragile: plugin and host must use the same Rust and dependency versions, and memory layout must match exactly. Opaque pointers and container reinterpretation (e.g., `Vec::from_raw_parts`) are used, which can break with even minor version or feature changes. See [pgdog-plugin/src/parameters.rs](../pgdog-plugin/src/parameters.rs) and code comments for details.
- Ownership and lifetime: host must keep memory valid for the FFI call; plugins must not free or mutate host-owned memory unless explicitly allowed. Panics must not unwind across the FFI boundary.

### Maintainability Issues & Pain Points

- **Opaque pointers hide implementation details:** Pointer fields (e.g., `void*`) obscure the true layout and ownership, so important rules are only in documentation, not enforced by the type system.
- **Fragile container reinterpretation:** Using `Vec::from_raw_parts` and similar tricks relies on *identical* Rust versions, crate versions, and feature flags. Any mismatch can cause undefined behavior or memory corruption.
- **Transitive dependency coupling:** Types like the `pg_raw_parse` AST or `bytes::Bytes` add hidden constraints on plugin dependencies, making upgrades and changes risky.
- **Hard to evolve:** Internal representation changes (e.g., switching `Bytes` → `Vec<u8>`, changing struct layouts) are breaking and require all plugins to be rebuilt in lockstep.
- **Debugging cost:** ABI or UB problems are subtle, often nondeterministic, and hard to diagnose or reproduce.
- **No ABI versioning:** There is no formal ABI version negotiation; any change in the host or plugin can silently break compatibility.

See the original design notes and migration checklist in the source for more details and future directions.
- Future improvements may include a stable C ABI, serialized ASTs, and ABI versioning. See code comments for migration plans.

## Plugin Context & Output

- The plugin `Context` provides access to cluster info, query AST, parameters, and transaction state. See [pgdog-plugin/src/context.rs](../pgdog-plugin/src/context.rs).
- Plugins return a `Route` to control query routing (unknown, block, direct, all, read/write). See [pgdog-plugin/src/plugin.rs](../pgdog-plugin/src/plugin.rs).

## Performance & Best Practices

- Keep `init()` fast; it blocks startup.
- All hooks run on the async executor; avoid blocking. See [Concurrency](#concurrency).
- Plugins are checked in order; first to return a route wins.
- Plugins must not panic. Panics are caught inside the plugin and fail closed: a panicking `statement` hook denies the statement, a panicking `mask_rows` closes the client connection, and a panicking `redact_error` reduces the error to its severity and SQLSTATE.
- Only declare the capabilities you implement: the statement hook is on the path of every statement, and `ERRORS` on the path of every error.
- Mask in SQL where you can: a rewrite costs nothing per row, while `mask_rows` runs for every batch of rows.

## Debugging

- Check PgDog logs for plugin load status and version mismatches.
- Use `ldd`/`otool` to verify library paths and symbols if plugins fail to load.

## Example

See [plugins/pgdog-example-plugin/](../plugins/pgdog-example-plugin/) for a working plugin example.

## Testing

### Integration Tests

**Location**: [integration/plugins/](../integration/plugins/)

The `integration/plugins` directory contains a small test harness and several test-plugin crates used to exercise plugin loading, FFI parameter passing, and API compatibility checks. Key files and behavior:

- **Test harness**: [integration/plugins/extended_spec.rb](../integration/plugins/extended_spec.rb) — an RSpec script that opens multiple connections to PgDog and issues prepared statements (parameterized queries). It verifies query results and that a plugin marker file was created to confirm the plugin's `route()` was invoked.
- **Hooks**: [integration/plugins/hooks_spec.rb](../integration/plugins/hooks_spec.rb) — exercises the statement, mask and error hooks of `test-plugin-compatible` through the compiled shared library: rewrites (simple, extended and prepared), denials (including a denied statement aborting its transaction), masks (simple, prepared, binary format, and a large result in batches), and error redaction.
- **Runner**: [integration/plugins/run.sh](../integration/plugins/run.sh) — builds the test plugins, sets `LD_LIBRARY_PATH` to include the test build outputs, starts PgDog using the integration helpers, runs the RSpec test, and stops PgDog.
- **Test plugins**: [integration/plugins/test-plugins/](../integration/plugins/test-plugins)
	- `test-plugin-compatible` — built with the same `pgdog-plugin` ABI; its `route()` calls `assert_context_compatible!()` and writes `route-called.test` the first time it is invoked. The RSpec test checks for this file to confirm the plugin was executed and parameters were seen. It also implements the statement, mask and error hooks, acting only on statements and errors containing its markers (`pgdog_plugin_rewrite`, `pgdog_plugin_block`, `pgdog_plugin_uppercase`, `pgdog_plugin_secret`).
	- `test-plugin-main` — validates the main-branch plugin API compatibility by calling `assert_context_compatible!()` on the received `Context` (detects breaking API changes between host and plugin crates).
	- `test-plugin-outdated` — intended to simulate an outdated `pgdog-plugin` dependency so the loader should skip it; currently this crate contains a TODO and does not actively panic if loaded, so it serves as a placeholder for the "outdated plugin" scenario.

What the integration test exercises:
- Parameterized queries travel through the frontend parser, router context creation, and across the FFI boundary into plugins.
- Plugins can access parameters and cluster/context metadata via the `Context` provided by the host.
- The host invokes plugin `route()` during routing; the `test-plugin-compatible` marker file verifies invocation.

How the integration runner operates:
- Builds `test-plugin-compatible`, `test-plugin-outdated`, `test-plugin-main`, and the example plugin.
- Sets `LD_LIBRARY_PATH` to include the crates' `target/debug` outputs and workspace targets so PgDog can `dlopen()` the test shared libraries.
- Starts PgDog using integration helpers, runs the RSpec test, then shuts PgDog down.

How to run locally:
```bash
cd integration/plugins
bash run.sh
```

Note: The integration runner is separate from the default integration test suite; it requires the integration environment prepared by the helper scripts (see [integration/dev-server.sh](../integration/dev-server.sh) and [integration/common.sh](../integration/common.sh)).

### Unit Tests

#### Plugin Data Structures

**Location**: [pgdog-plugin/src/](../../pgdog-plugin/src/)
**Location**: [pgdog-plugin/src/](../pgdog-plugin/src/)

**Test modules**:
- [parameters.rs#L238](../pgdog-plugin/src/parameters.rs#L238) - Tests parameter FFI structure creation and empty parameter handling
- [ast.rs#L108](../pgdog-plugin/src/ast.rs#L108) - Tests AST FFI conversion by parsing SQL and verifying the protobuf structure is correctly accessible through FFI
- [string.rs#L69](../pgdog-plugin/src/string.rs#L69) - Tests PdStr conversions from both `&str` and `String` types

**Testing approach**: These unit tests validate that FFI data structures correctly wrap and expose Rust types without memory corruption or lifetime issues.

**How to run**:
```bash
cd pgdog-plugin
cargo test
```

#### Example Plugin Tests

**Location**: [plugins/pgdog-example-plugin/src/plugin.rs#L104-136](../plugins/pgdog-example-plugin/src/plugin.rs#L104-136)

**Test approach**:
- Manually constructs a `PdRouterContext` with a parsed `SELECT` query
- Calls the plugin's `route_query()` function directly
- Verifies the routing decision matches expected behavior (Read route for SELECT on replica-enabled cluster)

This demonstrates how to unit test plugin routing logic without running the full PgDog proxy.

### Test Coverage Gaps

The following areas lack test coverage:

#### Plugin Loading & Lifecycle
- ❌ Rust compiler version mismatch scenarios
- ❌ Plugin symbol resolution failures
- ❌ Plugin with missing required functions
- ❌ Plugin init/fini execution order
- ❌ Plugin initialization failures
- ❌ Library loading errors (bad path, missing dependencies)

#### Routing Behavior
- ❌ `Route::direct(n)` - routing to specific shard
- ❌ `Route::all()` - broadcasting to all shards
- ❌ `Route::block()` - blocking query execution
- ❌ Multiple plugins with precedence rules
- ❌ Plugin routing overrides (shard + read/write combinations)
- ❌ Read/write routing decisions
## Testing

- **Integration tests:** See [integration/plugins/](../integration/plugins/) and [integration/plugins/extended_spec.rb](../integration/plugins/extended_spec.rb) for FFI and routing tests. Run with `cd integration/plugins && bash run.sh`.
- **Unit tests:** See [pgdog-plugin/src/](../pgdog-plugin/src/) for FFI structure tests. Run with `cd pgdog-plugin && cargo test`.
- **Example plugin tests:** See [plugins/pgdog-example-plugin/src/plugin.rs](../plugins/pgdog-example-plugin/src/plugin.rs).
- **Coverage gaps:** Some error, concurrency, and edge cases are not yet covered. See code comments for details.

