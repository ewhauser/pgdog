# PgDog Plugin System - Overview & Essentials

This document summarizes PgDog's plugin system: architecture, execution flow, integration points, and key development guidelines. For full details, see the referenced source files.

PgDog plugins are Rust shared libraries loaded at runtime. They can route queries, rewrite or block statements before PgDog parses them, transform the results sent back to clients, and receive database schema snapshots. FFI is used for safe communication, with strict version checks for safety.

This document describes plugin API 0.6 (`pgdog-plugin` 0.6). The hooks added in 0.6 are covered in [Hooks and capabilities](#hooks-and-capabilities).

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

A plugin declares which hooks it implements by returning a set of [`Capabilities`](../pgdog-plugin/src/capabilities.rs) from `Plugin::capabilities()`. PgDog only calls the hooks a plugin asked for, so a routing-only plugin pays nothing for the others. The default is `Capabilities::ROUTE`, which is how plugins behaved before 0.6.

| Capability | Hook | Called |
|---|---|---|
| `ROUTE` | `route(Context) -> Route` | For every statement PgDog routes, after parsing. |
| `STATEMENT` | `statement(StatementContext) -> StatementOutput` | For every `Query`, `Parse`, `Bind` and fast-path `FunctionCall`, before PgDog parses, rewrites or routes the statement. |
| `TRANSFORM` | `transform(TransformContext) -> TransformOutput` | For server messages of statements the plugin attached a transform to. |
| `SCHEMA` | `schema(database, epoch, snapshot)` | When a database's schema finishes loading. Makes PgDog load the schema even if `load_schema` would skip it. |
| `REQUIRED` | none | PgDog refuses to start if this plugin fails its configuration. |

Every plugin also has `reload() -> bool`, called when PgDog reloads its own configuration (`SIGHUP`, or the admin `RELOAD` and `FORCE_RELOAD` commands). Returning `false` means the new configuration is invalid; the plugin should keep its previous one, and PgDog logs a warning.

Capability bits PgDog doesn't know are kept, not dropped, so an older host never misreads a newer plugin.

### Statement hook

Plugins with `STATEMENT` see the SQL the client sent, with the client's identity (the user and database it authenticated as, client address, TLS certificate identity, session id, and the unauthenticated `application_name`), the statement kind and name, `search_path`, and whether the client is in a transaction. They return one of:

- `StatementOutput::cont()`: let the statement through unchanged;
- `StatementOutput::rewrite(sql, variant_tag)`: replace the SQL. Everything downstream, including the prepared statements cache, the AST cache, the router and sharding, sees the new SQL;
- `StatementOutput::block(sqlstate, message)`: reject the statement with an `ErrorResponse`.

Plugins run in config order, and each one sees the SQL returned by the previous one. The first block wins.

Blocked statements fail like statements Postgres rejects: the transaction, if any, is aborted (a later `COMMIT` reports `ROLLBACK`), and in the extended protocol everything up to the next `Sync` is discarded. A blocked statement never reaches a server. A plugin that panics or returns invalid output blocks the statement (`XX000`): the hook fails closed.

Prepared statements:

- For `Bind`, `sql` is the statement's **original** SQL, as the client prepared it, not a previous rewrite.
- `variant_tag` identifies a rewrite. If a later `Bind` returns a different tag than the `Parse` did (e.g., the plugin reloaded its configuration), PgDog prepares the statement again with the new SQL, so long-lived prepared statements follow plugin changes. If it can't (the unnamed statement, or prepared statements aren't handled by PgDog), the `Bind` fails with `26000` and the client must prepare the statement again.
- Rewrites of a `Parse` or `Bind` must keep the number and types of bind parameters.

Statement plugins are not called for admin database commands, and multi-statement queries PgDog splits internally are rewritten once, as the client sent them.

See [pgdog-plugin/src/statement.rs](../pgdog-plugin/src/statement.rs) and [pgdog/src/frontend/client/query_engine/statement_plugins.rs](../pgdog/src/frontend/client/query_engine/statement_plugins.rs).

### Result transform hook

A statement hook can attach a transform to its output with `with_transform(handle, codes)`, naming the server message codes it wants (e.g., `'D'` for `DataRow`, `'T'` for `RowDescription`, `'E'` for `ErrorResponse`). The plugin needs the `TRANSFORM` capability; transforms from plugins without it are released and ignored.

PgDog then calls `transform` with the handle for each matching message, after multi-shard results have been merged, sorted and aggregated, i.e., with exactly the messages the client would receive. The context has the message body (without the code and length header) and the result column formats from the client's `Bind` (empty for simple queries, where every column is text; one code applies to all columns, otherwise there's one per column). The plugin can forward the message, replace its body, or fail. Failing, or panicking, closes the client connection with a `FATAL` error and cancels the query, since some rows may already have been sent. Replication streams are not passed to transforms.

#### Transform ownership

A handle belongs to the statement output it was returned with, and PgDog releases it with `release_transform` exactly once, when that ends:

- a `Query` or fast-path call: at its `ReadyForQuery`, after any COPY data exchanged in between;
- a `Parse`: when the prepared statement is closed, replaced, or destroyed by a simple query (the unnamed statement), or the client disconnects. `Describe` responses go through it;
- a `Bind`: when the portal is closed, replaced, or destroyed by a simple query (the unnamed portal), or the transaction ends, or the client disconnects. Every `Execute` of the portal, including resumed ones, goes through it.

Handles are only identifiers, and must not be zero. A plugin may return the same value for several statements; it's then released once for each time it was returned.

See [pgdog-plugin/src/transform.rs](../pgdog-plugin/src/transform.rs).

### Concurrency

PgDog serves clients on many threads, and calls hooks from all of them:

- `route`, `statement` and `transform` run concurrently for different clients. For one client, they're called one at a time, in the order of the client's messages and the server's responses.
- `schema` and `reload` can run at any time, concurrently with the other hooks.
- `release_transform` runs on the thread of the client that owned the transform, or on the thread dropping its session.

Plugins must make their own state safe to share across threads. Hooks run on PgDog's async workers, so they must not block.

The authoritative version of these contracts is the documentation of the `Plugin` trait in [pgdog-plugin/src/plugin.rs](../pgdog-plugin/src/plugin.rs).

### Schema snapshots

Plugins with `SCHEMA` receive each database's schema as JSON: `pgdog_stats::Schema` with the full catalog (columns from `pg_attribute`, not filtered by the loading role's privileges, with their type names, comments and security labels; view definitions and options; non-system functions and operators). Names in view definitions, function bodies and type names are schema-qualified.

The JSON object has a `format_version` field, currently `1` (`pgdog_plugin::SCHEMA_SNAPSHOT_VERSION`). It changes whenever the format changes incompatibly, and plugins should reject versions they don't know.

A snapshot is sent each time a database's schema finishes loading: at startup, after configuration reloads, and after DDL when `reload_schema_on_ddl` is enabled. `epoch` increases with every snapshot, across all databases, so a plugin can ignore one older than what it has. If loading fails, PgDog retries and sends nothing until it succeeds: plugins keep their previous snapshot, and must decide for themselves what to do for a database they have no snapshot for yet. A security plugin should fail closed.

### Required plugins

By default, PgDog logs a warning and starts without a plugin that fails to load. A plugin can be made required, so PgDog refuses to start without it, in two ways:

- `required = true` in its `[[plugins]]` entry: PgDog doesn't start if the plugin fails to load for any reason (the shared library is missing, it was built with a different compiler or plugin API version, or it rejected its configuration);
- the `REQUIRED` capability: the plugin itself says PgDog must not run without it. Capabilities can only be read once the version checks pass, so this covers the plugin rejecting its configuration; use `required = true` to also cover loading failures.

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
- **Statement and transform hooks:** See [pgdog/src/frontend/client/query_engine/statement_plugins.rs](../pgdog/src/frontend/client/query_engine/statement_plugins.rs).
- **Schema snapshots and reload:** See [pgdog/src/plugin/mod.rs](../pgdog/src/plugin/mod.rs).
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
- Plugins must not panic. Panics are caught inside the plugin: a panicking `statement` hook blocks the statement and a panicking `transform` closes the client connection.
- Only declare the capabilities you implement: the statement and transform hooks are on the path of every statement and every server message.

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
- **Hooks**: [integration/plugins/hooks_spec.rb](../integration/plugins/hooks_spec.rb) — exercises the statement and transform hooks of `test-plugin-compatible` through the compiled shared library: rewrites (simple, extended and prepared), blocks (including a blocked statement aborting its transaction), and a `DataRow` transform that respects the `Bind` result formats.
- **Runner**: [integration/plugins/run.sh](../integration/plugins/run.sh) — builds the test plugins, sets `LD_LIBRARY_PATH` to include the test build outputs, starts PgDog using the integration helpers, runs the RSpec test, and stops PgDog.
- **Test plugins**: [integration/plugins/test-plugins/](../integration/plugins/test-plugins)
	- `test-plugin-compatible` — built with the same `pgdog-plugin` ABI; its `route()` calls `assert_context_compatible!()` and writes `route-called.test` the first time it is invoked. The RSpec test checks for this file to confirm the plugin was executed and parameters were seen. It also implements the statement and transform hooks, acting only on statements containing its markers (`pgdog_plugin_rewrite`, `pgdog_plugin_block`, `pgdog_plugin_uppercase`).
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

