//! Statement plugins: let plugins rewrite or block statements
//! before PgDog parses, rewrites and routes them.
//!
//! Plugins see the SQL the client sent. A rewrite replaces the SQL in the
//! client's `Query` or `Parse` message, so the rest of the query engine,
//! including the prepared statements cache, the AST cache and the router,
//! only ever sees the rewritten statement.
//!
//! Named prepared statements are rewritten before they are registered in the
//! global prepared statements cache. The cache is keyed by SQL, so every distinct
//! rewrite gets its own server-side statement, shared by all clients the plugin
//! rewrote the same way. On every `Bind`, plugins are asked again using the
//! statement's original SQL. If the rewrite changed (e.g., the plugin reloaded
//! its configuration), the statement is registered again with the new SQL and the
//! `Bind` is pointed at it.
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use bytes::{BufMut, BytesMut};
use pgdog_plugin::{
    Capabilities, Identity, PdSlice, StatementAction, StatementContext, StatementKind, Transform,
    TransformAction, TransformContext,
};
use tracing::{error, warn};

use super::*;
use crate::net::{Format, Parse, Protocol, ProtocolMessage};
use crate::parameters::ParameterValue;
use crate::plugin::{LoadedPlugin, has_capability, with_capability};

/// A client's prepared statement, as the client prepared it.
#[derive(Debug, Clone)]
struct StatementSource {
    /// Parse message with the client's statement name and original SQL.
    parse: Parse,
    /// Rewrite applied to the statement sent to the server, `None` if it wasn't rewritten.
    variant: Option<u64>,
}

/// Transform attached to a statement by a plugin.
#[derive(Debug, Clone, Copy)]
pub(super) struct PluginTransform {
    pub(super) plugin: &'static LoadedPlugin,
    pub(super) transform: Transform,
}

/// Combined decision of all statement plugins for one statement.
#[derive(Debug)]
enum Decision {
    Continue {
        /// Final SQL, if any plugin rewrote it.
        sql: Option<String>,
        /// Identifies the combination of rewrites.
        variant: Option<u64>,
        transforms: Vec<PluginTransform>,
    },
    Block(ErrorResponse),
}

/// Plugin state kept for the lifetime of the client connection.
#[derive(Debug, Default)]
pub(super) struct StatementPlugins {
    /// Prepared statements by client statement name ("" is the unnamed statement).
    sources: HashMap<String, StatementSource>,
    /// Transforms for the statement currently executing.
    transforms: Vec<PluginTransform>,
    /// Result formats requested by the `Bind` of the statement currently executing.
    result_formats: Vec<i16>,
}

impl StatementPlugins {
    /// Release transforms of the previous statement.
    fn release_transforms(&mut self) {
        release(self.transforms.drain(..));
        self.result_formats.clear();
    }
}

impl Drop for StatementPlugins {
    fn drop(&mut self) {
        self.release_transforms();
    }
}

fn release(transforms: impl IntoIterator<Item = PluginTransform>) {
    for transform in transforms {
        transform
            .plugin
            .vtable()
            .release_transform(transform.transform.handle);
    }
}

/// Session information plugins receive with every statement.
struct Session {
    user: String,
    database: String,
    application_name: String,
    client_addr: String,
    tls_identity: String,
    search_path: String,
    session_id: u64,
    in_transaction: bool,
}

impl Session {
    fn new(context: &QueryEngineContext<'_>) -> Self {
        // Display quotes values for use in SQL; plugins get them as-is.
        let value = |value: &ParameterValue| match value.as_str() {
            Some(value) => value.to_owned(),
            None => value.to_string(),
        };
        let param = |name: &str| context.params.get(name).map(value).unwrap_or_default();
        let user = param("user");
        let database = context
            .params
            .get("database")
            .map(value)
            .unwrap_or_else(|| user.clone());

        Self {
            database,
            application_name: param("application_name"),
            search_path: param("search_path"),
            client_addr: context
                .stream
                .peer_addr()
                .map(|addr| addr.ip().to_string())
                .unwrap_or_default(),
            tls_identity: context.stream.tls_identity().unwrap_or_default().to_owned(),
            session_id: context.id.pid() as u64,
            in_transaction: context.in_transaction(),
            user,
        }
    }

    fn context<'a>(
        &'a self,
        kind: StatementKind,
        sql: &'a str,
        statement_name: &'a str,
    ) -> StatementContext<'a> {
        StatementContext {
            identity: Identity {
                user: self.user.as_str().into(),
                database: self.database.as_str().into(),
                application_name: self.application_name.as_str().into(),
                client_addr: self.client_addr.as_str().into(),
                tls_identity: self.tls_identity.as_str().into(),
                session_id: self.session_id,
            },
            kind,
            sql: sql.into(),
            statement_name: statement_name.into(),
            search_path: self.search_path.as_str().into(),
            in_transaction: self.in_transaction,
        }
    }

    /// Run all statement plugins, in config order. Each plugin sees the SQL
    /// returned by the previous one.
    fn run(&self, kind: StatementKind, sql: &str, statement_name: &str) -> Decision {
        let mut rewritten: Option<String> = None;
        let mut variant: Option<DefaultHasher> = None;
        let mut transforms = vec![];

        for (index, plugin) in with_capability(Capabilities::STATEMENT).enumerate() {
            let current = rewritten.as_deref().unwrap_or(sql);
            let context = self.context(kind, current, statement_name);

            let decision = match plugin.vtable().statement(&context) {
                Ok(decision) => decision,
                Err(err) => {
                    release(transforms);
                    // Fail closed: a plugin that can't decide doesn't get bypassed.
                    return Decision::Block(blocked(
                        "XX000",
                        format!("plugin \"{}\" failed: {}", plugin.name(), err),
                    ));
                }
            };

            if let Some(transform) = decision.transform {
                let transform = PluginTransform { plugin, transform };
                if plugin.has(Capabilities::TRANSFORM) {
                    transforms.push(transform);
                } else {
                    warn!(
                        "plugin \"{}\" attached a transform without the TRANSFORM capability",
                        plugin.name()
                    );
                    release([transform]);
                }
            }

            match decision.action {
                StatementAction::Continue => (),
                StatementAction::Rewrite { sql, variant_tag } => {
                    let hasher = variant.get_or_insert_with(DefaultHasher::new);
                    (index, variant_tag).hash(hasher);
                    rewritten = Some(sql);
                }
                StatementAction::Block { sqlstate, message } => {
                    release(transforms);
                    return Decision::Block(blocked(&sqlstate, message));
                }
            }
        }

        Decision::Continue {
            sql: rewritten,
            variant: variant.map(|hasher| hasher.finish()),
            transforms,
        }
    }
}

fn blocked(sqlstate: &str, message: String) -> ErrorResponse {
    ErrorResponse {
        code: sqlstate.to_owned(),
        message,
        ..Default::default()
    }
}

fn out_of_date(name: &str) -> ErrorResponse {
    blocked(
        "26000",
        format!("prepared statement \"{name}\" is out of date, prepare it again"),
    )
}

impl QueryEngine {
    /// Run statement plugins on the client's request. Returns an error
    /// to send to the client if a plugin blocked the request.
    ///
    /// Must run before prepared statements are renamed to their global names.
    pub(super) fn apply_statement_plugins(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        client_request: &mut ClientRequest,
    ) -> Result<Option<ErrorResponse>, Error> {
        self.statement_plugins.release_transforms();

        if !has_capability(Capabilities::STATEMENT) {
            return Ok(None);
        }

        let session = Session::new(context);
        let state = &mut self.statement_plugins;
        // Transforms of statements prepared in this request, by name.
        let mut prepared: HashMap<String, Vec<PluginTransform>> = HashMap::new();
        let mut executing: Vec<PluginTransform> = vec![];
        let mut result_formats: Vec<i16> = vec![];
        let mut unnamed: Option<Parse> = None;

        let result = (|| {
            for message in client_request.messages.iter_mut() {
                match message {
                    ProtocolMessage::Query(query) => {
                        match session.run(StatementKind::Query, query.query(), "") {
                            Decision::Block(error) => return Some(error),
                            Decision::Continue {
                                sql, transforms, ..
                            } => {
                                if let Some(sql) = sql {
                                    query.set_query(&sql);
                                }
                                release(std::mem::replace(&mut executing, transforms));
                            }
                        }
                    }

                    ProtocolMessage::Parse(parse) => {
                        let decision =
                            session.run(StatementKind::Parse, parse.query(), parse.name());
                        match decision {
                            Decision::Block(error) => return Some(error),
                            Decision::Continue {
                                sql,
                                variant,
                                transforms,
                            } => {
                                state.sources.insert(
                                    parse.name().to_owned(),
                                    StatementSource {
                                        parse: parse.clone(),
                                        variant,
                                    },
                                );
                                if let Some(sql) = sql {
                                    parse.set_query(&sql);
                                }
                                if parse.anonymous() {
                                    unnamed = Some(parse.clone());
                                }
                                if let Some(previous) =
                                    prepared.insert(parse.name().to_owned(), transforms)
                                {
                                    release(previous);
                                }
                            }
                        }
                    }

                    ProtocolMessage::Bind(bind) => {
                        let name = bind.statement();
                        result_formats = bind
                            .result_formats()
                            .map(|format| match format {
                                Format::Text => 0,
                                Format::Binary => 1,
                            })
                            .collect();

                        // Prepared in this request: plugins have already seen it.
                        if let Some(transforms) = prepared.remove(name) {
                            release(std::mem::replace(&mut executing, transforms));
                            continue;
                        }

                        let Some(source) = state.sources.get_mut(name) else {
                            // Not prepared through us. Let Postgres report the error.
                            continue;
                        };

                        match session.run(StatementKind::Bind, source.parse.query(), name) {
                            Decision::Block(error) => return Some(error),
                            Decision::Continue {
                                sql,
                                variant,
                                transforms,
                            } => {
                                release(std::mem::replace(&mut executing, transforms));

                                if variant != source.variant {
                                    // The rewrite changed since the statement was prepared.
                                    let level = context.prepared_statements.level;
                                    let registered =
                                        context.prepared_statements.name(name).is_some();
                                    if source.parse.anonymous()
                                        || !level.handles_extended()
                                        || !registered
                                    {
                                        return Some(out_of_date(name));
                                    }

                                    let mut parse = source.parse.clone();
                                    if let Some(sql) = sql {
                                        parse.set_query(&sql);
                                    }
                                    // Registers the new statement under the client's name;
                                    // the Bind is renamed to it with the rest of the request.
                                    context.prepared_statements.insert(&mut parse);
                                    source.variant = variant;
                                }
                            }
                        }
                    }

                    ProtocolMessage::Close(close) if close.is_statement() => {
                        state.sources.remove(close.name());
                    }

                    ProtocolMessage::Fastpath(_) => {
                        match session.run(StatementKind::FunctionCall, "", "") {
                            Decision::Block(error) => return Some(error),
                            Decision::Continue { transforms, .. } => release(transforms),
                        }
                    }

                    _ => (),
                }
            }

            None
        })();

        // Statements prepared but not executed in this request.
        release(prepared.into_values().flatten());

        if result.is_some() {
            release(executing);
            return Ok(result);
        }

        // Drivers can execute the unnamed statement in a later request;
        // PgDog re-sends it from `last_parse`, which must be the rewritten one.
        if let Some(parse) = unnamed {
            client_request.last_parse = Some(parse);
        }

        state.transforms = executing;
        state.result_formats = result_formats;

        Ok(None)
    }

    /// Pass a server message to the plugins that attached a transform
    /// to the statement currently executing.
    pub(super) async fn transform_server_message(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        message: &mut Message,
    ) -> Result<(), Error> {
        if self.statement_plugins.transforms.is_empty() || message.streaming() {
            return Ok(());
        }

        let code = message.code();

        for transform in self.statement_plugins.transforms.clone() {
            if !transform.transform.codes.contains(code) {
                continue;
            }

            let action = {
                let payload = message.payload();
                transform.plugin.vtable().transform(&TransformContext {
                    handle: transform.transform.handle,
                    code: code as u8,
                    // Skip the code and length header.
                    payload: PdSlice::from(&payload[5..]),
                    result_formats: PdSlice::from(self.statement_plugins.result_formats.as_slice()),
                })
            };

            match action {
                Ok(TransformAction::Forward) => (),
                Ok(TransformAction::Replace(body)) => {
                    let mut payload = BytesMut::with_capacity(body.len() + 5);
                    payload.put_u8(code as u8);
                    payload.put_i32(body.len() as i32 + 4);
                    payload.put_slice(&body);
                    message.replace_payload(payload.freeze());
                }
                Ok(TransformAction::Fail) | Err(_) => {
                    let name = transform.plugin.name().to_owned();
                    error!(
                        "plugin \"{name}\" failed to transform a '{code}' message, closing connection"
                    );

                    // Some of the results may already be with the client, so the
                    // statement can't be completed. Stop the query and the session.
                    if let Err(err) = self.backend.cancel_query().await {
                        error!("failed to cancel query after plugin transform failure: {err}");
                    }
                    self.backend.force_close();
                    self.statement_plugins.release_transforms();
                    context
                        .stream
                        .fatal(ErrorResponse {
                            severity: "FATAL".into(),
                            ..blocked(
                                "XX000",
                                format!("plugin \"{name}\" failed to process the query results"),
                            )
                        })
                        .await?;

                    return Err(Error::PluginTransform(name));
                }
            }
        }

        // The statement is done.
        if code == 'Z' {
            self.statement_plugins.release_transforms();
        }

        Ok(())
    }
}
