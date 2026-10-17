//! Statement plugins: let a plugin allow, rewrite or deny statements before
//! PgDog parses, rewrites and routes them, mask columns of their results, and
//! redact the errors Postgres returns.
//!
//! The plugin sees the SQL the client sent. A rewrite replaces the SQL in the
//! client's `Query` or `Parse` message, so the rest of the query engine,
//! including the prepared statements cache, the AST cache and the router,
//! only ever sees the rewritten statement.
//!
//! Named prepared statements are rewritten before they are registered in the
//! global prepared statements cache. The cache is keyed by SQL, so every distinct
//! rewrite gets its own server-side statement, shared by all clients the plugin
//! rewrote the same way. Verdicts are deterministic until the plugin's
//! generation changes, so a prepared statement is checked again at `Bind` only if
//! the generation or the session's `search_path` changed since it was checked. If
//! the SQL to send changed, the statement is registered again with the new SQL
//! and the `Bind` is pointed at it.
//!
//! # Masks
//!
//! A verdict's column masks apply to what it was given for: a simple query
//! until its `ReadyForQuery`, a prepared statement until it's closed or
//! replaced, and the portals bound to it. Server messages are attributed to the
//! client messages they respond to, which carry the masks with them.
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use futures::FutureExt;
use pgdog_plugin::{Access, Capabilities, ClientInfo, ColumnMask, Session, Verdict};
use tracing::error;

use super::*;
use crate::net::{Parse, Protocol, ProtocolMessage, ReadyForQuery};
use crate::parameters::ParameterStore;
use crate::plugin::{LoadedPlugin, has_capability, with_capability};

mod errors;
mod masks;
mod params;
mod pending;

use masks::{MAX_BATCH_BYTES, MAX_BATCH_ROWS, Masking, Plan, PortalPlan};
use params::max_parameter;
use pending::{Pending, PendingQueue};

/// Who the client authenticated as. Captured when the connection is set up:
/// `user` and `database` are session parameters clients can `SET`, so they
/// can't be read from the parameter store later.
#[derive(Debug, Clone, Default)]
pub(super) struct AuthenticatedIdentity {
    pub(super) user: String,
    pub(super) database: String,
}

/// Connection details that don't change, read the first time a plugin needs them.
#[derive(Debug)]
struct Connection {
    tls_identity: String,
    addr: String,
}

/// What the plugin decided for a statement.
#[derive(Debug, Clone)]
struct Decision {
    /// SQL to send instead, if rewritten.
    sql: Option<String>,
    /// Columns to mask.
    plan: Option<Arc<Plan>>,
}

/// A client's prepared statement.
#[derive(Debug, Clone)]
struct Prepared {
    /// Parse message with the client's statement name and original SQL.
    parse: Parse,
    decision: Decision,
    /// Plugin generation the decision was made with.
    generation: u64,
    /// `search_path` the decision was made with.
    search_path: String,
}

/// Plugin state kept for the lifetime of the client connection.
#[derive(Debug, Default)]
pub(super) struct StatementPlugins {
    identity: AuthenticatedIdentity,
    connection: Option<Connection>,
    /// Prepared statements by client statement name ("" is the unnamed statement).
    prepared: HashMap<String, Prepared>,
    /// Mask plans by portal name.
    portals: HashMap<String, Option<PortalPlan>>,
    /// Client messages waiting for responses, in order. Only kept when a
    /// plugin masks columns.
    pending: PendingQueue,
    /// A plugin denied part of an extended protocol request: like Postgres after
    /// an error, discard messages until `Sync`.
    skip_until_sync: bool,
}

impl StatementPlugins {
    pub(super) fn new(identity: AuthenticatedIdentity) -> Self {
        Self {
            identity,
            ..Default::default()
        }
    }

    /// Read connection details, the first time they're needed.
    fn read_connection(&mut self, context: &QueryEngineContext<'_>) {
        self.connection.get_or_insert_with(|| Connection {
            tls_identity: context.stream.tls_identity().unwrap_or_default().to_owned(),
            addr: context
                .stream
                .peer_addr()
                .map(|addr| addr.ip().to_string())
                .unwrap_or_default(),
        });
    }
}

/// Everything a [`Session`] points to.
struct SessionStrings<'a> {
    identity: &'a AuthenticatedIdentity,
    connection: &'a Connection,
    search_path: Cow<'a, str>,
    application_name: Cow<'a, str>,
}

impl<'a> SessionStrings<'a> {
    fn new(
        identity: &'a AuthenticatedIdentity,
        connection: &'a Connection,
        params: &'a ParameterStore,
    ) -> Self {
        // Display quotes values for use in SQL; plugins get them as-is.
        let param = |name: &str| match params.get(name) {
            Some(value) => match value.as_str() {
                Some(value) => Cow::Borrowed(value),
                None => Cow::Owned(value.to_string()),
            },
            None => Cow::Borrowed(""),
        };

        Self {
            identity,
            connection,
            search_path: param("search_path"),
            application_name: param("application_name"),
        }
    }

    fn session(&self) -> Session<'_> {
        Session::new(
            self.identity.user.as_str().into(),
            self.identity.database.as_str().into(),
        )
        .with_tls_identity(self.connection.tls_identity.as_str().into())
        .with_search_path(self.search_path.as_ref().into())
        .with_client(ClientInfo::new(
            self.application_name.as_ref().into(),
            self.connection.addr.as_str().into(),
        ))
    }
}

/// Changes a request makes to plugin state, applied only if the plugin denies
/// none of it.
#[derive(Debug, Default)]
struct Staged {
    prepared: Vec<(String, Option<Prepared>)>,
    portals: Vec<(String, Option<Option<PortalPlan>>)>,
    pending: Vec<Pending>,
}

impl Staged {
    /// A prepared statement, including statements prepared earlier in this request.
    fn prepared<'a>(
        &'a mut self,
        prepared: &'a mut HashMap<String, Prepared>,
        name: &str,
    ) -> Option<&'a mut Prepared> {
        match self.prepared.iter().rposition(|(staged, _)| staged == name) {
            Some(index) => self.prepared[index].1.as_mut(),
            None => prepared.get_mut(name),
        }
    }

    /// The mask plan of a portal, including portals bound earlier in this request.
    fn portal(
        &self,
        portals: &HashMap<String, Option<PortalPlan>>,
        name: &str,
    ) -> Option<PortalPlan> {
        match self.portals.iter().rev().find(|(staged, _)| staged == name) {
            Some((_, portal)) => portal.clone().flatten(),
            None => portals.get(name).cloned().flatten(),
        }
    }

    fn apply(self, state: &mut StatementPlugins, track: bool) {
        for (name, prepared) in self.prepared {
            match prepared {
                Some(prepared) => state.prepared.insert(name, prepared),
                None => state.prepared.remove(&name),
            };
        }
        for (name, portal) in self.portals {
            match portal {
                Some(plan) => state.portals.insert(name, plan),
                None => state.portals.remove(&name),
            };
        }
        if track {
            state.pending.extend(self.pending);
        }
    }
}

fn denied(sqlstate: &str, message: String) -> ErrorResponse {
    ErrorResponse {
        code: sqlstate.to_owned(),
        message,
        ..Default::default()
    }
}

fn out_of_date(name: &str) -> ErrorResponse {
    denied(
        "26000",
        format!("prepared statement \"{name}\" is out of date, prepare it again"),
    )
}

/// Ask the statement plugin about a statement.
fn decide(
    plugin: &'static LoadedPlugin,
    session: &Session<'_>,
    sql: &str,
    extended: bool,
) -> Result<Decision, Box<ErrorResponse>> {
    let failed = |reason: String| {
        Box::new(denied(
            "XX000",
            format!("plugin \"{}\" {reason}", plugin.name()),
        ))
    };

    match plugin.vtable().statement(session, sql) {
        // Fail closed: a plugin that can't decide doesn't get bypassed.
        Err(err) => Err(failed(format!("failed: {err}"))),
        Ok(Verdict::Allow) => Ok(Decision {
            sql: None,
            plan: None,
        }),
        Ok(Verdict::Deny(deny)) => Err(Box::new(denied(deny.sqlstate.as_str(), deny.message))),
        Ok(Verdict::Rewrite {
            sql: rewritten,
            columns,
            redact_errors,
            ..
        }) => {
            if (!columns.is_empty() || redact_errors) && !plugin.has(Capabilities::MASK) {
                return Err(failed(
                    "masked columns or redacted errors without the MASK capability".into(),
                ));
            }
            // The client binds parameters for the statement it prepared.
            if extended && rewritten != sql {
                let original = max_parameter(sql);
                if original.is_none() || original != max_parameter(&rewritten) {
                    return Err(failed(
                        "rewrote a prepared statement with different parameters".into(),
                    ));
                }
            }
            Ok(Decision {
                sql: (rewritten != sql).then_some(rewritten),
                plan: plan(plugin, columns, redact_errors),
            })
        }
        // Fail closed on a verdict this version of PgDog doesn't know.
        Ok(_) => Err(failed("returned an unknown verdict".into())),
    }
}

fn plan(
    plugin: &'static LoadedPlugin,
    columns: Vec<ColumnMask>,
    redact_errors: bool,
) -> Option<Arc<Plan>> {
    (!columns.is_empty() || redact_errors).then(|| {
        Arc::new(Plan {
            plugin,
            columns,
            redact_errors,
        })
    })
}

/// The plugin with the statement hook. There is at most one.
fn statement_plugin() -> Option<&'static LoadedPlugin> {
    with_capability(Capabilities::STATEMENT).next()
}

impl QueryEngine {
    /// Run the statement plugin on the client's request. Returns an error
    /// to send to the client if the plugin denied the request.
    ///
    /// Must run before prepared statements are renamed to their global names.
    pub(super) fn apply_statement_plugins(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        client_request: &mut ClientRequest,
    ) -> Result<Option<ErrorResponse>, Error> {
        // Admin database commands are handled by PgDog and never reach Postgres.
        if context.admin {
            return Ok(None);
        }
        let Some(plugin) = statement_plugin() else {
            return Ok(None);
        };

        // Parts of a request PgDog split itself; the plugin has seen the whole request.
        if let Some(statement) = client_request.split_statement {
            // PgDog answers some parts itself, without the server's
            // CommandComplete, so results are numbered by part.
            self.statement_plugins.pending.start_statement(statement);
            return Ok(None);
        }

        let starts_statements = client_request.messages.iter().any(|message| {
            !matches!(
                message,
                ProtocolMessage::CopyData(_)
                    | ProtocolMessage::CopyDone(_)
                    | ProtocolMessage::CopyFail(_)
                    | ProtocolMessage::Other(_)
            )
        });
        if !starts_statements {
            return Ok(None);
        }

        // Nothing is outstanding from the server, so anything still pending was
        // answered by PgDog itself.
        if !self.backend.has_more_messages() && !self.backend.in_copy_mode() {
            self.statement_plugins.pending.clear();
        }

        let track = has_capability(Capabilities::MASK);
        let mut generation = None;
        let state = &mut self.statement_plugins;
        state.read_connection(context);
        let connection = state
            .connection
            .as_ref()
            .expect("connection details were read");
        let strings = SessionStrings::new(&state.identity, connection, context.params);
        let session = strings.session();
        let mut staged = Staged::default();
        let mut unnamed: Option<Parse> = None;

        for message in client_request.messages.iter_mut() {
            match message {
                ProtocolMessage::Query(query) => {
                    let decision = match decide(plugin, &session, query.query(), false) {
                        Ok(decision) => decision,
                        Err(error) => return Ok(Some(*error)),
                    };
                    if let Some(sql) = &decision.sql {
                        query.set_query(sql);
                    }
                    // A simple query destroys the unnamed statement and portal.
                    staged.prepared.push((String::new(), None));
                    staged.portals.push((String::new(), None));
                    staged.pending.push(Pending::Query {
                        plan: decision.plan,
                        result: 0,
                    });
                }

                ProtocolMessage::Parse(parse) => {
                    let decision = match decide(plugin, &session, parse.query(), true) {
                        Ok(decision) => decision,
                        Err(error) => return Ok(Some(*error)),
                    };
                    let name = parse.name().to_owned();
                    let prepared = Prepared {
                        parse: parse.clone(),
                        decision: decision.clone(),
                        generation: *generation.get_or_insert_with(|| plugin.vtable().generation()),
                        search_path: strings.search_path.to_string(),
                    };
                    if let Some(sql) = &decision.sql {
                        parse.set_query(sql);
                    }
                    if parse.anonymous() {
                        unnamed = Some(parse.clone());
                    }
                    staged.prepared.push((name, Some(prepared)));
                    staged.pending.push(Pending::Parse(decision.plan.clone()));
                }

                ProtocolMessage::Bind(bind) => {
                    let name = bind.statement().to_owned();
                    let portal = bind.portal().to_owned();
                    let mut plan = None;

                    let current = *generation.get_or_insert_with(|| plugin.vtable().generation());
                    if let Some(prepared) = staged.prepared(&mut state.prepared, &name) {
                        // The decision may no longer hold.
                        if prepared.generation != current
                            || prepared.search_path != strings.search_path
                        {
                            let decision =
                                match decide(plugin, &session, prepared.parse.query(), true) {
                                    Ok(decision) => decision,
                                    Err(error) => return Ok(Some(*error)),
                                };

                            if decision.sql != prepared.decision.sql {
                                // Different SQL: prepare it again under the client's name.
                                let level = context.prepared_statements.level;
                                let registered = context.prepared_statements.name(&name).is_some();
                                if prepared.parse.anonymous()
                                    || !level.handles_extended()
                                    || !registered
                                {
                                    return Ok(Some(out_of_date(&name)));
                                }

                                let mut parse = prepared.parse.clone();
                                if let Some(sql) = &decision.sql {
                                    parse.set_query(sql);
                                }
                                // The Bind is renamed to it with the rest of the request.
                                context.prepared_statements.insert(&mut parse);
                            }

                            prepared.decision = decision;
                            prepared.generation = current;
                            prepared.search_path = strings.search_path.to_string();
                        }
                        plan = prepared.decision.plan.clone();
                    }
                    // Otherwise not prepared through us: let Postgres report the error.

                    staged.pending.push(Pending::Bind(plan.clone()));
                    let plan = plan.map(|plan| PortalPlan {
                        plan,
                        formats: bind.result_formats().collect(),
                    });
                    staged.portals.push((portal, Some(plan)));
                }

                ProtocolMessage::Describe(describe) => {
                    let name = describe.statement();
                    let pending = if describe.is_statement() {
                        Pending::DescribeStatement(
                            staged
                                .prepared(&mut state.prepared, name)
                                .and_then(|prepared| prepared.decision.plan.clone()),
                        )
                    } else {
                        Pending::DescribePortal(staged.portal(&state.portals, name))
                    };
                    staged.pending.push(pending);
                }

                ProtocolMessage::Execute(execute) => {
                    let plan = staged.portal(&state.portals, execute.portal());
                    staged.pending.push(Pending::Execute(plan));
                }

                ProtocolMessage::Close(close) => {
                    let name = close.name().to_owned();
                    if close.is_statement() {
                        staged.prepared.push((name, None));
                    } else {
                        staged.portals.push((name, None));
                    }
                    staged.pending.push(Pending::Close);
                }

                ProtocolMessage::Sync(_) => staged.pending.push(Pending::Sync),

                ProtocolMessage::Fastpath(call) => {
                    let access = match call.function_oid() {
                        Some(function) => plugin.vtable().function_call(&session, function),
                        None => Ok(Access::Deny(pgdog_plugin::Deny::new(
                            pgdog_plugin::SqlState::new("08P01").expect("valid SQLSTATE"),
                            "malformed function call",
                        ))),
                    };
                    match access {
                        Ok(Access::Allow) => (),
                        Ok(Access::Deny(deny)) => {
                            return Ok(Some(denied(deny.sqlstate.as_str(), deny.message)));
                        }
                        // Fail closed on a verdict this version of PgDog doesn't know.
                        Ok(_) => {
                            return Ok(Some(denied(
                                "XX000",
                                format!("plugin \"{}\" returned an unknown verdict", plugin.name()),
                            )));
                        }
                        Err(err) => {
                            return Ok(Some(denied(
                                "XX000",
                                format!("plugin \"{}\" failed: {err}", plugin.name()),
                            )));
                        }
                    }
                    staged.pending.push(Pending::Query {
                        plan: None,
                        result: 0,
                    });
                }

                _ => (),
            }
        }

        drop(strings);
        staged.apply(&mut self.statement_plugins, track);

        // Drivers can execute the unnamed statement in a later request;
        // PgDog re-sends it from `last_parse`, which must be the rewritten one.
        if let Some(parse) = unnamed {
            client_request.last_parse = Some(parse);
        }

        Ok(None)
    }

    /// The plugin denied the request. Report it like Postgres reports a failed
    /// statement: the transaction, if any, is aborted, and in the extended
    /// protocol everything up to the next `Sync` is discarded.
    pub(super) async fn statement_blocked(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        client_request: &ClientRequest,
        error: ErrorResponse,
    ) -> Result<(), Error> {
        if let Some(transaction) = context.transaction.as_mut() {
            transaction.set_error();
        }

        let ends_cycle = client_request.messages.iter().any(|message| {
            matches!(
                message,
                ProtocolMessage::Query(_) | ProtocolMessage::Fastpath(_) | ProtocolMessage::Sync(_)
            )
        });

        if ends_cycle {
            return self.error_response(context, client_request, error).await;
        }

        error!("{:?} [{:?}]", error.message, context.stream.peer_addr());
        self.hooks.on_engine_error(context, &error)?;
        let sent = context.stream.send_flush(&error).await?;
        self.stats.sent(sent);
        self.statement_plugins.skip_until_sync = true;

        Ok(())
    }

    /// After a denial in the extended protocol, discard requests until `Sync`,
    /// then send `ReadyForQuery`. Returns true if the request was discarded.
    pub(super) async fn skip_until_sync(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        client_request: &ClientRequest,
    ) -> Result<bool, Error> {
        if !self.statement_plugins.skip_until_sync {
            return Ok(false);
        }

        let sync = client_request
            .messages
            .iter()
            .any(|message| matches!(message, ProtocolMessage::Sync(_)));
        if sync {
            self.statement_plugins.skip_until_sync = false;
            let ready = if context.in_error() {
                ReadyForQuery::error()
            } else {
                ReadyForQuery::in_transaction(context.in_transaction())
            };
            let sent = context.stream.send_flush(&ready).await?;
            self.stats.sent(sent);
        }

        Ok(true)
    }

    /// Plugin processing of a server message before it goes to the client:
    /// redact errors, and find the columns to mask. Returns the masking of a
    /// `DataRow`, which the caller must then mask with [`Self::mask_data_rows`].
    pub(super) async fn plugin_server_message(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        message: &mut Message,
        client_visible: bool,
    ) -> Result<Option<Masking>, Error> {
        if context.admin || message.streaming() {
            return Ok(None);
        }

        let code = message.code();

        if matches!(code, 'E' | 'N') && has_capability(Capabilities::ERRORS) {
            let state = &mut self.statement_plugins;
            state.read_connection(context);
            let connection = state
                .connection
                .as_ref()
                .expect("connection details were read");
            let strings = SessionStrings::new(&state.identity, connection, context.params);
            errors::redact(&strings.session(), message);
        }

        if !has_capability(Capabilities::MASK) {
            return Ok(None);
        }

        let masking = self.statement_plugins.pending.masking(code, client_visible);

        if code == 'Z' && client_visible {
            // The transaction ended, and with it all portals.
            if message.payload().get(5) == Some(&b'I') {
                self.statement_plugins.portals.clear();
            }
        }

        match (code, masking) {
            ('E' | 'N', Some(masking)) if masking.plan.redact_errors => {
                errors::redact_statement(message);
                Ok(None)
            }
            ('T', Some(masking)) => {
                if let Err(reason) = masking.check(message) {
                    return Err(self.fail_results(context, &masking, &reason).await);
                }
                Ok(None)
            }
            ('D', masking) => Ok(masking),
            _ => Ok(None),
        }
    }

    /// Mask a `DataRow`, together with the rows right behind it that the server
    /// already sent, and send them to the client. Returns the first message
    /// after them, which the caller must process next.
    pub(super) async fn mask_data_rows(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        first: Message,
        masking: Masking,
    ) -> Result<Option<Message>, Error> {
        let mut bytes = first.len();
        let mut rows = vec![first];
        let mut next = None;

        // Only take rows that are already here: batching never waits for the server.
        while rows.len() < MAX_BATCH_ROWS && bytes < MAX_BATCH_BYTES {
            match self.backend.read().now_or_never() {
                Some(Ok(message)) if message.code() == 'D' => {
                    // The pending queue needs no update: a `DataRow` leaves the
                    // statement that produced the first one at its head.
                    self.data_row_received(&message);
                    bytes += message.len();
                    rows.push(message);
                }
                Some(Ok(message)) => {
                    next = Some(message);
                    break;
                }
                Some(Err(err)) => return Err(err.into()),
                None => break,
            }
        }

        let result = if masking.blocking() {
            let masking = masking.clone();
            tokio::task::spawn_blocking(move || {
                let result = masking.mask(&mut rows);
                result.map(|_| rows)
            })
            .await
            .unwrap_or_else(|err| Err(format!("mask task failed: {err}")))
        } else {
            masking.mask(&mut rows).map(|_| rows)
        };

        let rows = match result {
            Ok(rows) => rows,
            Err(reason) => return Err(self.fail_results(context, &masking, &reason).await),
        };

        for row in &rows {
            self.stats.sent(row.len());
            context.stream.send(row).await?;
            self.hooks.on_server_message(context, row)?;
        }

        Ok(next)
    }

    /// Masking failed. Some of the results may already be with the client, so
    /// the statement can't be completed: stop the query and the session.
    async fn fail_results(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        masking: &Masking,
        reason: &str,
    ) -> Error {
        let name = masking.plan.plugin.name();
        error!("plugin \"{name}\" failed to mask results, closing connection: {reason}");

        if let Err(err) = self.backend.cancel_query().await {
            error!("failed to cancel query after plugin mask failure: {err}");
        }
        self.backend.force_close();
        let fatal = ErrorResponse {
            severity: "FATAL".into(),
            ..denied(
                "XX000",
                format!("plugin \"{name}\" failed to process the query results"),
            )
        };
        if let Err(err) = context.stream.fatal(fatal).await {
            return err.into();
        }

        Error::PluginResults(name.to_owned())
    }
}
