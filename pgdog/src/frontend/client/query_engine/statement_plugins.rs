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
//!
//! # Transforms
//!
//! A transform belongs to what the plugin attached it to, and lives exactly as
//! long as it does:
//!
//! - a simple `Query` (or fast-path call): until its `ReadyForQuery`, including
//!   any COPY data exchanged in between;
//! - a prepared statement (`Parse`): until it's closed or replaced, so `Describe`
//!   responses go through it;
//! - a portal (`Bind`): until it's closed or replaced, or the transaction ends,
//!   so every `Execute` of the portal, including resumed ones, goes through it.
//!
//! Server messages are attributed to their owner by keeping, in order, the client
//! messages that are still waiting for responses.
use std::collections::{HashMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};

use bytes::{BufMut, BytesMut};
use pgdog_plugin::{
    Capabilities, Identity, PdSlice, StatementAction, StatementContext, StatementKind, Transform,
    TransformAction, TransformContext,
};
use tracing::{debug, error, warn};

use super::*;
use crate::net::{Format, Parse, Protocol, ProtocolMessage, ReadyForQuery};
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

/// Transforms attached to one query, prepared statement or portal. Releases
/// its transform handles when dropped: each handle is released exactly once.
#[derive(Debug, Default)]
struct Attachment {
    transforms: Vec<PluginTransform>,
    /// Result formats from the portal's `Bind`.
    result_formats: Vec<i16>,
}

impl Drop for Attachment {
    fn drop(&mut self) {
        for transform in self.transforms.drain(..) {
            transform
                .plugin
                .vtable()
                .release_transform(transform.transform.handle);
        }
    }
}

/// Which attachment a server message belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Owner {
    Query,
    Statement(String),
    Portal(String),
    Nothing,
}

/// A client message still waiting for its responses.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pending {
    /// Simple query or fast-path call: everything until `ReadyForQuery`.
    Query,
    Parse(String),
    Bind(String),
    DescribeStatement(String),
    DescribePortal(String),
    Execute(String),
    Close,
    Sync,
}

impl Pending {
    fn owner(&self) -> Owner {
        match self {
            Self::Query => Owner::Query,
            Self::Parse(name) | Self::DescribeStatement(name) => Owner::Statement(name.clone()),
            Self::Bind(name) | Self::DescribePortal(name) | Self::Execute(name) => {
                Owner::Portal(name.clone())
            }
            Self::Close | Self::Sync => Owner::Nothing,
        }
    }
}

/// Combined decision of all statement plugins for one statement.
#[derive(Debug)]
enum Decision {
    Continue {
        /// Final SQL, if any plugin rewrote it.
        sql: Option<String>,
        /// Identifies the combination of rewrites.
        variant: Option<u64>,
        attachment: Attachment,
    },
    Block(ErrorResponse),
}

/// Who the client authenticated as. Captured when the connection is set up:
/// `user` and `database` are session parameters clients can `SET`, so they
/// can't be read from the parameter store later.
#[derive(Debug, Clone, Default)]
pub(super) struct AuthenticatedIdentity {
    pub(super) user: String,
    pub(super) database: String,
}

/// Plugin state kept for the lifetime of the client connection.
#[derive(Debug, Default)]
pub(super) struct StatementPlugins {
    identity: AuthenticatedIdentity,
    /// Prepared statements by client statement name ("" is the unnamed statement).
    sources: HashMap<String, StatementSource>,
    /// Transforms of the simple query being executed.
    query: Option<Attachment>,
    /// Transforms by prepared statement name.
    statements: HashMap<String, Attachment>,
    /// Transforms by portal name.
    portals: HashMap<String, Attachment>,
    /// Client messages waiting for responses, in order.
    pending: VecDeque<Pending>,
    /// A plugin blocked part of an extended protocol request: like Postgres after
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

    fn attachment(&self, owner: &Owner) -> Option<&Attachment> {
        match owner {
            Owner::Query => self.query.as_ref(),
            Owner::Statement(name) => self.statements.get(name),
            Owner::Portal(name) => self.portals.get(name),
            Owner::Nothing => None,
        }
    }

    fn has_transforms(&self) -> bool {
        let any = |attachment: &Attachment| !attachment.transforms.is_empty();
        self.query.as_ref().is_some_and(any)
            || self.statements.values().any(any)
            || self.portals.values().any(any)
    }

    /// The attachment a server message belongs to. Consumes the pending client
    /// message the server message completes.
    fn owner(&mut self, code: char, client_visible: bool) -> Owner {
        loop {
            let Some(head) = self.pending.front() else {
                return Owner::Nothing;
            };
            let owner = head.owner();
            let (matches, done) =
                match (head, code) {
                    // Internally split queries send ReadyForQuery for each part;
                    // only the one the client sees ends the query.
                    (Pending::Query, 'Z') => (true, client_visible),
                    (Pending::Query, _) => (true, false),
                    (Pending::Parse(_), '1') => (true, true),
                    (Pending::Bind(_), '2') => (true, true),
                    (Pending::DescribeStatement(_), 't') => (true, false),
                    (Pending::DescribeStatement(_), 'T' | 'n') => (true, true),
                    (Pending::DescribePortal(_), 'T' | 'n') => (true, true),
                    (Pending::Execute(_), 'C' | 's' | 'I') => (true, true),
                    (Pending::Execute(_), code) => {
                        (!matches!(code, '1' | '2' | '3' | 't' | 'Z'), false)
                    }
                    (Pending::Close, '3') => (true, true),
                    (Pending::Sync, 'Z') => (true, true),
                    // Errors belong to the message that failed. Postgres then skips the
                    // rest of the extended protocol messages until Sync.
                    (_, 'E') => {
                        while self.pending.front().is_some_and(|pending| {
                            !matches!(pending, Pending::Sync | Pending::Query)
                        }) {
                            self.pending.pop_front();
                        }
                        return owner;
                    }
                    // Notices and parameter changes belong to whatever is running.
                    (_, 'N' | 'S' | 'A') => (true, false),
                    _ => (false, false),
                };

            if matches {
                if done {
                    self.pending.pop_front();
                }
                return owner;
            }

            // The response to this message was produced by PgDog itself, not
            // the server, so it never reaches us. Move on to the next one.
            debug!("statement plugins: no response for {head:?} before '{code}'");
            self.pending.pop_front();
        }
    }

    /// A client-visible ReadyForQuery: the simple query is done, and if the
    /// transaction ended, so are all portals.
    fn ready_for_query(&mut self, status: u8) {
        self.query = None;
        if status == b'I' {
            self.portals.clear();
        }
    }
}

/// Changes a request makes to plugin state, applied only if no plugin blocks it.
#[derive(Debug, Default)]
struct Staged {
    sources: Vec<(String, Option<StatementSource>)>,
    query: Option<Attachment>,
    statements: Vec<(String, Option<Attachment>)>,
    portals: Vec<(String, Option<Attachment>)>,
    pending: Vec<Pending>,
}

impl Staged {
    /// The source of a statement, including statements prepared earlier in this request.
    fn source<'a>(
        &'a mut self,
        sources: &'a mut HashMap<String, StatementSource>,
        name: &str,
    ) -> Option<&'a mut StatementSource> {
        match self.sources.iter().rposition(|(staged, _)| staged == name) {
            Some(index) => self.sources[index].1.as_mut(),
            None => sources.get_mut(name),
        }
    }

    fn apply(self, state: &mut StatementPlugins) {
        for (name, source) in self.sources {
            match source {
                Some(source) => state.sources.insert(name, source),
                None => state.sources.remove(&name),
            };
        }
        if let Some(query) = self.query {
            state.query = Some(query);
        }
        for (name, attachment) in self.statements {
            match attachment {
                Some(attachment) => state.statements.insert(name, attachment),
                None => state.statements.remove(&name),
            };
        }
        for (name, attachment) in self.portals {
            match attachment {
                Some(attachment) => state.portals.insert(name, attachment),
                None => state.portals.remove(&name),
            };
        }
        state.pending.extend(self.pending);
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
    fn new(context: &QueryEngineContext<'_>, identity: &AuthenticatedIdentity) -> Self {
        // Display quotes values for use in SQL; plugins get them as-is.
        let value = |value: &ParameterValue| match value.as_str() {
            Some(value) => value.to_owned(),
            None => value.to_string(),
        };
        let param = |name: &str| context.params.get(name).map(value).unwrap_or_default();

        Self {
            user: identity.user.clone(),
            database: identity.database.clone(),
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
        let mut attachment = Attachment::default();

        for (index, plugin) in with_capability(Capabilities::STATEMENT).enumerate() {
            let current = rewritten.as_deref().unwrap_or(sql);
            let context = self.context(kind, current, statement_name);

            let decision = match plugin.vtable().statement(&context) {
                Ok(decision) => decision,
                Err(err) => {
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
                    attachment.transforms.push(transform);
                } else {
                    warn!(
                        "plugin \"{}\" attached a transform without the TRANSFORM capability",
                        plugin.name()
                    );
                    // Dropping it releases the handle.
                    let _ = Attachment {
                        transforms: vec![transform],
                        result_formats: vec![],
                    };
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
                    return Decision::Block(blocked(&sqlstate, message));
                }
            }
        }

        Decision::Continue {
            sql: rewritten,
            variant: variant.map(|hasher| hasher.finish()),
            attachment,
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

fn result_formats(bind: &crate::net::Bind) -> Vec<i16> {
    bind.result_formats()
        .map(|format| match format {
            Format::Text => 0,
            Format::Binary => 1,
        })
        .collect()
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
        // Admin database commands are handled by PgDog and never reach Postgres.
        if context.admin || !has_capability(Capabilities::STATEMENT) {
            return Ok(None);
        }

        // Parts of a request PgDog split itself; plugins have seen the whole request.
        if client_request.plugins_applied {
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
            self.statement_plugins.query = None;
        }

        let session = Session::new(context, &self.statement_plugins.identity);
        let state = &mut self.statement_plugins;
        let mut staged = Staged::default();
        let mut unnamed: Option<Parse> = None;

        for message in client_request.messages.iter_mut() {
            match message {
                ProtocolMessage::Query(query) => {
                    match session.run(StatementKind::Query, query.query(), "") {
                        Decision::Block(error) => return Ok(Some(error)),
                        Decision::Continue {
                            sql, attachment, ..
                        } => {
                            if let Some(sql) = sql {
                                query.set_query(&sql);
                            }
                            staged.query = Some(attachment);
                            // A simple query destroys the unnamed statement and portal.
                            staged.sources.push((String::new(), None));
                            staged.statements.push((String::new(), None));
                            staged.portals.push((String::new(), None));
                            staged.pending.push(Pending::Query);
                        }
                    }
                }

                ProtocolMessage::Parse(parse) => {
                    match session.run(StatementKind::Parse, parse.query(), parse.name()) {
                        Decision::Block(error) => return Ok(Some(error)),
                        Decision::Continue {
                            sql,
                            variant,
                            attachment,
                        } => {
                            let name = parse.name().to_owned();
                            staged.sources.push((
                                name.clone(),
                                Some(StatementSource {
                                    parse: parse.clone(),
                                    variant,
                                }),
                            ));
                            if let Some(sql) = sql {
                                parse.set_query(&sql);
                            }
                            if parse.anonymous() {
                                unnamed = Some(parse.clone());
                            }
                            staged.statements.push((name.clone(), Some(attachment)));
                            staged.pending.push(Pending::Parse(name));
                        }
                    }
                }

                ProtocolMessage::Bind(bind) => {
                    let name = bind.statement().to_owned();
                    let portal = bind.portal().to_owned();
                    let mut attachment = Attachment::default();

                    if let Some(source) = staged.source(&mut state.sources, &name) {
                        match session.run(StatementKind::Bind, source.parse.query(), &name) {
                            Decision::Block(error) => return Ok(Some(error)),
                            Decision::Continue {
                                sql,
                                variant,
                                attachment: bound,
                            } => {
                                attachment = bound;

                                if variant != source.variant {
                                    // The rewrite changed since the statement was prepared.
                                    let level = context.prepared_statements.level;
                                    let registered =
                                        context.prepared_statements.name(&name).is_some();
                                    if source.parse.anonymous()
                                        || !level.handles_extended()
                                        || !registered
                                    {
                                        return Ok(Some(out_of_date(&name)));
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
                    // Otherwise not prepared through us: let Postgres report the error.

                    attachment.result_formats = result_formats(bind);
                    staged.portals.push((portal.clone(), Some(attachment)));
                    staged.pending.push(Pending::Bind(portal));
                }

                ProtocolMessage::Describe(describe) => {
                    let name = describe.statement().to_owned();
                    staged.pending.push(if describe.is_statement() {
                        Pending::DescribeStatement(name)
                    } else {
                        Pending::DescribePortal(name)
                    });
                }

                ProtocolMessage::Execute(execute) => {
                    staged
                        .pending
                        .push(Pending::Execute(execute.portal().to_owned()));
                }

                ProtocolMessage::Close(close) => {
                    let name = close.name().to_owned();
                    if close.is_statement() {
                        staged.sources.push((name.clone(), None));
                        staged.statements.push((name, None));
                    } else {
                        staged.portals.push((name, None));
                    }
                    staged.pending.push(Pending::Close);
                }

                ProtocolMessage::Sync(_) => staged.pending.push(Pending::Sync),

                ProtocolMessage::Fastpath(_) => {
                    match session.run(StatementKind::FunctionCall, "", "") {
                        Decision::Block(error) => return Ok(Some(error)),
                        Decision::Continue { attachment, .. } => {
                            staged.query = Some(attachment);
                            staged.pending.push(Pending::Query);
                        }
                    }
                }

                _ => (),
            }
        }

        staged.apply(state);

        // Drivers can execute the unnamed statement in a later request;
        // PgDog re-sends it from `last_parse`, which must be the rewritten one.
        if let Some(parse) = unnamed {
            client_request.last_parse = Some(parse);
        }

        Ok(None)
    }

    /// A plugin blocked the request. Report it like Postgres reports a failed
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

    /// After a block in the extended protocol, discard requests until `Sync`,
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

    /// Pass a server message to the plugins that attached a transform
    /// to whatever the message is a response to.
    pub(super) async fn transform_server_message(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        message: &mut Message,
        client_visible: bool,
    ) -> Result<(), Error> {
        if message.streaming() {
            return Ok(());
        }

        let code = message.code();
        let tracking = !self.statement_plugins.pending.is_empty();
        if !tracking && !self.statement_plugins.has_transforms() {
            return Ok(());
        }

        let owner = self.statement_plugins.owner(code, client_visible);
        let (transforms, result_formats) = self
            .statement_plugins
            .attachment(&owner)
            .map(|attachment| {
                (
                    attachment.transforms.clone(),
                    attachment.result_formats.clone(),
                )
            })
            .unwrap_or_default();

        for transform in transforms {
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
                    result_formats: PdSlice::from(result_formats.as_slice()),
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

        if code == 'Z' && client_visible {
            let status = message.payload().get(5).copied().unwrap_or(b'I');
            self.statement_plugins.ready_for_query(status);
        }

        Ok(())
    }
}
