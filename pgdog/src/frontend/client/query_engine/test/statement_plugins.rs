//! Statement plugin hook.
use std::sync::atomic::Ordering;

use crate::{
    expect_message,
    net::{
        BindComplete, DataRow, ErrorResponse, Format, Message, ParameterDescription, ParseComplete,
        ReadyForQuery, RowDescription,
    },
    plugin::test::*,
};

use super::prelude::*;

async fn test_client() -> TestClient {
    load_test_plugin();
    TestClient::new_replicas(Parameters::default()).await
}

fn first_value(messages: &[Message]) -> String {
    let row = messages
        .iter()
        .find(|message| message.code() == 'D')
        .expect("a DataRow");
    let row = DataRow::try_from(row.clone()).unwrap();
    row.get::<String>(0, Format::Text).unwrap()
}

#[tokio::test]
async fn test_simple_query_rewritten() {
    let mut client = test_client().await;

    client
        .send_simple(Query::new(format!("SELECT '{REWRITE}' AS v")))
        .await;
    let messages = client.read_until('Z').await.unwrap();

    assert_eq!(first_value(&messages), REWRITTEN);
}

#[tokio::test]
async fn test_simple_query_blocked() {
    let mut client = test_client().await;

    client
        .send_simple(Query::new(format!("SELECT '{BLOCK}'")))
        .await;
    let error = client.read_until('Z').await.unwrap_err();
    assert_eq!(error.code, "42501");
    assert!(error.message.starts_with("blocked for"), "{error:?}");
    assert!(
        !error.message.contains('"'),
        "plugins get identity values unquoted: {error:?}"
    );
    expect_message!(client.read().await, ReadyForQuery);
    assert!(
        !client.backend_connected(),
        "blocked query never reaches a server"
    );

    // Connection is still usable.
    client.send_simple(Query::new("SELECT 'ok'")).await;
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), "ok");
}

#[tokio::test]
async fn test_extended_blocked() {
    let mut client = test_client().await;

    client
        .send(Parse::named("blocked", format!("SELECT '{BLOCK}'")))
        .await;
    client.send(Bind::new_statement("blocked")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    let error = client.read_until('Z').await.unwrap_err();
    assert_eq!(error.code, "42501");
}

#[tokio::test]
async fn test_named_statement_follows_plugin_changes() {
    let mut client = test_client().await;
    VERSION.store(1, Ordering::Relaxed);

    client
        .send(Parse::named(
            "versioned",
            format!("SELECT '{VERSIONED}' AS v"),
        ))
        .await;
    client.send(Bind::new_statement("versioned")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    expect_message!(client.read().await, ParseComplete);
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), "pgdog_test_versioned_1");

    // Same rewrite: the statement is reused as-is.
    client.send(Bind::new_statement("versioned")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    expect_message!(client.read().await, BindComplete);
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), "pgdog_test_versioned_1");

    // The plugin changes its rewrite: the next Bind re-prepares the statement,
    // without the client seeing an extra ParseComplete.
    VERSION.store(2, Ordering::Relaxed);

    client.send(Bind::new_statement("versioned")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    expect_message!(client.read().await, BindComplete);
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), "pgdog_test_versioned_2");
}

#[tokio::test]
async fn test_unnamed_statement_rewritten_across_requests() {
    let mut client = test_client().await;

    // lib/pq style: prepare and describe, then bind and execute in the next request.
    client
        .send(Parse::new_anonymous(&format!("SELECT '{REWRITE}' AS v")))
        .await;
    client.send(Describe::new_statement("")).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    expect_message!(client.read().await, ParseComplete);
    expect_message!(client.read().await, ParameterDescription);
    expect_message!(client.read().await, RowDescription);
    expect_message!(client.read().await, ReadyForQuery);

    client.send(Bind::new_statement("")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    expect_message!(client.read().await, BindComplete);
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), REWRITTEN);
}

#[tokio::test]
async fn test_simple_query_transformed() {
    let mut client = test_client().await;
    let released = RELEASED.load(Ordering::Relaxed);

    client
        .send_simple(Query::new(format!(
            "SELECT 'secret' AS v, '{TRANSFORM}' AS marker"
        )))
        .await;
    let messages = client.read_until('Z').await.unwrap();

    assert_eq!(first_value(&messages), TRANSFORMED);
    let row = messages
        .iter()
        .find(|message| message.code() == 'D')
        .unwrap();
    assert_eq!(DataRow::try_from(row.clone()).unwrap().len(), 1);
    assert_eq!(
        RELEASED.load(Ordering::Relaxed),
        released + 1,
        "transform released after ReadyForQuery"
    );

    // Transforms are per statement.
    client.send_simple(Query::new("SELECT 'plain'")).await;
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), "plain");
}

#[tokio::test]
async fn test_extended_transformed() {
    let mut client = test_client().await;

    client
        .send(Parse::named(
            "transformed",
            format!("SELECT 'secret' AS v, '{TRANSFORM}' AS marker"),
        ))
        .await;
    client.send(Bind::new_statement("transformed")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    expect_message!(client.read().await, ParseComplete);
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), TRANSFORMED);

    // Executing the prepared statement again still applies the transform.
    client.send(Bind::new_statement("transformed")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    expect_message!(client.read().await, BindComplete);
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), TRANSFORMED);
}

#[tokio::test]
async fn test_transform_failure_closes_connection() {
    let mut client = test_client().await;

    client
        .send(Query::new(format!("SELECT '{TRANSFORM_FAIL}'")))
        .await;
    let result = client.try_process().await;
    assert!(result.is_err(), "the session ends");

    // RowDescription goes out before the DataRow the plugin fails on.
    expect_message!(client.read().await, RowDescription);
    let error = expect_message!(client.read().await, ErrorResponse);
    assert_eq!(error.severity, "FATAL");
    assert_eq!(error.code, "XX000");
    assert!(!client.backend_connected(), "server connection was closed");
}

/// Admin database commands are PgDog's own and never reach Postgres, so
/// statement plugins must not see them.
#[tokio::test]
async fn test_admin_commands_skip_statement_plugins() {
    use crate::config::{config, load_test, set};
    use crate::frontend::client::test::SpawnedClient;
    use crate::net::{Authentication, Password};

    load_test_plugin();
    load_test();
    let mut cfg = (*config()).clone();
    cfg.config.general.auth_type = pgdog_config::AuthType::Plain;
    cfg.config.admin.password = "admin".into();
    set(cfg).unwrap();

    let cfg = config();
    let mut params = Parameters::default();
    params.insert("user", cfg.config.admin.user.as_str());
    params.insert("database", cfg.config.admin.name.as_str());
    let mut client = SpawnedClient::new_with_login(params).await;
    expect_message!(client.read().await, Authentication);
    client.send(Password::new_password("admin")).await;
    let ok = expect_message!(client.read().await, Authentication);
    assert!(matches!(ok, Authentication::Ok));
    client.read_until('Z').await;

    // The test plugin blocks anything containing its marker.
    client
        .send(Query::new(format!("SHOW CLIENTS /* {BLOCK} */")))
        .await;
    let messages = client.read_until('Z').await;
    for message in messages {
        if message.code() == 'E' {
            let error = ErrorResponse::try_from(message).unwrap();
            assert!(
                !error.message.starts_with("blocked for"),
                "admin command went through the plugin: {error:?}"
            );
        }
    }
    client.join().await;
}

/// `user` and `database` are parameters clients can SET; plugins must keep
/// seeing who the client authenticated as.
#[tokio::test]
async fn test_identity_comes_from_authentication() {
    let mut client = test_client().await;

    client
        .send_simple(Query::new(format!("SELECT '{BLOCK}'")))
        .await;
    let before = client.read_until('Z').await.unwrap_err();
    expect_message!(client.read().await, ReadyForQuery);

    client
        .send_simple(Query::new("SET \"user\" = 'impersonated'"))
        .await;
    client.read_until('Z').await.unwrap();

    client
        .send_simple(Query::new(format!("SELECT '{BLOCK}'")))
        .await;
    let after = client.read_until('Z').await.unwrap_err();
    assert_eq!(before.message, after.message);
    assert!(!after.message.contains("impersonated"), "{after:?}");
}

/// Describe of a prepared statement goes through the transforms attached at Parse.
#[tokio::test]
async fn test_describe_uses_statement_transforms() {
    let mut client = test_client().await;
    client
        .send(Parse::named(
            "described",
            format!("SELECT '{FAIL_DESCRIBE}'"),
        ))
        .await;
    client.send(Describe::new_statement("described")).await;
    client.send(Sync).await;
    assert!(
        client.try_process().await.is_err(),
        "the RowDescription transform fails the session"
    );
}

/// A suspended portal keeps its transform when it's resumed.
#[tokio::test]
async fn test_resumed_portal_keeps_transforms() {
    let mut client = test_client().await;
    client.send_simple(Query::new("BEGIN")).await;
    client.read_until('Z').await.unwrap();

    client
        .send(Parse::named(
            "rows",
            format!("SELECT 'secret', '{TRANSFORM}' FROM generate_series(1, 2)"),
        ))
        .await;
    client
        .send(Bind::new_name_portal("rows", "rows_portal"))
        .await;
    client
        .send(Execute::new_portal_limit("rows_portal", 1))
        .await;
    client.send(Flush).await;
    client.try_process().await.unwrap();
    let first = client.read_until('s').await.unwrap();
    assert_eq!(first_value(&first), TRANSFORMED);

    // Resume in a separate request, without Bind.
    client
        .send(Execute::new_portal_limit("rows_portal", 1))
        .await;
    client.send(Flush).await;
    client.try_process().await.unwrap();
    let second = client.read_until('s').await.unwrap();
    assert_eq!(first_value(&second), TRANSFORMED);

    // The portal's handle is released when the transaction ends.
    let released = RELEASED.load(Ordering::Relaxed);
    client.send(Sync).await;
    client.try_process().await.unwrap();
    client.read_until('Z').await.unwrap();
    client.send_simple(Query::new("COMMIT")).await;
    client.read_until('Z').await.unwrap();
    assert!(RELEASED.load(Ordering::Relaxed) > released);
}

/// COPY data arrives in separate requests; errors from the COPY still go
/// through the query's transforms.
#[tokio::test]
async fn test_copy_errors_use_query_transforms() {
    use crate::net::{CopyData, CopyDone};

    let mut client = test_client().await;
    client.send_simple(Query::new("BEGIN")).await;
    client.read_until('Z').await.unwrap();
    client
        .send_simple(Query::new(
            "CREATE TEMP TABLE copy_transform (id integer CHECK (id > 0), secret text DEFAULT 'secret')",
        ))
        .await;
    client.read_until('Z').await.unwrap();

    client
        .send_simple(Query::new(format!(
            "COPY copy_transform (id) FROM STDIN /* {FAIL_ERROR} */"
        )))
        .await;
    client.read_until('G').await.unwrap();
    client.send(CopyData::new(b"-1\n")).await;
    client.send(CopyDone).await;
    assert!(
        client.try_process().await.is_err(),
        "the ErrorResponse transform fails the session"
    );
}

/// A blocked statement aborts the transaction, like any failed statement.
#[tokio::test]
async fn test_block_aborts_transaction() {
    let mut client = test_client().await;
    client.send_simple(Query::new("BEGIN")).await;
    client.read_until('Z').await.unwrap();
    client.send_simple(Query::new("SELECT 1")).await;
    client.read_until('Z').await.unwrap();

    client
        .send_simple(Query::new(format!("SELECT '{BLOCK}'")))
        .await;
    client.read_until('Z').await.unwrap_err();
    let ready = expect_message!(client.read().await, ReadyForQuery);
    assert_eq!(ready.status, 'E');

    client
        .send_simple(Query::new("SELECT 'still running'"))
        .await;
    let error = client.read_until('Z').await.unwrap_err();
    assert_eq!(error.code, "25P02", "{error:?}");
    expect_message!(client.read().await, ReadyForQuery);

    // COMMIT of a failed transaction rolls back.
    client.send_simple(Query::new("COMMIT")).await;
    let messages = client.read_until('Z').await.unwrap();
    let complete = messages.iter().find(|m| m.code() == 'C').unwrap();
    let complete = crate::net::CommandComplete::try_from(complete.clone()).unwrap();
    assert_eq!(complete.command(), "ROLLBACK");
    let ready = ReadyForQuery::try_from(messages.last().unwrap().clone()).unwrap();
    assert_eq!(ready.status, 'I');
}

/// A block in an extended protocol request without Sync: error now, then
/// everything until Sync is discarded, like Postgres does after an error.
#[tokio::test]
async fn test_extended_block_skips_until_sync() {
    let mut client = test_client().await;

    client
        .send(Parse::named("blocked", format!("SELECT '{BLOCK}'")))
        .await;
    client.send(Describe::new_statement("blocked")).await;
    client.send(Flush).await;
    client.try_process().await.unwrap();
    let error = expect_message!(client.read().await, ErrorResponse);
    assert_eq!(error.code, "42501");

    client.send(Bind::new_statement("blocked")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();
    let ready = expect_message!(client.read().await, ReadyForQuery);
    assert_eq!(ready.status, 'I');

    client.send_simple(Query::new("SELECT 'ok'")).await;
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), "ok");
}

/// PgDog splits multi-statement queries internally; plugins rewrite them once.
#[tokio::test]
async fn test_split_query_rewritten_once() {
    let mut client = test_client().await;
    VERSION.store(1, Ordering::Relaxed);
    client
        .send_simple(Query::new(format!(
            "SET application_name = 'split'; SELECT '{VERSIONED}'"
        )))
        .await;
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), "pgdog_test_versioned_1");
}

/// Bind is checked even when Parse is in the same request.
#[tokio::test]
async fn test_bind_hook_runs_with_parse() {
    let mut client = test_client().await;
    client
        .send(Parse::named("deny_bind", format!("SELECT '{BLOCK_BIND}'")))
        .await;
    client.send(Bind::new_statement("deny_bind")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();
    let error = client.read_until('Z').await.unwrap_err();
    assert_eq!(error.message, "bind denied");
}

/// Closing a prepared statement releases the transforms attached at Parse.
#[tokio::test]
async fn test_close_releases_statement_transforms() {
    let mut client = test_client().await;
    client
        .send(Parse::named("closed", format!("SELECT '{TRANSFORM}'")))
        .await;
    client.send(Sync).await;
    client.try_process().await.unwrap();
    client.read_until('Z').await.unwrap();

    let released = RELEASED.load(Ordering::Relaxed);
    client.send(Close::named("closed")).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();
    client.read_until('Z').await.unwrap();
    assert_eq!(RELEASED.load(Ordering::Relaxed), released + 1);
}
