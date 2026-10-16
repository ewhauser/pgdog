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

/// First column of every DataRow.
fn values(messages: &[Message]) -> Vec<String> {
    messages
        .iter()
        .filter(|message| message.code() == 'D')
        .map(|row| {
            DataRow::try_from(row.clone())
                .unwrap()
                .get::<String>(0, Format::Text)
                .unwrap()
        })
        .collect()
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

/// PgDog connects lazily, so a block of the first statement after BEGIN fails
/// the transaction before it has a server connection. COMMIT still rolls back.
#[tokio::test]
async fn test_block_first_statement_then_commit() {
    let mut client = test_client().await;
    client.send_simple(Query::new("BEGIN")).await;
    client.read_until('Z').await.unwrap();

    client
        .send_simple(Query::new(format!("SELECT '{BLOCK}'")))
        .await;
    client.read_until('Z').await.unwrap_err();
    let ready = expect_message!(client.read().await, ReadyForQuery);
    assert_eq!(ready.status, 'E');
    assert!(!client.backend_connected(), "blocked query never connects");

    client.send_simple(Query::new("COMMIT")).await;
    let messages = client.read_until('Z').await.unwrap();
    let complete = messages.iter().find(|m| m.code() == 'C').unwrap();
    let complete = crate::net::CommandComplete::try_from(complete.clone()).unwrap();
    assert_eq!(complete.command(), "ROLLBACK");
    let ready = ReadyForQuery::try_from(messages.last().unwrap().clone()).unwrap();
    assert_eq!(ready.status, 'I');

    // Same for the extended protocol.
    client.send_simple(Query::new("BEGIN")).await;
    client.read_until('Z').await.unwrap();
    client
        .send_simple(Query::new(format!("SELECT '{BLOCK}'")))
        .await;
    client.read_until('Z').await.unwrap_err();
    expect_message!(client.read().await, ReadyForQuery);

    client.send(Parse::new_anonymous("COMMIT")).await;
    client.send(Bind::new_statement("")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();
    let messages = client.read_until('Z').await.unwrap();
    let complete = messages.iter().find(|m| m.code() == 'C').unwrap();
    let complete = crate::net::CommandComplete::try_from(complete.clone()).unwrap();
    assert_eq!(complete.command(), "ROLLBACK");
    let ready = ReadyForQuery::try_from(messages.last().unwrap().clone()).unwrap();
    assert_eq!(ready.status, 'I');
}

#[tokio::test]
async fn test_simple_query_masked() {
    let mut client = test_client().await;

    client
        .send_simple(Query::new(format!(
            "SELECT 'secret' AS v, '{MASK}' AS marker"
        )))
        .await;
    let messages = client.read_until('Z').await.unwrap();

    let row = messages
        .iter()
        .find(|message| message.code() == 'D')
        .unwrap();
    let row = DataRow::try_from(row.clone()).unwrap();
    assert_eq!(row.get::<String>(0, Format::Text).unwrap(), "SECRET");
    // Only the masked column changes.
    assert_eq!(row.get::<String>(1, Format::Text).unwrap(), MASK);

    // Masks are per statement.
    client.send_simple(Query::new("SELECT 'plain'")).await;
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), "plain");
}

#[tokio::test]
async fn test_extended_masked() {
    let mut client = test_client().await;

    client
        .send(Parse::named(
            "masked",
            format!("SELECT 'secret' AS v, NULL::text AS n, '{MASK}' AS marker"),
        ))
        .await;
    client.send(Bind::new_statement("masked")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    expect_message!(client.read().await, ParseComplete);
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), "SECRET");

    // Executing the prepared statement again still masks.
    client.send(Bind::new_statement("masked")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    expect_message!(client.read().await, BindComplete);
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), "SECRET");
}

/// Large results are masked in batches, in order.
#[tokio::test]
async fn test_masked_in_batches() {
    for marker in [MASK, MASK_BLOCKING] {
        let mut client = test_client().await;
        let batches = MASK_BATCHES.load(Ordering::Relaxed);

        client
            .send_simple(Query::new(format!(
                "SELECT 'row ' || n || ' {marker}' FROM generate_series(1, 2000) n"
            )))
            .await;
        let messages = client.read_until('Z').await.unwrap();

        let expected: Vec<_> = (1..=2000)
            .map(|n| format!("ROW {n} {}", marker.to_uppercase()))
            .collect();
        assert_eq!(values(&messages), expected);
        // Other tests mask a few rows at the same time.
        let batches = MASK_BATCHES.load(Ordering::Relaxed) - batches;
        assert!(batches < 1000, "{batches} batches for 2000 rows");
    }
}

/// Masks apply to the result set they name in multi-statement queries.
#[tokio::test]
async fn test_masked_second_result() {
    let mut client = test_client().await;

    client
        .send_simple(Query::new(format!(
            "SELECT 'first'; SELECT 'second' /* {MASK_SECOND} */"
        )))
        .await;
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(values(&messages), ["first", "SECOND"]);
}

#[tokio::test]
async fn test_mask_failure_closes_connection() {
    let mut client = test_client().await;

    client
        .send(Query::new(format!("SELECT '{MASK_FAIL}'")))
        .await;
    let result = client.try_process().await;
    assert!(result.is_err(), "the session ends");

    // RowDescription goes out before the rows the plugin fails on.
    expect_message!(client.read().await, RowDescription);
    let error = expect_message!(client.read().await, ErrorResponse);
    assert_eq!(error.severity, "FATAL");
    assert_eq!(error.code, "XX000");
    assert!(!client.backend_connected(), "server connection was closed");
}

/// Masked columns must have the type the plugin declared: checked on the
/// statement's RowDescription.
#[tokio::test]
async fn test_masked_column_type_checked() {
    let mut client = test_client().await;
    client
        .send(Parse::named("not_text", format!("SELECT 1 /* {MASK} */")))
        .await;
    client.send(Describe::new_statement("not_text")).await;
    client.send(Sync).await;
    assert!(
        client.try_process().await.is_err(),
        "an integer where the plugin declared text fails the session"
    );
}

/// Masks get values in the format the client asked for, and return them in it.
#[tokio::test]
async fn test_masked_in_client_format() {
    use crate::net::Format as WireFormat;

    let mut client = test_client().await;

    // Simple protocol: text.
    client
        .send_simple(Query::new(format!("SELECT 41 /* {MASK_INT} */")))
        .await;
    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(values(&messages), ["42"]);

    // Extended protocol, binary results.
    client
        .send(Parse::named(
            "int_mask",
            format!("SELECT 41 /* {MASK_INT} */"),
        ))
        .await;
    client
        .send(Bind::new_params_codes_results("int_mask", &[], &[], &[1]))
        .await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();
    expect_message!(client.read().await, ParseComplete);
    let messages = client.read_until('Z').await.unwrap();
    let row = messages
        .iter()
        .find(|message| message.code() == 'D')
        .unwrap();
    let row = DataRow::try_from(row.clone()).unwrap();
    assert_eq!(row.get::<i32>(0, WireFormat::Binary), Some(42));
}

/// A suspended portal keeps its masks when it's resumed.
#[tokio::test]
async fn test_resumed_portal_keeps_masks() {
    let mut client = test_client().await;
    client.send_simple(Query::new("BEGIN")).await;
    client.read_until('Z').await.unwrap();

    client
        .send(Parse::named(
            "rows",
            format!("SELECT 'secret', '{MASK}' FROM generate_series(1, 2)"),
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
    assert_eq!(first_value(&first), "SECRET");

    // Resume in a separate request, without Bind.
    client
        .send(Execute::new_portal_limit("rows_portal", 1))
        .await;
    client.send(Flush).await;
    client.try_process().await.unwrap();
    let second = client.read_until('s').await.unwrap();
    assert_eq!(first_value(&second), "SECRET");

    client.send(Sync).await;
    client.try_process().await.unwrap();
    client.read_until('Z').await.unwrap();
    client.send_simple(Query::new("COMMIT")).await;
    client.read_until('Z').await.unwrap();
}

/// Closing a portal right after executing it, in the same request, doesn't
/// lose the masks of rows still on their way.
#[tokio::test]
async fn test_close_after_execute_keeps_masks() {
    let mut client = test_client().await;

    client
        .send(Parse::named(
            "closing",
            format!("SELECT 'secret', '{MASK}'"),
        ))
        .await;
    client
        .send(Bind::new_name_portal("closing", "closing_portal"))
        .await;
    client.send(Execute::new_portal("closing_portal")).await;
    client.send(Close::portal("closing_portal")).await;
    client.send(Close::named("closing")).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    let messages = client.read_until('Z').await.unwrap();
    assert_eq!(first_value(&messages), "SECRET");
    assert_eq!(
        messages
            .iter()
            .filter(|message| message.code() == '3')
            .count(),
        2
    );
}

/// The statement is checked again at Bind only when the plugin's generation changes.
#[tokio::test]
async fn test_bind_rechecks_only_on_new_generation() {
    let mut client = test_client().await;
    let version = VERSION.load(Ordering::Relaxed);

    client
        .send(Parse::named(
            "generation",
            format!("SELECT '{VERSIONED}' AS v, 'generation'"),
        ))
        .await;
    client.send(Sync).await;
    client.try_process().await.unwrap();
    client.read_until('Z').await.unwrap();

    let calls = VERSIONED_CALLS.load(Ordering::Relaxed);
    for _ in 0..3 {
        client.send(Bind::new_statement("generation")).await;
        client.send(Execute::new()).await;
        client.send(Sync).await;
        client.try_process().await.unwrap();
        let messages = client.read_until('Z').await.unwrap();
        // Tests share the plugin: the version may move under us.
        if VERSION.load(Ordering::Relaxed) == version {
            assert_eq!(
                first_value(&messages),
                format!("pgdog_test_versioned_{version}")
            );
        }
    }
    if VERSION.load(Ordering::Relaxed) == version {
        assert_eq!(VERSIONED_CALLS.load(Ordering::Relaxed), calls);
    }
}

/// A rewrite of a prepared statement can't change its parameters.
#[tokio::test]
async fn test_rewrite_must_keep_parameters() {
    let mut client = test_client().await;

    client
        .send(Parse::named(
            "bad_params",
            format!("SELECT $1::int /* {BAD_PARAMS} */"),
        ))
        .await;
    client.send(Sync).await;
    client.try_process().await.unwrap();
    let error = client.read_until('Z').await.unwrap_err();
    assert_eq!(error.code, "XX000");
    assert!(error.message.contains("different parameters"), "{error:?}");
}

/// Errors from Postgres go through the plugin, which can't change their
/// severity or SQLSTATE.
#[tokio::test]
async fn test_errors_redacted() {
    let mut client = test_client().await;

    client
        .send_simple(Query::new(format!("SELECT '{SECRET}'::int")))
        .await;
    let error = client.read_until('Z').await.unwrap_err();
    assert_eq!(error.code, "22P02");
    assert_eq!(error.severity, "ERROR");
    assert!(!error.message.contains(SECRET), "{error:?}");
    assert!(error.message.contains(REDACTED), "{error:?}");
    expect_message!(client.read().await, ReadyForQuery);

    // Other errors are untouched.
    client.send_simple(Query::new("SELECT 'other'::int")).await;
    let error = client.read_until('Z').await.unwrap_err();
    assert!(error.message.contains("\"other\""), "{error:?}");
}

/// A plugin that fails to redact an error fails closed.
#[tokio::test]
async fn test_redaction_failure_hides_error() {
    let mut client = test_client().await;

    client
        .send_simple(Query::new(format!("SELECT '{REDACT_PANIC}'::int")))
        .await;
    let error = client.read_until('Z').await.unwrap_err();
    assert_eq!(error.code, "22P02");
    assert!(!error.message.contains(REDACT_PANIC), "{error:?}");
}

/// Rewritten prepared statements of any type are checked for their
/// parameters, including those the AST walker doesn't support.
#[tokio::test]
async fn test_rewritten_copy_prepared() {
    let mut client = test_client().await;

    client
        .send(Parse::named(
            "copy",
            format!("COPY (SELECT '{REWRITE}') TO STDOUT"),
        ))
        .await;
    client.send(Bind::new_statement("copy")).await;
    client.send(Execute::new()).await;
    client.send(Sync).await;
    client.try_process().await.unwrap();

    let messages = client.read_until('Z').await.unwrap();
    let data = messages
        .iter()
        .find(|message| message.code() == 'd')
        .expect("COPY data");
    assert!(
        String::from_utf8_lossy(&data.payload()).contains(REWRITTEN),
        "{data:?}"
    );
}
