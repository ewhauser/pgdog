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
