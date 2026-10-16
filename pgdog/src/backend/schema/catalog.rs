//! Catalog details loaded only when a plugin needs the schema: view
//! definitions, functions, operators and the names of system functions.
//!
//! Every query runs with an empty `search_path`, so names in view definitions,
//! function bodies and type names come back schema-qualified (everything outside
//! `pg_catalog`), independent of the loading role's settings.
use pgdog_stats::{Function, Operator};
use serde::de::DeserializeOwned;

use super::Error;
use crate::backend::Server;

static VIEWS: &str = include_str!("views.sql");
static FUNCTIONS: &str = include_str!("functions.sql");
static OPERATORS: &str = include_str!("operators.sql");

/// Definition of a view or materialized view.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct View {
    pub(crate) schema: String,
    pub(crate) name: String,
    pub(crate) definition: Option<String>,
    pub(crate) options: Vec<String>,
}

/// Run a query with an empty `search_path`, restoring it afterwards.
///
/// Outside a transaction, `SET LOCAL` lasts until the end of the implicit
/// transaction of the multi-statement query. Inside one, a savepoint undoes it.
pub(super) async fn fetch_qualified<T: From<crate::net::messages::DataRow>>(
    server: &mut Server,
    query: &str,
) -> Result<Vec<T>, Error> {
    let query = if server.in_transaction() {
        format!(
            "SAVEPOINT pgdog_catalog; SET LOCAL search_path TO ''; {query}; \
             ROLLBACK TO SAVEPOINT pgdog_catalog; RELEASE SAVEPOINT pgdog_catalog"
        )
    } else {
        format!("SET LOCAL search_path TO ''; {query}")
    };
    server.fetch_all(query.as_str()).await
}

/// Fetch rows that are a single JSON object each.
async fn fetch_json<T: DeserializeOwned>(
    server: &mut Server,
    query: &str,
) -> Result<Vec<T>, Error> {
    fetch_qualified::<String>(server, query)
        .await?
        .iter()
        .map(|row| serde_json::from_str(row).map_err(Error::from))
        .collect()
}

/// Load view and materialized view definitions.
pub(crate) async fn views(server: &mut Server) -> Result<Vec<View>, Error> {
    fetch_json(server, VIEWS).await
}

/// Load non-system functions.
pub(crate) async fn functions(server: &mut Server) -> Result<Vec<Function>, Error> {
    let version = server
        .fetch_all::<String>("SELECT current_setting('server_version_num')")
        .await?
        .pop()
        .and_then(|version| version.parse::<i64>().ok())
        .unwrap_or_default();
    // pg_get_function_sqlbody was added in Postgres 14.
    let sql_body = if version >= 140000 {
        "pg_catalog.pg_get_function_sqlbody(p.oid)"
    } else {
        "NULL"
    };
    fetch_json(server, &FUNCTIONS.replace("{sql_body}", sql_body)).await
}

/// Names of the functions in `pg_catalog`.
pub(crate) async fn system_functions(server: &mut Server) -> Result<Vec<String>, Error> {
    server
        .fetch_all(
            "SELECT DISTINCT proname::text FROM pg_catalog.pg_proc \
             WHERE pronamespace = 'pg_catalog'::regnamespace ORDER BY 1",
        )
        .await
}

/// Load non-system operators.
pub(crate) async fn operators(server: &mut Server) -> Result<Vec<Operator>, Error> {
    fetch_json(server, OPERATORS).await
}
