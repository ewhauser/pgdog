//! Schema operations.
pub(crate) mod cache;
pub(crate) mod catalog;
pub(crate) mod columns;
pub(crate) mod relation;
pub(crate) mod sync;

pub(crate) use pgdog_stats::{
    Relation as StatsRelation, Relations as StatsRelations, Schema as StatsSchema, SchemaInner,
};
use serde::{Deserialize, Serialize};
use std::ops::DerefMut;
use std::{collections::HashMap, ops::Deref};
use tracing::info;

pub(crate) use cache::SchemaCache;
pub(crate) use relation::Relation;

use super::{Cluster, Error, Server, pool::Request};
use crate::frontend::router::parser::Table;
use crate::net::parameter::ParameterValue;
use crate::plugin;
use pgdog_plugin::Capabilities;
use sync::ShardConfig;

static SETUP: &str = include_str!("setup.sql");

/// How much of the catalog to load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CatalogDetail {
    /// What PgDog itself needs: relations and the columns the loading role can see.
    Standard,
    /// Everything plugins may need: columns from `pg_attribute`, view definitions,
    /// comments, security labels, functions and operators.
    Full,
}

impl CatalogDetail {
    /// The full catalog is loaded only for plugins that receive schema snapshots.
    pub(crate) fn current() -> Self {
        if plugin::has_capability(Capabilities::SCHEMA) {
            Self::Full
        } else {
            Self::Standard
        }
    }
}

/// Load schema from database.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Hash)]
pub(crate) struct Schema {
    inner: StatsSchema,
}

impl Deref for Schema {
    type Target = StatsSchema;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Schema {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Schema {
    /// Load schema from a server connection.
    pub(crate) async fn load(server: &mut Server) -> Result<Self, Error> {
        Self::load_with(server, CatalogDetail::current()).await
    }

    /// Load schema from a server connection, with the given catalog detail.
    pub(crate) async fn load_with(
        server: &mut Server,
        detail: CatalogDetail,
    ) -> Result<Self, Error> {
        let mut relations: StatsRelations = HashMap::new();
        for relation in Relation::load(server, detail).await? {
            relations
                .entry(relation.schema().to_owned())
                .or_default()
                .insert(relation.name.clone(), relation.into());
        }

        let search_path = server
            .fetch_all::<String>("SHOW search_path")
            .await?
            .pop()
            .unwrap_or(String::from("$user, public"))
            .split(",")
            .map(|p| p.trim().replace("\"", ""))
            .collect();

        let aggregate_functions = server
            .fetch_all::<String>(
                "SELECT DISTINCT proname FROM pg_proc INNER JOIN pg_aggregate ON oid = aggfnoid",
            )
            .await?
            .into_iter()
            .collect();

        let (functions, operators, system_functions) = match detail {
            CatalogDetail::Standard => (Vec::new(), Vec::new(), Vec::new()),
            CatalogDetail::Full => (
                catalog::functions(server).await?,
                catalog::operators(server).await?,
                catalog::system_functions(server).await?,
            ),
        };

        let inner = SchemaInner {
            search_path,
            relations,
            aggregate_functions,
            full_catalog: detail == CatalogDetail::Full,
            functions,
            operators,
            system_functions,
        };

        Ok(Self {
            inner: StatsSchema::new(inner),
        })
    }

    /// The schema has been loaded from the database.
    pub(crate) fn is_loaded(&self) -> bool {
        !self.inner.relations.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn from_parts(
        search_path: Vec<String>,
        relations: HashMap<(String, String), Relation>,
    ) -> Self {
        Self::from_parts_with_agg(search_path, relations, Vec::new())
    }

    #[cfg(test)]
    pub(crate) fn from_parts_with_agg(
        search_path: Vec<String>,
        relations: HashMap<(String, String), Relation>,
        aggregate_functions: Vec<String>,
    ) -> Self {
        let mut nested: StatsRelations = HashMap::new();
        for ((schema, name), relation) in relations {
            nested
                .entry(schema)
                .or_default()
                .insert(name, relation.into());
        }
        Self {
            inner: StatsSchema::new(SchemaInner {
                search_path,
                relations: nested,
                aggregate_functions: aggregate_functions.into_iter().collect(),
                ..Default::default()
            }),
        }
    }

    /// Install PgDog functions and schema.
    pub(crate) async fn setup(server: &mut Server) -> Result<(), Error> {
        server.execute_checked(SETUP).await?;
        Ok(())
    }

    async fn install_server(server: &mut Server) -> Result<(), Error> {
        Self::setup(server).await?;
        let schema = Self::load(server).await?;

        let tables = schema
            .tables()
            .iter()
            .cloned()
            // Skip partition children: PostgreSQL forbids ALTER TABLE <child>
            // DROP IDENTITY (error 42P16). The partitioned parent's
            // install_sharded_sequence call handles the entire hierarchy because
            // DROP IDENTITY and SET DEFAULT on a partitioned parent propagate
            // to all partition children automatically.
            .filter(|table| {
                !matches!(table.schema.as_str(), "pgdog" | "pgdog_shadow")
                    && table.parent_table_name.is_none()
            })
            .collect::<Vec<_>>();

        info!(
            "[schema] checking {} tables for sharded sequences [{}]",
            tables.len(),
            server.addr(),
        );

        for table in tables {
            for column in table.columns().iter().filter(|column| {
                column.1.is_primary_key // Only primary keys.
                    && matches!(column.1.data_type.as_str(), "bigint" | "int8") // Only BIGINT.
                // Only the ones that rely on a sequence.
            }) {
                info!(
                    "[schema] creating sharded sequence for \"{}\".\"{}\".\"{}\"",
                    column.1.table_schema, column.1.table_name, column.1.column_name,
                );

                let query = format!(
                    "SELECT pgdog.install_sharded_sequence('{}', '{}', '{}')",
                    column.1.table_schema, column.1.table_name, column.1.column_name,
                );

                server.execute_checked(&query).await?;
            }
        }

        info!("[schema] sharded sequence check done [{}]", server.addr());

        Ok(())
    }

    /// Install PgDog-specific functions and triggers.
    pub(crate) async fn install(cluster: &Cluster) -> Result<(), Error> {
        let shards = cluster.shards();
        let sharded_tables = cluster.sharded_tables().tables();

        if sharded_tables.is_empty() {
            return Ok(());
        }

        // Sync configuration.
        ShardConfig::sync_all(cluster).await?;

        for shard in shards {
            let mut server = shard.primary(&Request::default()).await?;
            Self::install_server(&mut server).await?;
        }

        Ok(())
    }

    /// Get table by name.
    ///
    /// If the table has an explicit schema, looks up in that schema directly.
    /// Otherwise, iterates through the search_path to find the first match.
    pub(crate) fn table(
        &self,
        table: Table<'_>,
        user: &str,
        search_path: Option<&ParameterValue>,
    ) -> Option<&StatsRelation> {
        if let Some(schema) = table.schema {
            return self.inner.get(schema, table.name);
        }

        for schema in self.resolve_search_path(user, search_path) {
            if let Some(relation) = self.inner.get(schema, table.name) {
                return Some(relation);
            }
        }

        None
    }

    fn resolve_search_path<'a>(
        &'a self,
        user: &'a str,
        search_path: Option<&'a ParameterValue>,
    ) -> Vec<&'a str> {
        let path: &[String] = match search_path {
            Some(ParameterValue::Tuple(overriden)) => overriden.as_slice(),
            _ => &self.inner.search_path,
        };

        path.iter()
            .map(|p| if p == "$user" { user } else { p.as_str() })
            .collect()
    }

    /// Get all tables.
    pub(crate) fn tables(&self) -> Vec<&StatsRelation> {
        self.inner
            .relations
            .values()
            .flat_map(|tables| tables.values())
            .filter(|relation| relation.is_table())
            .collect()
    }

    /// Get search path components.
    pub(crate) fn search_path(&self) -> &[String] {
        &self.inner.search_path
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use indexmap::IndexMap;

    use crate::backend::pool::Request;
    use crate::backend::schema::relation::Relation;
    use crate::backend::server::test::test_server;
    use crate::frontend::router::parser::Table;
    use crate::net::parameter::ParameterValue;

    use super::super::pool::test::pool;
    use super::Schema;
    use pgdog_stats::SecurityLabel;

    #[tokio::test]
    async fn test_schema() {
        let pool = pool();
        let mut conn = pool.get(&Request::default()).await.unwrap();
        conn.execute("DROP SCHEMA IF EXISTS pgdog CASCADE")
            .await
            .unwrap();
        let _schema = Schema::load(&mut conn).await.unwrap();
        Schema::setup(&mut conn).await.unwrap();
        let schema = Schema::load(&mut conn).await.unwrap();
        let seq = schema
            .relations
            .values()
            .flat_map(|tables| tables.values())
            .filter(|relation| relation.is_sequence())
            .find(|seq| seq.schema() == "pgdog")
            .cloned()
            .unwrap();
        assert!(
            matches!(
                seq.name.as_str(),
                "unique_id_seq" | "validator_bigint_id_seq"
            ),
            "{}",
            seq.name
        );

        let server_ok = conn.fetch_all::<i32>("SELECT 1 AS one").await.unwrap();
        assert_eq!(server_ok.first().unwrap().clone(), 1);

        let debug = conn
            .fetch_all::<String>("SELECT pgdog.debug()")
            .await
            .unwrap();
        assert!(debug.first().unwrap().contains("PgDog Debug"));
    }

    #[tokio::test]
    async fn test_install_next_id_seq() {
        use crate::backend::server::test::test_server;

        let mut conn = test_server().await;

        // Use a dedicated schema to avoid conflicts with test_schema
        // which drops the pgdog schema.
        conn.execute_checked("CREATE SCHEMA IF NOT EXISTS pgdog_test")
            .await
            .unwrap();

        // Install pgdog schema (CREATE OR REPLACE is idempotent).
        Schema::setup(&mut conn).await.unwrap();

        // Ensure shard config exists.
        let count = conn
            .fetch_all::<i64>("SELECT COUNT(*) FROM pgdog.config")
            .await
            .unwrap();
        if count.first().copied() == Some(0) {
            conn.execute_checked("INSERT INTO pgdog.config (shard, shards) VALUES (0, 1)")
                .await
                .unwrap();
        }

        // Clean up from previous runs and create a test table with BIGSERIAL primary key.
        conn.execute_checked("DROP TABLE IF EXISTS pgdog_test.ids")
            .await
            .unwrap();
        conn.execute_checked("CREATE TABLE pgdog_test.ids (id BIGSERIAL PRIMARY KEY, value TEXT)")
            .await
            .unwrap();

        // Install the sharded sequence via install_next_id_seq.
        let result = conn
            .fetch_all::<String>("SELECT pgdog.install_next_id_seq('pgdog_test', 'ids', 'id')")
            .await
            .unwrap();
        assert!(
            result.first().unwrap().contains("installed"),
            "{}",
            result.first().unwrap()
        );

        // Insert rows and collect generated IDs.
        conn.execute_checked("INSERT INTO pgdog_test.ids (value) VALUES ('a')")
            .await
            .unwrap();
        conn.execute_checked("INSERT INTO pgdog_test.ids (value) VALUES ('b')")
            .await
            .unwrap();
        conn.execute_checked("INSERT INTO pgdog_test.ids (value) VALUES ('c')")
            .await
            .unwrap();

        let ids = conn
            .fetch_all::<i64>("SELECT id FROM pgdog_test.ids ORDER BY id")
            .await
            .unwrap();

        assert_eq!(ids.len(), 3);

        // All IDs should be unique.
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3, "IDs are not unique: {:?}", ids);

        // Clean up.
        conn.execute_checked("DROP SCHEMA pgdog_test CASCADE")
            .await
            .unwrap();
    }

    #[test]
    fn test_resolve_search_path_default() {
        let schema = Schema::from_parts(vec!["$user".into(), "public".into()], HashMap::new());

        let resolved = schema.resolve_search_path("alice", None);
        assert_eq!(resolved, vec!["alice", "public"]);
    }

    #[test]
    fn test_resolve_search_path_override() {
        let schema = Schema::from_parts(vec!["$user".into(), "public".into()], HashMap::new());

        let override_path = ParameterValue::Tuple(vec!["custom".into(), "other".into()]);
        let resolved = schema.resolve_search_path("alice", Some(&override_path));
        assert_eq!(resolved, vec!["custom", "other"]);
    }

    #[test]
    fn test_resolve_search_path_override_with_user() {
        let schema = Schema::from_parts(vec!["public".into()], HashMap::new());

        let override_path = ParameterValue::Tuple(vec!["$user".into(), "app".into()]);
        let resolved = schema.resolve_search_path("bob", Some(&override_path));
        assert_eq!(resolved, vec!["bob", "app"]);
    }

    #[test]
    fn test_table_with_explicit_schema() {
        let relations: HashMap<(String, String), Relation> = HashMap::from([
            (
                ("myschema".into(), "users".into()),
                Relation::test_table("myschema", "users", IndexMap::new()),
            ),
            (
                ("public".into(), "users".into()),
                Relation::test_table("public", "users", IndexMap::new()),
            ),
        ]);
        let schema = Schema::from_parts(vec!["$user".into(), "public".into()], relations);

        let table = Table {
            name: "users",
            schema: Some("myschema"),
            alias: None,
        };

        let result = schema.table(table, "alice", None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().schema(), "myschema");
    }

    #[test]
    fn test_table_search_path_lookup() {
        let relations: HashMap<(String, String), Relation> = HashMap::from([(
            ("public".into(), "orders".into()),
            Relation::test_table("public", "orders", IndexMap::new()),
        )]);
        let schema = Schema::from_parts(vec!["$user".into(), "public".into()], relations);

        let table = Table {
            name: "orders",
            schema: None,
            alias: None,
        };

        // User schema "alice" doesn't have "orders", but "public" does
        let result = schema.table(table, "alice", None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().schema(), "public");
    }

    #[test]
    fn test_table_found_in_user_schema() {
        let relations: HashMap<(String, String), Relation> = HashMap::from([
            (
                ("alice".into(), "settings".into()),
                Relation::test_table("alice", "settings", IndexMap::new()),
            ),
            (
                ("public".into(), "settings".into()),
                Relation::test_table("public", "settings", IndexMap::new()),
            ),
        ]);
        let schema = Schema::from_parts(vec!["$user".into(), "public".into()], relations);

        let table = Table {
            name: "settings",
            schema: None,
            alias: None,
        };

        // Should find in "alice" schema first (due to $user)
        let result = schema.table(table, "alice", None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().schema(), "alice");
    }

    #[test]
    fn test_table_not_found() {
        let relations: HashMap<(String, String), Relation> = HashMap::from([(
            ("public".into(), "users".into()),
            Relation::test_table("public", "users", IndexMap::new()),
        )]);
        let schema = Schema::from_parts(vec!["$user".into(), "public".into()], relations);

        let table = Table {
            name: "nonexistent",
            schema: None,
            alias: None,
        };

        let result = schema.table(table, "alice", None);
        assert!(result.is_none());
    }

    #[test]
    fn test_table_with_overridden_search_path() {
        let relations: HashMap<(String, String), Relation> = HashMap::from([
            (
                ("custom".into(), "data".into()),
                Relation::test_table("custom", "data", IndexMap::new()),
            ),
            (
                ("public".into(), "data".into()),
                Relation::test_table("public", "data", IndexMap::new()),
            ),
        ]);
        let schema = Schema::from_parts(vec!["$user".into(), "public".into()], relations);

        let table = Table {
            name: "data",
            schema: None,
            alias: None,
        };

        // Override search_path to look in "custom" first
        let override_path = ParameterValue::Tuple(vec!["custom".into(), "public".into()]);
        let result = schema.table(table, "alice", Some(&override_path));
        assert!(result.is_some());
        assert_eq!(result.unwrap().schema(), "custom");
    }

    #[tokio::test]
    async fn test_identity_column() {
        let mut server = test_server().await;
        // Drop and recreate the schema so the test is repeatable.
        server
            .execute_checked("DROP SCHEMA IF EXISTS pgdog_schema_test CASCADE")
            .await
            .unwrap();
        server
            .execute_checked("DROP SCHEMA IF EXISTS pgdog_shadow CASCADE")
            .await
            .unwrap();
        server
            .execute_checked(include_str!("test_schema.sql"))
            .await
            .unwrap();
        Schema::install_server(&mut server).await.unwrap();

        // Verify the partitioned parents had identity dropped and a sharded
        // sequence default installed. Children inherit the default from the
        // parent so they should NOT have been touched directly (which would
        // raise error 42P16).
        let parents = ["partitioned_identity", "partitioned_identity_compound"];
        for parent in parents {
            let identity: Vec<String> = server
                .fetch_all::<String>(&format!(
                    "SELECT is_identity FROM information_schema.columns \
                     WHERE table_schema = 'pgdog_schema_test' \
                     AND table_name = '{parent}' AND column_name = 'id'"
                ))
                .await
                .unwrap();
            assert_eq!(
                identity.first().map(String::as_str),
                Some("NO"),
                "{parent}.id should no longer be identity after install_server",
            );

            let default: Vec<String> = server
                .fetch_all::<String>(&format!(
                    "SELECT column_default FROM information_schema.columns \
                     WHERE table_schema = 'pgdog_schema_test' \
                     AND table_name = '{parent}' AND column_name = 'id'"
                ))
                .await
                .unwrap();
            assert!(
                default.first().is_some_and(|d| d.contains("next_id_seq")),
                "{parent}.id should have a next_id_seq default, got {:?}",
                default.first(),
            );
        }
    }

    #[tokio::test]
    async fn test_loading_aggregate_functions() {
        let mut server = test_server().await;
        server.execute_checked("BEGIN").await.unwrap();

        let schema = Schema::load(&mut server).await.unwrap();
        assert!(
            !schema
                .aggregate_functions
                .contains(&String::from("pgdog_sum"))
        );

        server
            .execute_checked("CREATE AGGREGATE pgdog_sum (int4) (sfunc = int4_sum, stype = bigint)")
            .await
            .unwrap();
        let schema = Schema::load(&mut server).await.unwrap();
        assert!(
            schema
                .aggregate_functions
                .contains(&String::from("pgdog_sum"))
        );
    }

    #[tokio::test]
    async fn test_load_full_catalog() {
        use super::CatalogDetail;

        let mut server = test_server().await;
        server.execute_checked("BEGIN").await.unwrap();
        server
            .execute_checked(
                "CREATE SCHEMA catalog_test;
                 CREATE TABLE catalog_test.people (id BIGINT PRIMARY KEY, ssn VARCHAR(11), tags TEXT[]);
                 COMMENT ON COLUMN catalog_test.people.ssn IS 'Social security number. pgdog:tag=pii.ssn';
                 CREATE VIEW catalog_test.people_ssn WITH (security_barrier) AS SELECT id, ssn FROM catalog_test.people;
                 CREATE MATERIALIZED VIEW catalog_test.people_count AS SELECT count(*) AS n FROM catalog_test.people;
                 CREATE FUNCTION catalog_test.last4(value TEXT, keep INT DEFAULT 4) RETURNS TEXT
                     LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT right(value, keep) $$;
                 CREATE FUNCTION catalog_test.ssns() RETURNS TABLE (person BIGINT, ssn TEXT)
                     LANGUAGE sql STABLE SECURITY DEFINER SET search_path = catalog_test
                     BEGIN ATOMIC SELECT id, ssn FROM catalog_test.people; END;
                 CREATE FUNCTION catalog_test.same(a TEXT, b TEXT) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT a = b';
                 CREATE OPERATOR catalog_test.=== (LEFTARG = TEXT, RIGHTARG = TEXT, FUNCTION = catalog_test.same);
                 CREATE ROLE catalog_test_reader NOLOGIN;
                 GRANT USAGE ON SCHEMA catalog_test TO catalog_test_reader;
                 GRANT SELECT (id) ON catalog_test.people TO catalog_test_reader",
            )
            .await
            .unwrap();
        // Vanilla Postgres has no label provider, so add the label directly.
        server
            .execute_checked(
                "INSERT INTO pg_seclabel VALUES \
                 ('catalog_test.people'::regclass, 'pg_class'::regclass, 2, 'pgdog', 'pii.ssn')",
            )
            .await
            .unwrap();

        let standard = Schema::load_with(&mut server, CatalogDetail::Standard)
            .await
            .unwrap();
        assert!(!standard.full_catalog);
        assert!(standard.functions.is_empty());
        let people = standard.get("catalog_test", "people").unwrap();
        assert!(people.definition.is_none());
        assert_eq!(people.columns["ssn"].comment, None);

        let full = Schema::load_with(&mut server, CatalogDetail::Full)
            .await
            .unwrap();
        assert!(full.full_catalog);

        let people = full.get("catalog_test", "people").unwrap();
        let columns: Vec<_> = people.column_names().collect();
        assert_eq!(columns, ["id", "ssn", "tags"]);
        let ssn = &people.columns["ssn"];
        // data_type matches information_schema; type_name is format_type.
        assert_eq!(ssn.data_type, "character varying");
        assert_eq!(ssn.type_name, "character varying");
        assert_eq!(people.columns["tags"].data_type, "ARRAY");
        assert_eq!(people.columns["tags"].type_name, "text[]");
        assert!(people.columns["id"].is_primary_key);
        assert_eq!(
            ssn.comment.as_deref(),
            Some("Social security number. pgdog:tag=pii.ssn")
        );
        assert_eq!(
            ssn.security_labels,
            [SecurityLabel {
                provider: "pgdog".into(),
                label: "pii.ssn".into(),
            }]
        );

        // Definitions are schema-qualified regardless of the search_path.
        let view = full.get("catalog_test", "people_ssn").unwrap();
        assert!(view.is_view());
        let definition = view.definition.as_deref().unwrap();
        assert!(
            definition.contains("FROM catalog_test.people"),
            "{definition}"
        );
        assert_eq!(view.options, ["security_barrier=true"]);
        let matview = full.get("catalog_test", "people_count").unwrap();
        assert!(matview.is_materialized_view());
        assert!(matview.definition.is_some());

        let function = |name: &str| {
            full.functions
                .iter()
                .find(|function| function.schema == "catalog_test" && function.name == name)
                .unwrap()
        };
        let last4 = function("last4");
        assert_eq!(last4.kind, "function");
        assert_eq!(last4.language, "sql");
        assert_eq!(last4.argument_types, ["text", "integer"]);
        assert_eq!(last4.argument_names, ["value", "keep"]);
        assert_eq!(last4.argument_defaults, 1);
        assert_eq!(last4.return_type, "text");
        assert!(!last4.returns_set);
        assert_eq!(last4.volatility, "immutable");
        assert!(last4.strict);
        assert!(!last4.security_definer);
        assert!(last4.source.contains("right(value, keep)"));
        assert!(last4.sql_body.is_none());
        assert!(last4.config.is_empty());

        let ssns = function("ssns");
        assert!(ssns.returns_set);
        assert!(ssns.security_definer);
        assert_eq!(ssns.result, "TABLE(person bigint, ssn text)");
        assert_eq!(ssns.output_names, ["person", "ssn"]);
        assert_eq!(ssns.output_types, ["bigint", "text"]);
        assert_eq!(ssns.config, ["search_path=catalog_test"]);
        let body = ssns.sql_body.as_deref().unwrap();
        assert!(body.contains("FROM catalog_test.people"), "{body}");

        let operator = full
            .operators
            .iter()
            .find(|operator| operator.schema == "catalog_test")
            .unwrap();
        assert_eq!(operator.name, "===");
        assert_eq!(operator.left_type.as_deref(), Some("text"));
        assert_eq!(operator.right_type.as_deref(), Some("text"));
        assert_eq!(operator.result_type, "boolean");
        assert_eq!(operator.function_schema, "catalog_test");
        assert_eq!(operator.function_name, "same");

        assert!(full.system_functions.iter().any(|name| name == "lower"));
        assert!(!full.system_functions.iter().any(|name| name == "last4"));

        // information_schema hides columns the role can't access; pg_attribute doesn't.
        server
            .execute_checked("SET LOCAL ROLE catalog_test_reader")
            .await
            .unwrap();
        let standard = Schema::load_with(&mut server, CatalogDetail::Standard)
            .await
            .unwrap();
        let visible: Vec<_> = standard
            .get("catalog_test", "people")
            .unwrap()
            .column_names()
            .collect();
        assert_eq!(visible, ["id"]);
        let full = Schema::load_with(&mut server, CatalogDetail::Full)
            .await
            .unwrap();
        let visible: Vec<_> = full
            .get("catalog_test", "people")
            .unwrap()
            .column_names()
            .collect();
        assert_eq!(visible, ["id", "ssn", "tags"]);

        // The empty search_path used for loading doesn't leak into the transaction.
        let search_path = server
            .fetch_all::<String>("SHOW search_path")
            .await
            .unwrap();
        assert_ne!(search_path, [String::from("\"\"")]);

        server.execute_checked("ROLLBACK").await.unwrap();
    }

    #[tokio::test]
    async fn test_load_full_catalog_outside_transaction() {
        use super::CatalogDetail;

        let mut server = test_server().await;
        let before = server
            .fetch_all::<String>("SHOW search_path")
            .await
            .unwrap();
        let schema = Schema::load_with(&mut server, CatalogDetail::Full)
            .await
            .unwrap();
        assert!(schema.full_catalog);
        assert!(!server.in_transaction());
        let after = server
            .fetch_all::<String>("SHOW search_path")
            .await
            .unwrap();
        assert_eq!(before, after);
    }
}
