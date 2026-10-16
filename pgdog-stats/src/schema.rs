use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    ops::Deref,
    sync::Arc,
};

/// Schema name -> Table name -> Relation
pub type Relations = HashMap<String, HashMap<String, Relation>>;

/// The action to take when a referenced row is deleted or updated.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ForeignKeyAction {
    #[default]
    NoAction,
    Restrict,
    Cascade,
    SetNull,
    SetDefault,
}

impl ForeignKeyAction {
    /// Parse from PostgreSQL's information_schema representation.
    pub fn from_pg_string(s: &str) -> Self {
        match s {
            "CASCADE" => Self::Cascade,
            "SET NULL" => Self::SetNull,
            "SET DEFAULT" => Self::SetDefault,
            "RESTRICT" => Self::Restrict,
            _ => Self::NoAction,
        }
    }

    pub fn is_destructive_on_delete(&self) -> bool {
        matches!(self, Self::Cascade | Self::SetNull | Self::SetDefault)
    }
}

/// A foreign key reference to another table's column.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Hash)]
pub struct ForeignKey {
    pub schema: String,
    pub table: String,
    pub column: String,
    pub on_delete: ForeignKeyAction,
    pub on_update: ForeignKeyAction,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Hash)]
pub struct Column {
    pub table_catalog: String,
    pub table_schema: String,
    pub table_name: String,
    pub column_name: String,
    pub column_default: String,
    pub is_nullable: bool,
    pub data_type: String,
    pub ordinal_position: i32,
    pub is_primary_key: bool,
    pub foreign_keys: Vec<ForeignKey>,
    /// Type name from `format_type`, without typmod and schema-qualified unless
    /// it's in `pg_catalog`. Only loaded for plugins.
    #[serde(default)]
    pub type_name: String,
    /// `COMMENT ON COLUMN`. Only loaded for plugins.
    #[serde(default)]
    pub comment: Option<String>,
    /// `SECURITY LABEL ON COLUMN`, one per provider. Only loaded for plugins.
    #[serde(default)]
    pub security_labels: Vec<SecurityLabel>,
    /// Type OID, the base type for domains. Only loaded for plugins.
    #[serde(default)]
    pub type_oid: u32,
}

/// A security label set with `SECURITY LABEL FOR <provider> ON ...`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SecurityLabel {
    pub provider: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Relation {
    pub schema: String,
    pub name: String,
    pub type_: String,
    pub owner: String,
    pub persistence: String,
    pub access_method: String,
    pub description: String,
    pub oid: i32,
    /// Schema of the parent (partitioned) table, if this is a partition.
    pub parent_table_schema: Option<String>,
    /// Name of the parent (partitioned) table, if this is a partition.
    pub parent_table_name: Option<String>,
    /// Columns indexed by name, ordered by ordinal position.
    pub columns: IndexMap<String, Column>,
    /// Query of a view or materialized view, from `pg_get_viewdef`, with every
    /// name schema-qualified. Only loaded for plugins.
    #[serde(default)]
    pub definition: Option<String>,
    /// Storage and view options (`reloptions`), e.g. `security_barrier=true`.
    /// Only loaded for plugins.
    #[serde(default)]
    pub options: Vec<String>,
}

impl Hash for Relation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.schema.hash(state);
        self.name.hash(state);
        self.type_.hash(state);
        self.owner.hash(state);
        self.persistence.hash(state);
        self.access_method.hash(state);
        self.description.hash(state);
        self.oid.hash(state);
        self.parent_table_schema.hash(state);
        self.parent_table_name.hash(state);
        for (key, value) in &self.columns {
            key.hash(state);
            value.hash(state);
        }
        self.definition.hash(state);
        self.options.hash(state);
    }
}

impl Relation {
    /// Get schema where the table is located.
    pub fn schema(&self) -> &str {
        if self.schema.is_empty() {
            "public"
        } else {
            &self.schema
        }
    }

    /// This is an index.
    pub fn is_index(&self) -> bool {
        matches!(self.type_.as_str(), "index" | "partitioned index")
    }

    /// This is a table.
    pub fn is_table(&self) -> bool {
        matches!(self.type_.as_str(), "table" | "partitioned table")
    }

    /// This is a sequence.
    pub fn is_sequence(&self) -> bool {
        self.type_ == "sequence"
    }

    /// Columns by name, in ordinal position order.
    pub fn columns(&self) -> &IndexMap<String, Column> {
        &self.columns
    }

    /// Get ordered column names (in ordinal position order).
    pub fn column_names(&self) -> impl Iterator<Item = &str> {
        self.columns.keys().map(|s| s.as_str())
    }

    pub fn has_column(&self, name: &str) -> bool {
        self.columns.contains_key(name)
    }

    /// This is a view.
    pub fn is_view(&self) -> bool {
        self.type_ == "view"
    }

    /// This is a materialized view.
    pub fn is_materialized_view(&self) -> bool {
        self.type_ == "materialized view"
    }
}

/// A function or procedure from `pg_proc`, outside `pg_catalog` and
/// `information_schema`.
///
/// Type names come from `format_type`: without typmod, and schema-qualified
/// unless they're in `pg_catalog`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Function {
    pub oid: i64,
    pub schema: String,
    pub name: String,
    /// `function`, `procedure`, `aggregate` or `window`.
    pub kind: String,
    /// Input argument types, in order. Includes `VARIADIC` and arguments with defaults.
    pub argument_types: Vec<String>,
    /// Input argument names, in order; empty for unnamed arguments.
    pub argument_names: Vec<String>,
    /// Number of trailing input arguments that have defaults.
    pub argument_defaults: i32,
    /// The last input argument is `VARIADIC`.
    pub variadic: bool,
    pub return_type: String,
    /// `RETURNS` clause from `pg_get_function_result`, e.g. `SETOF text` or `TABLE(id bigint)`.
    pub result: String,
    pub returns_set: bool,
    /// Names of `OUT`, `INOUT` and `TABLE` columns, in order.
    pub output_names: Vec<String>,
    /// Types of `OUT`, `INOUT` and `TABLE` columns, in order.
    pub output_types: Vec<String>,
    /// `sql`, `plpgsql`, `c`, `internal`, ...
    pub language: String,
    /// `prosrc`: the body as written, or the link symbol for C functions.
    pub source: String,
    /// `BEGIN ATOMIC` / `RETURN` bodies from `pg_get_function_sqlbody`, with
    /// every name schema-qualified. Postgres 14+.
    pub sql_body: Option<String>,
    /// `immutable`, `stable` or `volatile`.
    pub volatility: String,
    pub security_definer: bool,
    pub strict: bool,
    /// `SET` clauses (`proconfig`), e.g. `search_path=public`.
    pub config: Vec<String>,
    /// Extension that owns this function, if any.
    pub extension: Option<String>,
}

/// An operator from `pg_operator`, outside `pg_catalog` and `information_schema`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Operator {
    pub oid: i64,
    pub schema: String,
    pub name: String,
    /// Left operand type; `None` for prefix operators.
    pub left_type: Option<String>,
    pub right_type: Option<String>,
    pub result_type: String,
    /// Function implementing the operator.
    pub function_oid: i64,
    pub function_schema: String,
    pub function_name: String,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SchemaInner {
    pub search_path: Vec<String>,
    pub relations: Relations,
    pub aggregate_functions: HashSet<String>,
    /// Non-system functions. Only loaded for plugins.
    #[serde(default)]
    pub functions: Vec<Function>,
    /// Non-system operators. Only loaded for plugins.
    #[serde(default)]
    pub operators: Vec<Operator>,
    /// Names of the functions in `pg_catalog`, sorted. Only loaded for plugins.
    #[serde(default)]
    pub system_functions: Vec<String>,
}

impl Hash for SchemaInner {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.search_path.hash(state);
        let mut entries: Vec<_> = self.relations.iter().collect();
        entries.sort_by_key(|(k, _)| *k);
        for (schema, tables) in entries {
            schema.hash(state);
            let mut table_entries: Vec<_> = tables.iter().collect();
            table_entries.sort_by_key(|(k, _)| *k);
            for (name, relation) in table_entries {
                name.hash(state);
                relation.hash(state);
            }
        }
        self.functions.hash(state);
        self.operators.hash(state);
        self.system_functions.hash(state);
    }
}

/// Load schema from database.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Schema {
    inner: Arc<SchemaInner>,
}

impl Hash for Schema {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl Schema {
    pub fn tables(&self) -> &Relations {
        &self.relations
    }

    /// Get a relation by schema and table name.
    pub fn get(&self, schema: &str, name: &str) -> Option<&Relation> {
        self.inner
            .relations
            .get(schema)
            .and_then(|tables| tables.get(name))
    }

    /// Returns true if a column is referenced by a foreign key whose ON DELETE
    /// action would be unsafe during a sharding-key row move.
    pub fn has_destructive_on_delete_reference(
        &self,
        schema: &str,
        table: &str,
        column: &str,
    ) -> bool {
        self.relations
            .values()
            .flat_map(|tables| tables.values())
            .flat_map(|relation| relation.columns.values())
            .flat_map(|column| column.foreign_keys.iter())
            .any(|foreign_key| {
                foreign_key.schema == schema
                    && foreign_key.table == table
                    && foreign_key.column == column
                    && foreign_key.on_delete.is_destructive_on_delete()
            })
    }
}

impl Deref for Schema {
    type Target = SchemaInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Schema {
    pub fn new(inner: SchemaInner) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}
