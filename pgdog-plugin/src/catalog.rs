//! Database catalog sent to plugins.
//!
//! Plugins with [`crate::Capabilities::CATALOG`] receive a [`Catalog`] for each
//! database when PgDog loads its schema: at startup, after configuration
//! reloads, and after DDL when `reload_schema_on_ddl` is enabled. PgDog sends a
//! database's catalog again only if it changed.
//!
//! Relations are always included. Plugins ask for more with
//! [`crate::Plugin::catalog_parts`]; PgDog loads the union of what loaded plugins
//! ask for, so plugins should check [`Catalog::parts`] rather than assume.
//!
//! Names in view definitions, function bodies and type names are
//! schema-qualified (everything outside `pg_catalog`), independent of any
//! `search_path`.
//!
//! The catalog is passed by reference and is only valid during the call;
//! plugins copy what they need. It's a plain Rust type, which is safe across
//! the plugin boundary because plugins are built with the same compiler and
//! `pgdog-plugin` version as PgDog.
use std::ops::{BitOr, BitOrAssign};

/// Optional parts of the catalog.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct CatalogParts(u32);

impl CatalogParts {
    /// Relations and the columns PgDog itself loads.
    pub const NONE: Self = Self(0);
    /// Every column from `pg_attribute`, including those the role PgDog loads
    /// the schema with can't read, with type names, comments and security labels.
    pub const COLUMNS: Self = Self(1 << 0);
    /// Definitions and options of views and materialized views.
    pub const VIEWS: Self = Self(1 << 1);
    /// Functions and procedures outside `pg_catalog`, and the names of the
    /// functions in `pg_catalog`.
    pub const FUNCTIONS: Self = Self(1 << 2);
    /// Operators outside `pg_catalog`.
    pub const OPERATORS: Self = Self(1 << 3);
    /// Everything.
    pub const ALL: Self = Self(0b1111);

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// All parts in `other` are present in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for CatalogParts {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for CatalogParts {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// The catalog of one database.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalog {
    /// Parts that were loaded.
    pub parts: CatalogParts,
    /// `search_path` of the role PgDog loaded the schema with.
    pub search_path: Vec<String>,
    /// Tables, partitioned tables, views, materialized views and foreign tables.
    pub relations: Vec<Relation>,
    /// Functions and procedures outside `pg_catalog`. Requires [`CatalogParts::FUNCTIONS`].
    pub functions: Vec<Function>,
    /// Names of the functions in `pg_catalog`, sorted. Requires [`CatalogParts::FUNCTIONS`].
    pub system_functions: Vec<String>,
    /// Operators outside `pg_catalog`. Requires [`CatalogParts::OPERATORS`].
    pub operators: Vec<Operator>,
}

/// Kind of relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelationKind {
    Table,
    PartitionedTable,
    View,
    MaterializedView,
    ForeignTable,
    Other,
}

/// A relation from `pg_class`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relation {
    pub schema: String,
    pub name: String,
    pub kind: RelationKind,
    /// Columns in ordinal order.
    pub columns: Vec<Column>,
    /// Parent table `(schema, name)`, for partitions.
    pub parent: Option<(String, String)>,
    /// Query of a view or materialized view. Requires [`CatalogParts::VIEWS`].
    pub definition: Option<String>,
    /// `reloptions`, e.g. `security_barrier=true`. Requires [`CatalogParts::VIEWS`].
    pub options: Vec<String>,
}

/// A column of a relation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    /// As in `information_schema.columns.data_type`.
    pub data_type: String,
    /// From `format_type`, without typmod, e.g. `public.mood` or `text[]`.
    /// Requires [`CatalogParts::COLUMNS`].
    pub type_name: String,
    /// Type OID, as Postgres reports it in `RowDescription`: the base type for
    /// domains. Requires [`CatalogParts::COLUMNS`].
    pub type_oid: u32,
    pub is_primary_key: bool,
    /// `COMMENT ON COLUMN`. Requires [`CatalogParts::COLUMNS`].
    pub comment: Option<String>,
    /// `SECURITY LABEL ON COLUMN`, one per provider. Requires [`CatalogParts::COLUMNS`].
    pub security_labels: Vec<SecurityLabel>,
}

/// A security label set with `SECURITY LABEL FOR <provider> ON ...`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SecurityLabel {
    pub provider: String,
    pub label: String,
}

/// A function or procedure from `pg_proc`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Function {
    pub oid: u32,
    pub schema: String,
    pub name: String,
    /// `function`, `procedure`, `aggregate` or `window`.
    pub kind: String,
    /// Input argument types, in order. Includes `VARIADIC` and arguments with defaults.
    pub argument_types: Vec<String>,
    /// Input argument names, in order; empty for unnamed arguments.
    pub argument_names: Vec<String>,
    /// Number of trailing input arguments that have defaults.
    pub argument_defaults: u16,
    /// The last input argument is `VARIADIC`.
    pub variadic: bool,
    pub return_type: String,
    /// `RETURNS` clause, e.g. `SETOF text` or `TABLE(id bigint)`.
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
    /// `BEGIN ATOMIC` / `RETURN` body. Postgres 14+.
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

/// An operator from `pg_operator`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Operator {
    pub oid: u32,
    pub schema: String,
    pub name: String,
    /// Left operand type; `None` for prefix operators.
    pub left_type: Option<String>,
    pub right_type: Option<String>,
    pub result_type: String,
    /// Function implementing the operator.
    pub function_oid: u32,
    pub function_schema: String,
    pub function_name: String,
}
