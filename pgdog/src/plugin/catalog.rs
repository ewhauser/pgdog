//! The catalog plugins receive, built from PgDog's schema.
use pgdog_plugin::{
    Catalog, CatalogParts,
    catalog::{Column, Function, Operator, Relation, RelationKind, SecurityLabel},
};

use crate::backend::Schema;

/// Build the catalog of one database.
pub(super) fn from_schema(schema: &Schema, parts: CatalogParts) -> Catalog {
    let mut relations: Vec<_> = schema
        .relations
        .values()
        .flat_map(|relations| relations.values())
        .map(relation)
        .collect();
    // Stable order, independent of hashing.
    relations.sort_by(|a, b| (&a.schema, &a.name).cmp(&(&b.schema, &b.name)));

    let mut catalog = Catalog::new(parts);
    catalog.search_path = schema.search_path.clone();
    catalog.relations = relations;
    catalog.functions = schema.functions.iter().map(function).collect();
    catalog.system_functions = schema.system_functions.clone();
    catalog.operators = schema.operators.iter().map(operator).collect();
    catalog
}

fn relation(relation: &pgdog_stats::Relation) -> Relation {
    let kind = match relation.type_.as_str() {
        "table" => RelationKind::Table,
        "partitioned table" => RelationKind::PartitionedTable,
        "view" => RelationKind::View,
        "materialized view" => RelationKind::MaterializedView,
        "foreign table" => RelationKind::ForeignTable,
        _ => RelationKind::Other,
    };

    let mut out = Relation::new(&relation.schema, &relation.name, kind);
    out.columns = relation.columns.values().map(column).collect();
    out.parent = relation
        .parent_table_schema
        .clone()
        .zip(relation.parent_table_name.clone());
    out.definition = relation.definition.clone();
    out.options = relation.options.clone();
    out
}

fn column(column: &pgdog_stats::Column) -> Column {
    let mut out = Column::new(&column.column_name, &column.data_type);
    out.type_name = column.type_name.clone();
    out.type_oid = column.type_oid;
    out.is_primary_key = column.is_primary_key;
    out.comment = column.comment.clone();
    out.security_labels = column
        .security_labels
        .iter()
        .map(|label| SecurityLabel::new(&label.provider, &label.label))
        .collect();
    out
}

fn function(function: &pgdog_stats::Function) -> Function {
    let mut out = Function::new(function.oid as u32, &function.schema, &function.name);
    out.kind = function.kind.clone();
    out.argument_types = function.argument_types.clone();
    out.argument_names = function.argument_names.clone();
    out.argument_defaults = function.argument_defaults.max(0) as u16;
    out.variadic = function.variadic;
    out.return_type = function.return_type.clone();
    out.result = function.result.clone();
    out.returns_set = function.returns_set;
    out.output_names = function.output_names.clone();
    out.output_types = function.output_types.clone();
    out.language = function.language.clone();
    out.source = function.source.clone();
    out.sql_body = function.sql_body.clone();
    out.volatility = function.volatility.clone();
    out.security_definer = function.security_definer;
    out.strict = function.strict;
    out.config = function.config.clone();
    out.extension = function.extension.clone();
    out
}

fn operator(operator: &pgdog_stats::Operator) -> Operator {
    let mut out = Operator::new(operator.oid as u32, &operator.schema, &operator.name);
    out.left_type = operator.left_type.clone();
    out.right_type = operator.right_type.clone();
    out.result_type = operator.result_type.clone();
    out.function_oid = operator.function_oid as u32;
    out.function_schema = operator.function_schema.clone();
    out.function_name = operator.function_name.clone();
    out
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::backend::schema::Relation as PgdogRelation;
    use indexmap::IndexMap;

    #[test]
    fn test_from_schema() {
        let mut columns = IndexMap::new();
        columns.insert(
            "ssn".to_string(),
            crate::backend::schema::columns::Column::from(pgdog_stats::Column {
                column_name: "ssn".into(),
                data_type: "text".into(),
                comment: Some("pii".into()),
                ..Default::default()
            }),
        );
        let people = PgdogRelation::test_table("public", "people", columns);
        let schema = Schema::from_parts(
            vec!["public".into()],
            [(("public".into(), "people".into()), people)].into(),
        );

        let catalog = from_schema(&schema, CatalogParts::COLUMNS);
        assert_eq!(catalog.parts, CatalogParts::COLUMNS);
        assert_eq!(catalog.search_path, ["public"]);
        let people = &catalog.relations[0];
        assert_eq!(people.kind, RelationKind::Table);
        assert_eq!(people.columns[0].name, "ssn");
        assert_eq!(people.columns[0].comment.as_deref(), Some("pii"));
    }
}
