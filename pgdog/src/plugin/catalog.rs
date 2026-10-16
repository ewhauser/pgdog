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

    Catalog {
        parts,
        search_path: schema.search_path.clone(),
        relations,
        functions: schema.functions.iter().map(function).collect(),
        system_functions: schema.system_functions.clone(),
        operators: schema.operators.iter().map(operator).collect(),
    }
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

    Relation {
        schema: relation.schema.clone(),
        name: relation.name.clone(),
        kind,
        columns: relation.columns.values().map(column).collect(),
        parent: relation
            .parent_table_schema
            .clone()
            .zip(relation.parent_table_name.clone()),
        definition: relation.definition.clone(),
        options: relation.options.clone(),
    }
}

fn column(column: &pgdog_stats::Column) -> Column {
    Column {
        name: column.column_name.clone(),
        data_type: column.data_type.clone(),
        type_name: column.type_name.clone(),
        is_primary_key: column.is_primary_key,
        comment: column.comment.clone(),
        security_labels: column
            .security_labels
            .iter()
            .map(|label| SecurityLabel {
                provider: label.provider.clone(),
                label: label.label.clone(),
            })
            .collect(),
    }
}

fn function(function: &pgdog_stats::Function) -> Function {
    Function {
        oid: function.oid as u32,
        schema: function.schema.clone(),
        name: function.name.clone(),
        kind: function.kind.clone(),
        argument_types: function.argument_types.clone(),
        argument_names: function.argument_names.clone(),
        argument_defaults: function.argument_defaults.max(0) as u16,
        variadic: function.variadic,
        return_type: function.return_type.clone(),
        result: function.result.clone(),
        returns_set: function.returns_set,
        output_names: function.output_names.clone(),
        output_types: function.output_types.clone(),
        language: function.language.clone(),
        source: function.source.clone(),
        sql_body: function.sql_body.clone(),
        volatility: function.volatility.clone(),
        security_definer: function.security_definer,
        strict: function.strict,
        config: function.config.clone(),
        extension: function.extension.clone(),
    }
}

fn operator(operator: &pgdog_stats::Operator) -> Operator {
    Operator {
        oid: operator.oid as u32,
        schema: operator.schema.clone(),
        name: operator.name.clone(),
        left_type: operator.left_type.clone(),
        right_type: operator.right_type.clone(),
        result_type: operator.result_type.clone(),
        function_oid: operator.function_oid as u32,
        function_schema: operator.function_schema.clone(),
        function_name: operator.function_name.clone(),
    }
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
