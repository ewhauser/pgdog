-- View and materialized view definitions.
SELECT pg_catalog.json_build_object(
    'schema', n.nspname,
    'name', c.relname,
    'definition', pg_catalog.pg_get_viewdef(c.oid),
    'options', COALESCE(c.reloptions, '{}')
)::text
FROM
    pg_catalog.pg_class c
JOIN
    pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE
    c.relkind IN ('v', 'm')
    AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY
    n.nspname, c.relname
