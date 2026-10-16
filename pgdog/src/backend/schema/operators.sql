-- Operators outside the system schemas, with the function implementing each.
SELECT pg_catalog.json_build_object(
    'oid', o.oid::bigint,
    'schema', n.nspname,
    'name', o.oprname,
    'left_type', CASE WHEN o.oprleft <> 0 THEN pg_catalog.format_type(o.oprleft, NULL) END,
    'right_type', CASE WHEN o.oprright <> 0 THEN pg_catalog.format_type(o.oprright, NULL) END,
    'result_type', pg_catalog.format_type(o.oprresult, NULL),
    'function_oid', f.oid::bigint,
    'function_schema', fn.nspname,
    'function_name', f.proname
)::text
FROM
    pg_catalog.pg_operator o
JOIN
    pg_catalog.pg_namespace n ON n.oid = o.oprnamespace
JOIN
    pg_catalog.pg_proc f ON f.oid = o.oprcode::pg_catalog.oid
JOIN
    pg_catalog.pg_namespace fn ON fn.oid = f.pronamespace
WHERE
    n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY
    n.nspname, o.oprname, o.oid
