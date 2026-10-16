-- Functions and procedures outside the system schemas.
-- {sql_body} is pg_get_function_sqlbody(p.oid) on Postgres 14+, NULL before.
SELECT pg_catalog.json_build_object(
    'oid', p.oid::bigint,
    'schema', n.nspname,
    'name', p.proname,
    'kind', CASE p.prokind
        WHEN 'p' THEN 'procedure'
        WHEN 'a' THEN 'aggregate'
        WHEN 'w' THEN 'window'
        ELSE 'function'
    END,
    'argument_types', ARRAY(
        SELECT pg_catalog.format_type(a.type, NULL)
        FROM pg_catalog.unnest(p.proargtypes::pg_catalog.oid[]) WITH ORDINALITY AS a(type, position)
        ORDER BY a.position
    ),
    'argument_names', ARRAY(
        SELECT COALESCE(p.proargnames[m.position], '')
        FROM pg_catalog.unnest(
            COALESCE(p.proargmodes, pg_catalog.array_fill('i'::"char", ARRAY[p.pronargs::int]))
        ) WITH ORDINALITY AS m(mode, position)
        WHERE m.mode IN ('i', 'b', 'v')
        ORDER BY m.position
    ),
    'argument_defaults', p.pronargdefaults,
    'variadic', p.provariadic <> 0,
    'return_type', pg_catalog.format_type(p.prorettype, NULL),
    'result', COALESCE(pg_catalog.pg_get_function_result(p.oid), ''),
    'returns_set', p.proretset,
    'output_names', ARRAY(
        SELECT COALESCE(p.proargnames[m.position], '')
        FROM pg_catalog.unnest(p.proargmodes) WITH ORDINALITY AS m(mode, position)
        WHERE m.mode IN ('o', 'b', 't')
        ORDER BY m.position
    ),
    'output_types', ARRAY(
        SELECT pg_catalog.format_type(o.type, NULL)
        FROM ROWS FROM (pg_catalog.unnest(p.proallargtypes), pg_catalog.unnest(p.proargmodes)) WITH ORDINALITY AS o(type, mode, position)
        WHERE o.mode IN ('o', 'b', 't')
        ORDER BY o.position
    ),
    'language', l.lanname,
    'source', COALESCE(p.prosrc, ''),
    'sql_body', {sql_body},
    'volatility', CASE p.provolatile
        WHEN 'i' THEN 'immutable'
        WHEN 's' THEN 'stable'
        ELSE 'volatile'
    END,
    'security_definer', p.prosecdef,
    'strict', p.proisstrict,
    'config', COALESCE(p.proconfig, '{}'),
    'extension', e.extname
)::text
FROM
    pg_catalog.pg_proc p
JOIN
    pg_catalog.pg_namespace n ON n.oid = p.pronamespace
JOIN
    pg_catalog.pg_language l ON l.oid = p.prolang
LEFT JOIN
    pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
        AND d.objid = p.oid
        AND d.deptype = 'e'
LEFT JOIN
    pg_catalog.pg_extension e ON e.oid = d.refobjid
WHERE
    n.nspname NOT IN ('pg_catalog', 'information_schema')
    AND n.nspname !~ '^pg_toast'
ORDER BY
    n.nspname, p.proname, p.oid
