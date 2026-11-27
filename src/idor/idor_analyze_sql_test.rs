#[cfg(test)]
mod tests {
    use crate::idor::idor_analyze_sql::idor_analyze_sql;
    use crate::idor::sql_query_result::{FilterColumn, InsertColumn, SqlQueryResult, TableRef};

    #[test]
    fn test_simple_select() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id = $1", 9).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_delete_mysql_placeholder() {
        assert_eq!(
            idor_analyze_sql("DELETE FROM users WHERE tenant_id = ?", 8).unwrap(),
            vec![SqlQueryResult {
                kind: "delete".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),

                    value: "?".into(),
                    placeholder_number: Some(0),
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_select_union_three_queries() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE tenant_id = $1 UNION SELECT * FROM admins WHERE tenant_id = $2 UNION SELECT * FROM guests WHERE tenant_id = $3",
                9,
            )
            .unwrap(),
            vec![
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "users".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                        is_placeholder: true,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "admins".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                        is_placeholder: true,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "guests".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$3".into(),
                        placeholder_number: None,
                        is_placeholder: true,
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_subquery_in_from() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM (SELECT * FROM users WHERE tenant_id = $1) AS u",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_cte_recursive_with_self_reference() {
        assert_eq!(
            idor_analyze_sql(
                "WITH RECURSIVE tree AS (SELECT * FROM categories WHERE tenant_id = $1 UNION ALL SELECT c.* FROM categories c JOIN tree t ON c.parent_id = t.id WHERE c.tenant_id = $1) SELECT * FROM tree",
                9,
            )
            .unwrap(),
            vec![
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "categories".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                        is_placeholder: true,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "categories".into(),
                        alias: Some("c".into()),
                    }],
                    filters: vec![FilterColumn {
                        table: Some("c".into()),
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                        is_placeholder: true,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![],
                    filters: vec![],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_where_not_equal_ansi_skipped() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id <> $1", 9).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_update_where_or_extracts_no_filters() {
        assert_eq!(
            idor_analyze_sql(
                "UPDATE users SET name = $1 WHERE tenant_id = $2 OR admin = true",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_three_table_join() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users u JOIN orders o ON o.user_id = u.id JOIN products p ON p.id = o.product_id WHERE u.tenant_id = $1",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![
                    TableRef {
                        name: "users".into(),
                        alias: Some("u".into()),
                    },
                    TableRef {
                        name: "orders".into(),
                        alias: Some("o".into()),
                    },
                    TableRef {
                        name: "products".into(),
                        alias: Some("p".into()),
                    },
                ],
                filters: vec![FilterColumn {
                    table: Some("u".into()),
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_delete_with_using_postgres() {
        assert_eq!(
            idor_analyze_sql(
                "DELETE FROM orders USING users WHERE users.id = orders.user_id AND users.tenant_id = $1",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "delete".into(),
                tables: vec![
                    TableRef {
                        name: "orders".into(),
                        alias: None,
                    },
                    TableRef {
                        name: "users".into(),
                        alias: None,
                    },
                ],
                filters: vec![FilterColumn {
                    table: Some("users".into()),
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_deeply_parenthesized_where() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE ((tenant_id = $1) AND (status = 'active'))",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![
                    FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                        is_placeholder: true,
                    },
                    FilterColumn {
                        table: None,
                        column: "status".into(),
                        value: "active".into(),
                        placeholder_number: None,
                        is_placeholder: false,
                    },
                ],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_select_with_table_alias_no_as_keyword() {
        assert_eq!(
            idor_analyze_sql("SELECT u.* FROM users u WHERE u.tenant_id = $1", 9).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: Some("u".into()),
                }],
                filters: vec![FilterColumn {
                    table: Some("u".into()),
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_delete_parenthesized_where() {
        assert_eq!(
            idor_analyze_sql(
                "DELETE FROM users WHERE (tenant_id = $1 AND status = 'deleted')",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "delete".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![
                    FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                        is_placeholder: true,
                    },
                    FilterColumn {
                        table: None,
                        column: "status".into(),
                        value: "deleted".into(),
                        placeholder_number: None,
                        is_placeholder: false,
                    },
                ],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_select_with_group_by() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT status, COUNT(*) FROM orders WHERE tenant_id = $1 GROUP BY status",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "orders".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_postgres_notification_statements_ignored() {
        for query in [
            "LISTEN zen_events;",
            "UNLISTEN zen_events;",
            "UNLISTEN *;",
            "NOTIFY zen_events;",
            "NOTIFY zen_events, 'ready';",
        ] {
            assert_eq!(idor_analyze_sql(query, 9).unwrap(), vec![], "{query}");
        }
    }

    #[test]
    fn test_pdo_named_placeholder_with_join() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users u JOIN orders o ON o.user_id = u.id WHERE u.tenant_id = :tenant_id",
                8,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![
                    TableRef {
                        name: "users".into(),
                        alias: Some("u".into()),
                    },
                    TableRef {
                        name: "orders".into(),
                        alias: Some("o".into()),
                    },
                ],
                filters: vec![FilterColumn {
                    table: Some("u".into()),
                    column: "tenant_id".into(),
                    value: ":tenant_id".into(),
                    placeholder_number: None,
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_sqlite_question_mark_placeholder() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id = ?", 12).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "?".into(),
                    placeholder_number: Some(0),
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_where_unicode_string_literal() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE id = U&'abc'", 9).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "id".into(),
                    value: "abc".into(),
                    placeholder_number: None,
                    is_placeholder: false,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_mssql_deprecated_multiple_table_hints_is_real_table() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM orders (NOLOCK, READPAST) WHERE tenant_id = $1",
                7, // MSSQL
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "orders".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_string_literal_is_not_placeholder() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM orders WHERE tenant_id = 'org_123'", 9).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "orders".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "org_123".into(),
                    placeholder_number: None,
                    is_placeholder: false,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_join_col_col_not_resolved_inside_or_mysql() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT r.* FROM requests r \
                 JOIN tenants t ON t.id = r.tenant_id \
                 WHERE r.sys_group_id = t.sys_group_id OR t.sys_group_id = ?",
                8,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![
                    TableRef {
                        name: "requests".into(),
                        alias: Some("r".into()),
                    },
                    TableRef {
                        name: "tenants".into(),
                        alias: Some("t".into()),
                    },
                ],
                filters: vec![],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_chain_fan_out_via_intermediate_node() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * \
                 FROM table_a a \
                 JOIN table_b b ON a.group_id = b.group_id \
                 JOIN table_c c ON a.group_id = c.group_id \
                 WHERE b.group_id = $1",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![
                    TableRef {
                        name: "table_a".into(),
                        alias: Some("a".into()),
                    },
                    TableRef {
                        name: "table_b".into(),
                        alias: Some("b".into()),
                    },
                    TableRef {
                        name: "table_c".into(),
                        alias: Some("c".into()),
                    },
                ],
                filters: vec![
                    FilterColumn {
                        table: Some("b".into()),
                        column: "group_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                        is_placeholder: true,
                    },
                    FilterColumn {
                        table: Some("a".into()),
                        column: "group_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                        is_placeholder: true,
                    },
                    FilterColumn {
                        table: Some("c".into()),
                        column: "group_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                        is_placeholder: true,
                    },
                ],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_right_join_col_col_not_resolved_from_where() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT r.* FROM requests r \
                 RIGHT JOIN tenants t ON r.tenant_id = t.tenant_id \
                 WHERE t.tenant_id = $1",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![
                    TableRef {
                        name: "requests".into(),
                        alias: Some("r".into()),
                    },
                    TableRef {
                        name: "tenants".into(),
                        alias: Some("t".into()),
                    },
                ],
                filters: vec![FilterColumn {
                    table: Some("t".into()),
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_update_join_col_col_resolved_mysql() {
        assert_eq!(
            idor_analyze_sql(
                "UPDATE orders t1 \
                 INNER JOIN users t2 ON t1.tenant_id = t2.tenant_id \
                 SET t1.status = 'active' \
                 WHERE t2.tenant_id = ?",
                8,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
                tables: vec![
                    TableRef {
                        name: "orders".into(),
                        alias: Some("t1".into()),
                    },
                    TableRef {
                        name: "users".into(),
                        alias: Some("t2".into()),
                    },
                ],
                filters: vec![
                    FilterColumn {
                        table: Some("t2".into()),
                        column: "tenant_id".into(),
                        value: "?".into(),
                        placeholder_number: Some(0),
                        is_placeholder: true,
                    },
                    FilterColumn {
                        table: Some("t1".into()),
                        column: "tenant_id".into(),
                        value: "?".into(),
                        placeholder_number: Some(0),
                        is_placeholder: true,
                    },
                ],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_update_placeholder_in_where_numbered_after_join_and_assignment_mysql() {
        assert_eq!(
            idor_analyze_sql(
                "UPDATE users u JOIN tenants t ON t.region_id = ? SET u.name = ? WHERE u.tenant_id = ?",
                8,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
                tables: vec![
                    TableRef {
                        name: "users".into(),
                        alias: Some("u".into()),
                    },
                    TableRef {
                        name: "tenants".into(),
                        alias: Some("t".into()),
                    },
                ],
                filters: vec![FilterColumn {
                    table: Some("u".into()),
                    column: "tenant_id".into(),
                    value: "?".into(),
                    placeholder_number: Some(2),
                    is_placeholder: true,
                }],
                insert_columns: None,
            }]
        );
    }

}
