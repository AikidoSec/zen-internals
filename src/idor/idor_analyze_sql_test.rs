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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_join() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users u JOIN orders o ON o.user_id = u.id WHERE u.tenant_id = $1",
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
                ],
                filters: vec![FilterColumn {
                    table: Some("u".into()),
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_mysql_placeholder() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id = ?", 8).unwrap(),
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_mysql_multiple_placeholders() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE status = ? AND tenant_id = ? AND name = ?",
                8,
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
                        column: "status".into(),

                        value: "?".into(),
                        placeholder_number: Some(0),
                    },
                    FilterColumn {
                        table: None,
                        column: "tenant_id".into(),

                        value: "?".into(),
                        placeholder_number: Some(1),
                    },
                    FilterColumn {
                        table: None,
                        column: "name".into(),

                        value: "?".into(),
                        placeholder_number: Some(2),
                    },
                ],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_parse_error() {
        assert_eq!(idor_analyze_sql("NOT VALID SQL !!!", 9).is_err(), true);
    }

    #[test]
    fn test_update_with_where_postgres() {
        assert_eq!(
            idor_analyze_sql("UPDATE users SET name = 'x' WHERE tenant_id = $1", 9).unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),

                    value: "$1".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_update_set_not_in_filters() {
        // SET has 2 placeholders (positions 0 and 1), so WHERE placeholder is position 2
        assert_eq!(
            idor_analyze_sql(
                "UPDATE users SET name = ?, tenant_id = ? WHERE tenant_id = ?",
                8,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),

                    value: "?".into(),
                    placeholder_number: Some(2),
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_update_without_where() {
        assert_eq!(
            idor_analyze_sql("UPDATE users SET name = 'x'", 9).unwrap(),
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
    fn test_update_mysql_placeholder() {
        assert_eq!(
            idor_analyze_sql("UPDATE users SET name = ? WHERE tenant_id = ?", 8).unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),

                    value: "?".into(),
                    placeholder_number: Some(1),
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_delete_with_where_postgres() {
        assert_eq!(
            idor_analyze_sql("DELETE FROM users WHERE tenant_id = $1", 9).unwrap(),
            vec![SqlQueryResult {
                kind: "delete".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),

                    value: "$1".into(),
                    placeholder_number: None,
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_delete_without_where() {
        assert_eq!(
            idor_analyze_sql("DELETE FROM users", 9).unwrap(),
            vec![SqlQueryResult {
                kind: "delete".into(),
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
    fn test_insert_postgres_placeholder() {
        assert_eq!(
            idor_analyze_sql("INSERT INTO users (name, tenant_id) VALUES ('x', $1)", 9,).unwrap(),
            vec![SqlQueryResult {
                kind: "insert".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: Some(vec![vec![
                    InsertColumn {
                        column: "name".into(),
                        value: "x".into(),
                        placeholder_number: None,
                    },
                    InsertColumn {
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    },
                ]]),
            }]
        );
    }

    #[test]
    fn test_insert_mysql_placeholder() {
        assert_eq!(
            idor_analyze_sql("INSERT INTO users (name, tenant_id) VALUES (?, ?)", 8,).unwrap(),
            vec![SqlQueryResult {
                kind: "insert".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: Some(vec![vec![
                    InsertColumn {
                        column: "name".into(),
                        value: "?".into(),
                        placeholder_number: Some(0),
                    },
                    InsertColumn {
                        column: "tenant_id".into(),
                        value: "?".into(),
                        placeholder_number: Some(1),
                    },
                ]]),
            }]
        );
    }

    #[test]
    fn test_insert_missing_tenant_column() {
        assert_eq!(
            idor_analyze_sql("INSERT INTO users (name) VALUES ('x')", 9).unwrap(),
            vec![SqlQueryResult {
                kind: "insert".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: Some(vec![vec![InsertColumn {
                    column: "name".into(),
                    value: "x".into(),
                    placeholder_number: None,
                }]]),
            }]
        );
    }

    #[test]
    fn test_insert_multi_row() {
        assert_eq!(
            idor_analyze_sql(
                "INSERT INTO users (name, tenant_id) VALUES ('x', 'org_1'), ('y', 'org_2')",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "insert".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: Some(vec![
                    vec![
                        InsertColumn {
                            column: "name".into(),
                            value: "x".into(),
                            placeholder_number: None,
                        },
                        InsertColumn {
                            column: "tenant_id".into(),
                            value: "org_1".into(),
                            placeholder_number: None,
                        },
                    ],
                    vec![
                        InsertColumn {
                            column: "name".into(),
                            value: "y".into(),
                            placeholder_number: None,
                        },
                        InsertColumn {
                            column: "tenant_id".into(),
                            value: "org_2".into(),
                            placeholder_number: None,
                        },
                    ],
                ]),
            }]
        );
    }

    #[test]
    fn test_insert_on_conflict_postgres() {
        assert_eq!(
            idor_analyze_sql(
                "INSERT INTO users (name, tenant_id) VALUES ('x', $1) ON CONFLICT (id) DO UPDATE SET name = 'y'",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "insert".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: Some(vec![vec![
                    InsertColumn {
                        column: "name".into(),
                        value: "x".into(),
                        placeholder_number: None,
                    },
                    InsertColumn {
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    },
                ]]),
            }]
        );
    }

    #[test]
    fn test_insert_on_duplicate_key_mysql() {
        assert_eq!(
            idor_analyze_sql(
                "INSERT INTO users (name, tenant_id) VALUES ('x', ?) ON DUPLICATE KEY UPDATE name = 'y'",
                8,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "insert".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: Some(vec![vec![
                    InsertColumn {
                        column: "name".into(),
                        value: "x".into(),
                        placeholder_number: None,
                    },
                    InsertColumn {
                        column: "tenant_id".into(),
                        value: "?".into(),
                        placeholder_number: Some(0),
                    },
                ]]),
            }]
        );
    }

    #[test]
    fn test_select_union() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE tenant_id = $1 UNION SELECT * FROM admins WHERE tenant_id = $2",
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
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_select_union_all_mysql() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE tenant_id = ? UNION ALL SELECT * FROM admins WHERE tenant_id = ?",
                8,
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
                        value: "?".into(),
                        placeholder_number: Some(0),
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
                        value: "?".into(),
                        placeholder_number: Some(1),
                    }],
                    insert_columns: None,
                },
            ]
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
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_select_union_same_table_one_without_filter() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE tenant_id = $1 UNION SELECT * FROM users",
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "users".into(),
                        alias: None,
                    }],
                    filters: vec![],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_select_union_no_filter_on_one_side() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE tenant_id = $1 UNION SELECT * FROM admins",
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "admins".into(),
                        alias: None,
                    }],
                    filters: vec![],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_select_union_with_join() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT u.* FROM users u JOIN orders o ON o.user_id = u.id WHERE u.tenant_id = $1 UNION ALL SELECT u.* FROM users u JOIN returns r ON r.user_id = u.id WHERE u.tenant_id = $2",
                9,
            )
            .unwrap(),
            vec![
                SqlQueryResult {
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
                        value: "$1".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![
                        TableRef {
                            name: "users".into(),
                            alias: Some("u".into()),
                        },
                        TableRef {
                            name: "returns".into(),
                            alias: Some("r".into()),
                        },
                    ],
                    filters: vec![FilterColumn {
                        table: Some("u".into()),
                        column: "tenant_id".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_select_except() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE tenant_id = $1 EXCEPT SELECT * FROM blocked_users WHERE tenant_id = $2",
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "blocked_users".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_select_intersect() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE tenant_id = $1 INTERSECT SELECT * FROM premium_users WHERE tenant_id = $2",
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "premium_users".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_inner_join_duplicate_table() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT a.*, b.* FROM users a INNER JOIN users b ON a.manager_id = b.id WHERE a.tenant_id = $1",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![
                    TableRef {
                        name: "users".into(),
                        alias: Some("a".into()),
                    },
                    TableRef {
                        name: "users".into(),
                        alias: Some("b".into()),
                    },
                ],
                filters: vec![FilterColumn {
                    table: Some("a".into()),
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_cross_join_lateral_subquery() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT c.*, o.* FROM customers c CROSS JOIN LATERAL (SELECT * FROM orders WHERE orders.customer_id = c.id ORDER BY created_at DESC LIMIT 3) AS o WHERE c.tenant_id = $1",
                9,
            )
            .unwrap(),
            vec![
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "customers".into(),
                        alias: Some("c".into()),
                    }],
                    filters: vec![FilterColumn {
                        table: Some("c".into()),
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "orders".into(),
                        alias: None,
                    }],
                    filters: vec![],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_left_join_lateral_subquery() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT u.*, p.* FROM users u LEFT JOIN LATERAL (SELECT * FROM posts WHERE posts.user_id = u.id LIMIT 5) AS p ON true WHERE u.tenant_id = $1",
                9,
            )
            .unwrap(),
            vec![
                SqlQueryResult {
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "posts".into(),
                        alias: None,
                    }],
                    filters: vec![],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_cross_join_lateral_with_placeholders() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT c.*, r.* FROM customers c CROSS JOIN LATERAL (SELECT * FROM recent_orders WHERE customer_id = c.id AND status = $1) AS r WHERE c.tenant_id = $2",
                9,
            )
            .unwrap(),
            vec![
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "customers".into(),
                        alias: Some("c".into()),
                    }],
                    filters: vec![FilterColumn {
                        table: Some("c".into()),
                        column: "tenant_id".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "recent_orders".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "status".into(),
                        value: "$1".into(),
                        placeholder_number: None,
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_insert_select_with_union() {
        assert_eq!(
            idor_analyze_sql(
                "INSERT INTO archive (name, tenant_id) SELECT name, tenant_id FROM users WHERE tenant_id = $1 UNION ALL SELECT name, tenant_id FROM admins WHERE tenant_id = $2",
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "insert".into(),
                    tables: vec![TableRef {
                        name: "archive".into(),
                        alias: None,
                    }],
                    filters: vec![],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_multiple_statements() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE tenant_id = $1; DELETE FROM orders WHERE tenant_id = $2",
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "delete".into(),
                    tables: vec![TableRef {
                        name: "orders".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_unsupported_statement_returns_error() {
        assert_eq!(
            idor_analyze_sql("MERGE INTO target USING source ON target.id = source.id WHEN MATCHED THEN UPDATE SET target.name = source.name;", 9)
                .unwrap_err()
                .contains("Unrecognized SQL statement"),
            true
        );
    }

    #[test]
    fn test_truncate_ignored() {
        assert_eq!(idor_analyze_sql("TRUNCATE users", 9).unwrap(), vec![]);
    }

    #[test]
    fn test_cte_simple() {
        assert_eq!(
            idor_analyze_sql(
                "WITH active AS (SELECT * FROM users WHERE tenant_id = $1) SELECT * FROM active WHERE status = 'active'",
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "status".into(),
                        value: "active".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_cte_multiple() {
        assert_eq!(
            idor_analyze_sql(
                "WITH u AS (SELECT * FROM users WHERE tenant_id = $1), o AS (SELECT * FROM orders WHERE tenant_id = $2) SELECT * FROM u JOIN o ON o.user_id = u.id",
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "orders".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$2".into(),
                        placeholder_number: None,
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
    fn test_cte_with_real_table_in_main_query() {
        assert_eq!(
            idor_analyze_sql(
                "WITH active_users AS (SELECT * FROM users WHERE tenant_id = $1) SELECT * FROM active_users au JOIN orders o ON o.user_id = au.id WHERE o.tenant_id = $2",
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "orders".into(),
                        alias: Some("o".into()),
                    }],
                    filters: vec![FilterColumn {
                        table: Some("o".into()),
                        column: "tenant_id".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_cte_referencing_another_cte() {
        assert_eq!(
            idor_analyze_sql(
                "WITH a AS (SELECT * FROM users WHERE tenant_id = $1), b AS (SELECT * FROM a WHERE status = 'active') SELECT * FROM b",
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "status".into(),
                        value: "active".into(),
                        placeholder_number: None,
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
    fn test_cte_name_case_insensitive() {
        assert_eq!(
            idor_analyze_sql(
                "WITH Active AS (SELECT * FROM users WHERE tenant_id = $1) SELECT * FROM ACTIVE",
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
    fn test_cte_insert_into_real_table_with_same_name_as_cte() {
        // Always track INSERT even if table name matches CTE - safer to over-report than miss real inserts
        assert_eq!(
            idor_analyze_sql(
                "WITH users AS (SELECT * FROM admins) INSERT INTO users (name, tenant_id) VALUES ('test', $1)",
                9,
            )
            .unwrap(),
            vec![
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "admins".into(),
                        alias: None,
                    }],
                    filters: vec![],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "insert".into(),
                    tables: vec![TableRef {
                        name: "users".into(),
                        alias: None,
                    }],
                    filters: vec![],
                    insert_columns: Some(vec![vec![
                        InsertColumn {
                            column: "name".into(),
                            value: "test".into(),
                            placeholder_number: None,
                        },
                        InsertColumn {
                            column: "tenant_id".into(),
                            value: "$1".into(),
                            placeholder_number: None,
                        },
                    ]]),
                },
            ]
        );
    }

    #[test]
    fn test_cte_with_update_and_subquery() {
        assert_eq!(
            idor_analyze_sql(
                r#"WITH selected AS (
                    SELECT id FROM items WHERE project_id = $1 AND tenant_id = $2 ORDER BY priority ASC LIMIT 1
                ),
                upd_item AS (
                    UPDATE items i SET status = 'active' FROM selected s WHERE i.id = s.id AND i.tenant_id = $2 RETURNING i.*
                ),
                upd_worker AS (
                    UPDATE workers w SET item_id = (SELECT id FROM selected) WHERE w.id = $3 AND w.tenant_id = $2 RETURNING w.*
                )
                SELECT upd_worker.* FROM upd_worker"#,
                9,
            )
            .unwrap(),
            vec![
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "items".into(),
                        alias: None,
                    }],
                    filters: vec![
                        FilterColumn {
                            table: None,
                            column: "project_id".into(),
                            value: "$1".into(),
                            placeholder_number: None,
                        },
                        FilterColumn {
                            table: None,
                            column: "tenant_id".into(),
                            value: "$2".into(),
                            placeholder_number: None,
                        },
                    ],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "update".into(),
                    tables: vec![TableRef {
                        name: "items".into(),
                        alias: Some("i".into()),
                    }],
                    filters: vec![FilterColumn {
                        table: Some("i".into()),
                        column: "tenant_id".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "update".into(),
                    tables: vec![TableRef {
                        name: "workers".into(),
                        alias: Some("w".into()),
                    }],
                    filters: vec![
                        FilterColumn {
                            table: Some("w".into()),
                            column: "id".into(),
                            value: "$3".into(),
                            placeholder_number: None,
                        },
                        FilterColumn {
                            table: Some("w".into()),
                            column: "tenant_id".into(),
                            value: "$2".into(),
                            placeholder_number: None,
                        },
                    ],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![],
                    filters: vec![],
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
    fn test_subquery_in_where_in() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE tenant_id = $1)",
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
                    filters: vec![],
                    insert_columns: None,
                },
                SqlQueryResult {
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
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_subquery_in_where_exists() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE EXISTS (SELECT 1 FROM orgs WHERE orgs.id = users.tenant_id AND orgs.id = $1)",
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
                    filters: vec![],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "orgs".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: Some("orgs".into()),
                        column: "id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_where_not_equal_skipped() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id != $1", 9).unwrap(),
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
    fn test_where_greater_than_skipped() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM audit_log WHERE created_at > $1 AND tenant_id = $2",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "audit_log".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "$2".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_where_less_than_or_equal_skipped() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM events WHERE priority <= $1 AND tenant_id = $2",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "events".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "$2".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_where_in_list_skipped() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id IN ($1, $2, $3)", 9,).unwrap(),
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
    fn test_where_in_list_mysql_skipped() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id IN (?, ?, ?)", 8,).unwrap(),
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
    fn test_where_or_condition() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE tenant_id = $1 OR admin = true",
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
                    },
                    FilterColumn {
                        table: None,
                        column: "admin".into(),
                        value: "true".into(),
                        placeholder_number: None,
                    },
                ],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_schema_qualified_table() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM public.users WHERE tenant_id = $1", 9,).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "public.users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_schema_qualified_table_with_alias() {
        assert_eq!(
            idor_analyze_sql("SELECT u.* FROM public.users u WHERE u.tenant_id = $1", 9,).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "public.users".into(),
                    alias: Some("u".into()),
                }],
                filters: vec![FilterColumn {
                    table: Some("u".into()),
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                }],
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_update_with_from_postgres() {
        assert_eq!(
            idor_analyze_sql(
                "UPDATE orders SET status = 'cancelled' FROM users WHERE users.id = orders.user_id AND users.tenant_id = $1",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_insert_select_simple() {
        assert_eq!(
            idor_analyze_sql(
                "INSERT INTO archive (name, tenant_id) SELECT name, tenant_id FROM users WHERE tenant_id = $1",
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
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "insert".into(),
                    tables: vec![TableRef {
                        name: "archive".into(),
                        alias: None,
                    }],
                    filters: vec![],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_right_join() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM orders o RIGHT JOIN users u ON u.id = o.user_id WHERE u.tenant_id = $1",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![
                    TableRef {
                        name: "orders".into(),
                        alias: Some("o".into()),
                    },
                    TableRef {
                        name: "users".into(),
                        alias: Some("u".into()),
                    },
                ],
                filters: vec![FilterColumn {
                    table: Some("u".into()),
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_full_outer_join() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users u FULL OUTER JOIN profiles p ON p.user_id = u.id WHERE u.tenant_id = $1",
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
                        name: "profiles".into(),
                        alias: Some("p".into()),
                    },
                ],
                filters: vec![FilterColumn {
                    table: Some("u".into()),
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_where_between_skipped() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM events WHERE id BETWEEN $1 AND $2 AND tenant_id = $3",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "events".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "$3".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_where_is_null_skipped() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE deleted_at IS NULL AND tenant_id = $1",
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_where_is_not_null_skipped() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE email IS NOT NULL AND tenant_id = $1",
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_where_like_skipped() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE name LIKE $1 AND tenant_id = $2",
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
                    value: "$2".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_where_hardcoded_number() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE id = 3 AND tenant_id = $1", 9,).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![
                    FilterColumn {
                        table: None,
                        column: "id".into(),
                        value: "3".into(),
                        placeholder_number: None,
                    },
                    FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    },
                ],
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_nested_subqueries_in_from() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM (SELECT * FROM (SELECT * FROM users WHERE tenant_id = $1) sub1) sub2",
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_insert_schema_qualified() {
        assert_eq!(
            idor_analyze_sql(
                "INSERT INTO public.users (name, tenant_id) VALUES ('x', $1)",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "insert".into(),
                tables: vec![TableRef {
                    name: "public.users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: Some(vec![vec![
                    InsertColumn {
                        column: "name".into(),
                        value: "x".into(),
                        placeholder_number: None,
                    },
                    InsertColumn {
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    },
                ]]),
            }]
        );
    }

    #[test]
    fn test_update_schema_qualified() {
        assert_eq!(
            idor_analyze_sql("UPDATE public.users SET name = 'x' WHERE tenant_id = $1", 9,)
                .unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
                tables: vec![TableRef {
                    name: "public.users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_delete_schema_qualified() {
        assert_eq!(
            idor_analyze_sql("DELETE FROM public.users WHERE tenant_id = $1", 9,).unwrap(),
            vec![SqlQueryResult {
                kind: "delete".into(),
                tables: vec![TableRef {
                    name: "public.users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_reversed_comparison() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE $1 = tenant_id", 9).unwrap(),
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_reversed_comparison_mysql() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE ? = tenant_id", 8).unwrap(),
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_mysql_backtick_quoted_identifiers() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM `users` WHERE `tenant_id` = ?", 8).unwrap(),
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_postgres_double_quoted_identifiers() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM \"users\" WHERE \"tenant_id\" = $1", 9,).unwrap(),
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_parenthesized_where_condition() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE (tenant_id = $1 AND status = 'active')",
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
                    },
                    FilterColumn {
                        table: None,
                        column: "status".into(),
                        value: "active".into(),
                        placeholder_number: None,
                    },
                ],
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
                    },
                    FilterColumn {
                        table: None,
                        column: "status".into(),
                        value: "active".into(),
                        placeholder_number: None,
                    },
                ],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_select_no_from() {
        assert_eq!(
            idor_analyze_sql("SELECT 1", 9).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![],
                filters: vec![],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_select_now() {
        assert_eq!(
            idor_analyze_sql("SELECT NOW()", 9).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![],
                filters: vec![],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(idor_analyze_sql("", 9).is_err(), true);
    }

    #[test]
    fn test_update_with_subquery_in_where() {
        assert_eq!(
            idor_analyze_sql(
                "UPDATE orders SET status = 'cancelled' WHERE user_id IN (SELECT id FROM users WHERE tenant_id = $1)",
                9,
            )
            .unwrap(),
            vec![
                SqlQueryResult {
                    kind: "update".into(),
                    tables: vec![TableRef {
                        name: "orders".into(),
                        alias: None,
                    }],
                    filters: vec![],
                    insert_columns: None,
                },
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
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_delete_with_subquery_in_where() {
        assert_eq!(
            idor_analyze_sql(
                "DELETE FROM orders WHERE user_id IN (SELECT id FROM users WHERE tenant_id = $1)",
                9,
            )
            .unwrap(),
            vec![
                SqlQueryResult {
                    kind: "delete".into(),
                    tables: vec![TableRef {
                        name: "orders".into(),
                        alias: None,
                    }],
                    filters: vec![],
                    insert_columns: None,
                },
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
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_insert_returning_postgres() {
        assert_eq!(
            idor_analyze_sql(
                "INSERT INTO users (name, tenant_id) VALUES ('x', $1) RETURNING *",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "insert".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: Some(vec![vec![
                    InsertColumn {
                        column: "name".into(),
                        value: "x".into(),
                        placeholder_number: None,
                    },
                    InsertColumn {
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    },
                ]]),
            }]
        );
    }

    #[test]
    fn test_insert_multi_row_mysql_placeholders() {
        assert_eq!(
            idor_analyze_sql(
                "INSERT INTO users (name, tenant_id) VALUES (?, ?), (?, ?)",
                8,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "insert".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: Some(vec![
                    vec![
                        InsertColumn {
                            column: "name".into(),
                            value: "?".into(),
                            placeholder_number: Some(0),
                        },
                        InsertColumn {
                            column: "tenant_id".into(),
                            value: "?".into(),
                            placeholder_number: Some(1),
                        },
                    ],
                    vec![
                        InsertColumn {
                            column: "name".into(),
                            value: "?".into(),
                            placeholder_number: Some(2),
                        },
                        InsertColumn {
                            column: "tenant_id".into(),
                            value: "?".into(),
                            placeholder_number: Some(3),
                        },
                    ],
                ]),
            }]
        );
    }

    #[test]
    fn test_update_with_multiple_set_placeholders_mysql() {
        assert_eq!(
            idor_analyze_sql(
                "UPDATE users SET name = ?, email = ?, status = ? WHERE tenant_id = ?",
                8,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "?".into(),
                    placeholder_number: Some(3),
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_update_with_multiple_where_placeholders_mysql() {
        assert_eq!(
            idor_analyze_sql(
                "UPDATE users SET name = ? WHERE tenant_id = ? AND status = ?",
                8,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![
                    FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "?".into(),
                        placeholder_number: Some(1),
                    },
                    FilterColumn {
                        table: None,
                        column: "status".into(),
                        value: "?".into(),
                        placeholder_number: Some(2),
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_select_with_table_alias_as_keyword() {
        assert_eq!(
            idor_analyze_sql("SELECT u.* FROM users AS u WHERE u.tenant_id = $1", 9).unwrap(),
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_delete_with_join_mysql() {
        assert_eq!(
            idor_analyze_sql(
                "DELETE t1 FROM orders t1 INNER JOIN users t2 ON t1.user_id = t2.id WHERE t2.tenant_id = ?",
                8,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "delete".into(),
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
                filters: vec![FilterColumn {
                    table: Some("t2".into()),
                    column: "tenant_id".into(),
                    value: "?".into(),
                    placeholder_number: Some(0),
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_select_string_value_in_filter() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id = 'org_123'", 9,).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "org_123".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_select_multiple_conditions_and() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM users WHERE tenant_id = $1 AND status = $2 AND role = $3",
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
                    },
                    FilterColumn {
                        table: None,
                        column: "status".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                    },
                    FilterColumn {
                        table: None,
                        column: "role".into(),
                        value: "$3".into(),
                        placeholder_number: None,
                    },
                ],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_parenthesized_select_query() {
        assert_eq!(
            idor_analyze_sql("(SELECT * FROM users WHERE tenant_id = $1)", 9).unwrap(),
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_union_with_parenthesized_selects() {
        assert_eq!(
            idor_analyze_sql(
                "(SELECT * FROM users WHERE tenant_id = $1) UNION (SELECT * FROM admins WHERE tenant_id = $2)",
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
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_scalar_subquery_in_select() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT *, (SELECT COUNT(*) FROM orders WHERE orders.user_id = users.id AND orders.tenant_id = $1) FROM users WHERE tenant_id = $2",
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
                        value: "$2".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "orders".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: Some("orders".into()),
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_mysql_double_quoted_string_value() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id = \"org_123\"", 8,).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "org_123".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_update_parenthesized_where() {
        assert_eq!(
            idor_analyze_sql(
                "UPDATE users SET status = 'inactive' WHERE (tenant_id = $1 AND role = 'admin')",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
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
                    },
                    FilterColumn {
                        table: None,
                        column: "role".into(),
                        value: "admin".into(),
                        placeholder_number: None,
                    },
                ],
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
                    },
                    FilterColumn {
                        table: None,
                        column: "status".into(),
                        value: "deleted".into(),
                        placeholder_number: None,
                    },
                ],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_update_deeply_nested_parentheses() {
        assert_eq!(
            idor_analyze_sql(
                "UPDATE users SET status = 'inactive' WHERE ((tenant_id = $1) AND (role = 'admin'))",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "update".into(),
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
                    },
                    FilterColumn {
                        table: None,
                        column: "role".into(),
                        value: "admin".into(),
                        placeholder_number: None,
                    },
                ],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_insert_more_values_than_columns() {
        assert_eq!(
            idor_analyze_sql(
                "INSERT INTO users (name) VALUES ('alice', 'extra_value')",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "insert".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: Some(vec![vec![InsertColumn {
                    column: "name".into(),
                    value: "alice".into(),
                    placeholder_number: None,
                }]]),
            }]
        );
    }

    #[test]
    fn test_insert_multi_row_more_values_than_columns() {
        assert_eq!(
            idor_analyze_sql(
                "INSERT INTO users (name, tenant_id) VALUES ('alice', 'org_1', 'extra'), ('bob', 'org_2', 'extra2')",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "insert".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![],
                insert_columns: Some(vec![
                    vec![
                        InsertColumn {
                            column: "name".into(),
                            value: "alice".into(),
                            placeholder_number: None,
                        },
                        InsertColumn {
                            column: "tenant_id".into(),
                            value: "org_1".into(),
                            placeholder_number: None,
                        },
                    ],
                    vec![
                        InsertColumn {
                            column: "name".into(),
                            value: "bob".into(),
                            placeholder_number: None,
                        },
                        InsertColumn {
                            column: "tenant_id".into(),
                            value: "org_2".into(),
                            placeholder_number: None,
                        },
                    ],
                ]),
            }]
        );
    }

    #[test]
    fn test_whitespace_only_query() {
        assert!(idor_analyze_sql("   ", 9).is_err());
    }

    #[test]
    fn test_semicolon_only_query() {
        assert!(idor_analyze_sql(";", 9).is_err());
    }

    #[test]
    fn test_select_with_escaped_string_literal_postgres() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id = E'org_123'", 9,).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "org_123".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_select_with_dollar_quoted_string_postgres() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id = $$org_123$$", 9,).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "org_123".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_select_with_national_string_literal_mysql() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id = N'org_123'", 8,).unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "users".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "org_123".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_select_with_having_clause() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT department, COUNT(*) FROM employees WHERE tenant_id = $1 GROUP BY department HAVING COUNT(*) > 5",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![TableRef {
                    name: "employees".into(),
                    alias: None,
                }],
                filters: vec![FilterColumn {
                    table: None,
                    column: "tenant_id".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                }],
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
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_update_with_subquery_in_set() {
        assert_eq!(
            idor_analyze_sql(
                "UPDATE users SET score = (SELECT AVG(score) FROM scores WHERE tenant_id = $1) WHERE id = $2",
                9,
            )
            .unwrap(),
            vec![
                SqlQueryResult {
                    kind: "update".into(),
                    tables: vec![TableRef {
                        name: "users".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "id".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "scores".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_delete_with_mysql_placeholder_in_nested_where() {
        assert_eq!(
            idor_analyze_sql("DELETE FROM users WHERE (tenant_id = ? AND status = ?)", 8,).unwrap(),
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
                        value: "?".into(),
                        placeholder_number: Some(0),
                    },
                    FilterColumn {
                        table: None,
                        column: "status".into(),
                        value: "?".into(),
                        placeholder_number: Some(1),
                    },
                ],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_on_with_specific_value() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT * FROM orders o JOIN users u ON o.user_id = u.id AND u.tenant_id = 123",
                9,
            )
            .unwrap(),
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![
                    TableRef {
                        name: "orders".into(),
                        alias: Some("o".into()),
                    },
                    TableRef {
                        name: "users".into(),
                        alias: Some("u".into()),
                    },
                ],
                filters: vec![FilterColumn {
                    table: Some("u".into()),
                    column: "tenant_id".into(),
                    value: "123".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_multiple_subqueries_in_select_list() {
        assert_eq!(
            idor_analyze_sql(
                "SELECT (SELECT name FROM orgs WHERE id = $1), (SELECT COUNT(*) FROM logs WHERE tenant_id = $2) FROM users WHERE id = $3",
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
                        column: "id".into(),
                        value: "$3".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "orgs".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "id".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
                SqlQueryResult {
                    kind: "select".into(),
                    tables: vec![TableRef {
                        name: "logs".into(),
                        alias: None,
                    }],
                    filters: vec![FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                    }],
                    insert_columns: None,
                },
            ]
        );
    }

    #[test]
    fn test_transaction_statements_ignored() {
        assert_eq!(idor_analyze_sql("START TRANSACTION;", 9).unwrap(), vec![]);
        assert_eq!(idor_analyze_sql("BEGIN TRANSACTION;", 9).unwrap(), vec![]);
        assert_eq!(idor_analyze_sql("COMMIT;", 9).unwrap(), vec![]);
        assert_eq!(idor_analyze_sql("ROLLBACK;", 9).unwrap(), vec![]);
        assert_eq!(idor_analyze_sql("SAVEPOINT sp1;", 9).unwrap(), vec![]);
        assert_eq!(
            idor_analyze_sql("SET TRANSACTION ISOLATION LEVEL READ COMMITTED;", 9).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("RELEASE SAVEPOINT sp1;", 9).unwrap(),
            vec![]
        );
    }

    #[test]
    fn test_ddl_statements_ignored() {
        assert_eq!(
            idor_analyze_sql("CREATE TABLE users (id INT PRIMARY KEY, name TEXT);", 9).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("ALTER TABLE users ADD COLUMN email TEXT;", 9).unwrap(),
            vec![]
        );
        assert_eq!(idor_analyze_sql("DROP TABLE users;", 9).unwrap(), vec![]);
        assert_eq!(
            idor_analyze_sql("DROP TABLE IF EXISTS users;", 9).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("CREATE INDEX idx_users_email ON users (email);", 9).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql(
                "CREATE VIEW active_users AS SELECT * FROM users WHERE active = true;",
                9
            )
            .unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("CREATE SCHEMA myschema;", 9).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("CREATE DATABASE mydb;", 9).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("CREATE SEQUENCE users_id_seq;", 9).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("CREATE EXTENSION IF NOT EXISTS pgcrypto;", 9).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("ALTER VIEW myview AS SELECT * FROM users;", 9).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql(
                "CREATE FUNCTION my_func() RETURNS INT LANGUAGE SQL AS 'SELECT 1';",
                9
            )
            .unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql(
                "CREATE TRIGGER check_insert BEFORE INSERT ON accounts FOR EACH ROW EXECUTE FUNCTION check_account_insert();",
                9
            )
            .unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("DROP FUNCTION my_func;", 9).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("DROP TRIGGER check_update ON accounts;", 9).unwrap(),
            vec![]
        );
    }

    #[test]
    fn test_ddl_statements_ignored_mysql() {
        assert_eq!(
            idor_analyze_sql(
                "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(255));",
                8
            )
            .unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("ALTER TABLE users ADD COLUMN email VARCHAR(255);", 8).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("DROP TABLE IF EXISTS users;", 8).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("CREATE INDEX idx_email ON users (email);", 8).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("TRUNCATE TABLE users;", 8).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("DROP PROCEDURE my_proc;", 8).unwrap(),
            vec![]
        );
    }

    #[test]
    fn test_dcl_statements_ignored() {
        assert_eq!(
            idor_analyze_sql("GRANT SELECT ON users TO myuser;", 9).unwrap(),
            vec![]
        );
        assert_eq!(
            idor_analyze_sql("REVOKE SELECT ON users FROM myuser;", 9).unwrap(),
            vec![]
        );
    }

    #[test]
    fn test_session_statements_ignored() {
        assert_eq!(
            idor_analyze_sql("SET search_path TO myschema;", 9).unwrap(),
            vec![]
        );
        assert_eq!(idor_analyze_sql("SET TIME ZONE 'UTC';", 9).unwrap(), vec![]);
        assert_eq!(idor_analyze_sql("SHOW server_version;", 9).unwrap(), vec![]);
        assert_eq!(
            idor_analyze_sql("EXPLAIN SELECT * FROM users;", 9).unwrap(),
            vec![]
        );
        assert_eq!(idor_analyze_sql("SET ROLE myrole;", 9).unwrap(), vec![]);
    }

    #[test]
    fn test_session_statements_ignored_mysql() {
        assert_eq!(idor_analyze_sql("SET NAMES 'utf8mb4';", 8).unwrap(), vec![]);
        assert_eq!(idor_analyze_sql("SET NAMES DEFAULT;", 8).unwrap(), vec![]);
        assert_eq!(idor_analyze_sql("SHOW TABLES;", 8).unwrap(), vec![]);
        assert_eq!(
            idor_analyze_sql("SHOW COLUMNS FROM users;", 8).unwrap(),
            vec![]
        );
        assert_eq!(idor_analyze_sql("USE mydb;", 8).unwrap(), vec![]);
        assert_eq!(idor_analyze_sql("SHOW STATUS;", 8).unwrap(), vec![]);
        assert_eq!(idor_analyze_sql("SHOW VARIABLES;", 8).unwrap(), vec![]);
        assert_eq!(
            idor_analyze_sql("SHOW CREATE TABLE users;", 8).unwrap(),
            vec![]
        );
        assert_eq!(idor_analyze_sql("SHOW COLLATION;", 8).unwrap(), vec![]);
        assert_eq!(idor_analyze_sql("DESCRIBE users;", 8).unwrap(), vec![]);
    }

    #[test]
    fn test_cursor_statements_ignored() {
        assert_eq!(
            idor_analyze_sql("FETCH NEXT IN my_cursor;", 9).unwrap(),
            vec![]
        );
        assert_eq!(idor_analyze_sql("CLOSE my_cursor;", 9).unwrap(), vec![]);
    }

    #[test]
    fn test_declare_cursor_not_ignored() {
        assert!(idor_analyze_sql("DECLARE my_cursor CURSOR FOR SELECT * FROM users;", 9).is_err());
    }
}
