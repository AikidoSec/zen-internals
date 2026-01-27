#[cfg(test)]
mod tests {
    use crate::idor::{idor_analyze_sql, FilterColumn, InsertColumn, SqlQueryResult, TableRef};

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
                    operator: "=".into(),
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
                filters: vec![
                    FilterColumn {
                        table: Some("o".into()),
                        column: "user_id".into(),
                        operator: "=".into(),
                        value: "u.id".into(),
                        placeholder_number: None,
                    },
                    FilterColumn {
                        table: Some("u".into()),
                        column: "tenant_id".into(),
                        operator: "=".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    },
                ],
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
                    operator: "=".into(),
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
                        operator: "=".into(),
                        value: "?".into(),
                        placeholder_number: Some(0),
                    },
                    FilterColumn {
                        table: None,
                        column: "tenant_id".into(),
                        operator: "=".into(),
                        value: "?".into(),
                        placeholder_number: Some(1),
                    },
                    FilterColumn {
                        table: None,
                        column: "name".into(),
                        operator: "=".into(),
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
                    operator: "=".into(),
                    value: "$1".into(),
                    placeholder_number: None,
                }],
                insert_columns: None,
            }]
        );
    }

    #[test]
    fn test_update_set_not_in_filters() {
        // SET assignments must NOT appear as filters — only WHERE conditions
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
                    operator: "=".into(),
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
        // SET has 1 placeholder (position 0), so WHERE placeholder is position 1
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
                    operator: "=".into(),
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
                    operator: "=".into(),
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
                    operator: "=".into(),
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
                        value: "'x'".into(),
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
                    value: "'x'".into(),
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
                            value: "'x'".into(),
                            placeholder_number: None,
                        },
                        InsertColumn {
                            column: "tenant_id".into(),
                            value: "'org_1'".into(),
                            placeholder_number: None,
                        },
                    ],
                    vec![
                        InsertColumn {
                            column: "name".into(),
                            value: "'y'".into(),
                            placeholder_number: None,
                        },
                        InsertColumn {
                            column: "tenant_id".into(),
                            value: "'org_2'".into(),
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
                        value: "'x'".into(),
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
                        value: "'x'".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                    filters: vec![
                        FilterColumn {
                            table: Some("o".into()),
                            column: "user_id".into(),
                            operator: "=".into(),
                            value: "u.id".into(),
                            placeholder_number: None,
                        },
                        FilterColumn {
                            table: Some("u".into()),
                            column: "tenant_id".into(),
                            operator: "=".into(),
                            value: "$1".into(),
                            placeholder_number: None,
                        },
                    ],
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
                    filters: vec![
                        FilterColumn {
                            table: Some("r".into()),
                            column: "user_id".into(),
                            operator: "=".into(),
                            value: "u.id".into(),
                            placeholder_number: None,
                        },
                        FilterColumn {
                            table: Some("u".into()),
                            column: "tenant_id".into(),
                            operator: "=".into(),
                            value: "$2".into(),
                            placeholder_number: None,
                        },
                    ],
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                filters: vec![
                    FilterColumn {
                        table: Some("a".into()),
                        column: "manager_id".into(),
                        operator: "=".into(),
                        value: "b.id".into(),
                        placeholder_number: None,
                    },
                    FilterColumn {
                        table: Some("a".into()),
                        column: "tenant_id".into(),
                        operator: "=".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    },
                ],
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
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![
                    TableRef {
                        name: "customers".into(),
                        alias: Some("c".into()),
                    },
                    TableRef {
                        name: "orders".into(),
                        alias: None,
                    },
                ],
                filters: vec![
                    FilterColumn {
                        table: Some("orders".into()),
                        column: "customer_id".into(),
                        operator: "=".into(),
                        value: "c.id".into(),
                        placeholder_number: None,
                    },
                    FilterColumn {
                        table: Some("c".into()),
                        column: "tenant_id".into(),
                        operator: "=".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    },
                ],
                insert_columns: None,
            }]
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
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![
                    TableRef {
                        name: "users".into(),
                        alias: Some("u".into()),
                    },
                    TableRef {
                        name: "posts".into(),
                        alias: None,
                    },
                ],
                filters: vec![
                    FilterColumn {
                        table: Some("posts".into()),
                        column: "user_id".into(),
                        operator: "=".into(),
                        value: "u.id".into(),
                        placeholder_number: None,
                    },
                    FilterColumn {
                        table: Some("u".into()),
                        column: "tenant_id".into(),
                        operator: "=".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    },
                ],
                insert_columns: None,
            }]
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
            vec![SqlQueryResult {
                kind: "select".into(),
                tables: vec![
                    TableRef {
                        name: "customers".into(),
                        alias: Some("c".into()),
                    },
                    TableRef {
                        name: "recent_orders".into(),
                        alias: None,
                    },
                ],
                filters: vec![
                    FilterColumn {
                        table: None,
                        column: "customer_id".into(),
                        operator: "=".into(),
                        value: "c.id".into(),
                        placeholder_number: None,
                    },
                    FilterColumn {
                        table: None,
                        column: "status".into(),
                        operator: "=".into(),
                        value: "$1".into(),
                        placeholder_number: None,
                    },
                    FilterColumn {
                        table: Some("c".into()),
                        column: "tenant_id".into(),
                        operator: "=".into(),
                        value: "$2".into(),
                        placeholder_number: None,
                    },
                ],
                insert_columns: None,
            }]
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
                    operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
                        operator: "=".into(),
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
            idor_analyze_sql("CREATE TABLE users (id INT)", 9)
                .unwrap_err()
                .contains("Unsupported SQL statement type"),
            true
        );
    }

    #[test]
    fn test_truncate_returns_error() {
        assert_eq!(idor_analyze_sql("TRUNCATE users", 9).is_err(), true);
    }
}
