#[cfg(test)]
mod tests {
    use crate::idor::{idor_analyze_sql, FilterColumn, InsertColumn, SqlQueryResult, TableRef};

    // ── SELECT ──────────────────────────────────────────────────────────

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

    // ── UPDATE ──────────────────────────────────────────────────────────

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

    // ── DELETE ──────────────────────────────────────────────────────────

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

    // ── INSERT ──────────────────────────────────────────────────────────

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

    // ── Unsupported statement ───────────────────────────────────────────

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
