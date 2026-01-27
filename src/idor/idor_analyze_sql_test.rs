#[cfg(test)]
mod tests {
    use crate::idor::{idor_analyze_sql, FilterColumn, SelectQueryResult, TableRef};

    #[test]
    fn test_simple_select() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id = $1", 9).unwrap(),
            vec![SelectQueryResult {
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
            vec![SelectQueryResult {
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
            }]
        );
    }

    #[test]
    fn test_mysql_placeholder() {
        assert_eq!(
            idor_analyze_sql("SELECT * FROM users WHERE tenant_id = ?", 8).unwrap(),
            vec![SelectQueryResult {
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
            vec![SelectQueryResult {
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
            }]
        );
    }

    #[test]
    fn test_parse_error() {
        assert!(idor_analyze_sql("NOT VALID SQL !!!", 9).is_err());
    }
}
