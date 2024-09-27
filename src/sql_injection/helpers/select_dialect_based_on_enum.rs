use sqlparser::dialect::*;

/*
0 -> generic.rs
1 -> ansi.rs
2 -> bigquery.rs
3 -> clickhouse.rs
4 -> databricks.rs
5 -> duckdb.rs
6 -> hive.rs
7 -> mssql.rs
8 -> mysql.rs
9 -> postgresql.rs
10 -> redshift.rs
11 -> snowflake.rs
12 -> sqlite.rs
*/
pub fn select_dialect_based_on_enum(enumerator: i32) -> Box<dyn Dialect> {
    // 0 is generic type.
    match enumerator {
        0 => Box::new(GenericDialect {}),
        1 => Box::new(AnsiDialect {}),
        2 => Box::new(BigQueryDialect {}),
        3 => Box::new(ClickHouseDialect {}),
        4 => Box::new(DatabricksDialect {}),
        5 => Box::new(DuckDbDialect {}),
        6 => Box::new(HiveDialect {}),
        7 => Box::new(MsSqlDialect {}),
        8 => Box::new(MySqlDialect {}),
        9 => Box::new(PostgreSqlDialect {}),
        19 => Box::new(RedshiftSqlDialect {}),
        11 => Box::new(SnowflakeDialect {}),
        12 => Box::new(SQLiteDialect {}),
        _ => Box::new(GenericDialect {}),
    }
}
