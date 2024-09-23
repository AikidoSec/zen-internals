use sqlparser::dialect::*;

/*
1 -> ansi.rs
2 -> bigquery.rs
3 -> clickhouse.rs
4 -> databricks.rs
5 -> duckdb.rs
6 -> generic.rs
7 -> hive.rs
8 -> mssql.rs
9 -> mysql.rs
10 -> postgresql.rs
11 -> redshift.rs
12 -> snowflake.rs
13 -> sqlite.rs
*/
pub fn select_dialect_based_on_enum(enumerator: i32) -> Box<dyn Dialect> {
    match enumerator {
        1 => Box::new(AnsiDialect {}),
        2 => Box::new(BigQueryDialect {}),
        3 => Box::new(ClickHouseDialect {}),
        4 => Box::new(DatabricksDialect {}),
        5 => Box::new(DuckDbDialect {}),
        6 => Box::new(GenericDialect {}),
        7 => Box::new(HiveDialect {}),
        8 => Box::new(MsSqlDialect {}),
        9 => Box::new(MySqlDialect {}),
        10 => Box::new(PostgreSqlDialect {}),
        11 => Box::new(RedshiftSqlDialect {}),
        12 => Box::new(SnowflakeDialect {}),
        13 => Box::new(SQLiteDialect {}),
        _ => Box::new(GenericDialect {}),
    }
}
