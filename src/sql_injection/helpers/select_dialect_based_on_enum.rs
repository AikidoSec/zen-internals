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
        10 => Box::new(RedshiftSqlDialect {}),
        11 => Box::new(SnowflakeDialect {}),
        12 => Box::new(SQLiteDialect {}),
        _ => Box::new(GenericDialect {}),
    }
}

#[cfg(test)]
mod tests {
    use crate::sql_injection::helpers::select_dialect_based_on_enum::select_dialect_based_on_enum;
    use sqlparser::dialect::{
        AnsiDialect, BigQueryDialect, ClickHouseDialect, DatabricksDialect, DuckDbDialect,
        GenericDialect, HiveDialect, MsSqlDialect, MySqlDialect, PostgreSqlDialect,
        RedshiftSqlDialect, SQLiteDialect, SnowflakeDialect,
    };

    #[test]
    fn test_select_dialect_based_on_enum() {
        assert!(select_dialect_based_on_enum(0).is::<GenericDialect>());
        assert!(select_dialect_based_on_enum(1).is::<AnsiDialect>());
        assert!(select_dialect_based_on_enum(2).is::<BigQueryDialect>());
        assert!(select_dialect_based_on_enum(3).is::<ClickHouseDialect>());
        assert!(select_dialect_based_on_enum(4).is::<DatabricksDialect>());
        assert!(select_dialect_based_on_enum(5).is::<DuckDbDialect>());
        assert!(select_dialect_based_on_enum(6).is::<HiveDialect>());
        assert!(select_dialect_based_on_enum(7).is::<MsSqlDialect>());
        assert!(select_dialect_based_on_enum(8).is::<MySqlDialect>());
        assert!(select_dialect_based_on_enum(9).is::<PostgreSqlDialect>());
        assert!(select_dialect_based_on_enum(10).is::<RedshiftSqlDialect>());
        assert!(select_dialect_based_on_enum(11).is::<SnowflakeDialect>());
        assert!(select_dialect_based_on_enum(12).is::<SQLiteDialect>());
        assert!(select_dialect_based_on_enum(13).is::<GenericDialect>());
    }
}
