#[cfg(test)]
mod tests {
    macro_rules! is_safe_for_every_dialect {
        ($input:expr) => {
            let dialects = vec!["generic", "mysql", "postgresql", "sqlite", "clickhouse"];
            for d in dialects {
                assert_eq!(
                    is_safe_sql_string($input, dialect(d)),
                    true,
                    "Should be safe input {}",
                    $input
                );
            }
        };
    }

    macro_rules! is_unsafe_for_every_dialect {
        ($input:expr) => {
            let dialects = vec!["generic", "mysql", "postgresql", "sqlite", "clickhouse"];
            for d in dialects {
                assert_eq!(
                    is_safe_sql_string($input, dialect(d)),
                    false,
                    "Should be unsafe input {}",
                    $input
                );
            }
        };
    }

    use crate::sql_injection::is_safe_sql_string::is_safe_sql_string;

    fn dialect(s: &str) -> i32 {
        match s {
            "generic" => 0,
            "clickhouse" => 3,
            "mysql" => 8,
            "postgresql" => 9,
            "sqlite" => 12,
            _ => panic!("Unknown dialect"),
        }
    }

    #[test]
    fn test_is_safe_sql_input() {
        is_safe_for_every_dialect!("-1");
        is_safe_for_every_dialect!("1");
        is_safe_for_every_dialect!("1.2");
        is_safe_for_every_dialect!("-1.2");
        is_safe_for_every_dialect!("1,2,3,4");
        is_safe_for_every_dialect!("1\t,2,3,4");
        is_safe_for_every_dialect!("1, 2, 3, 4");
        is_safe_for_every_dialect!("1, 2, 3, -4");
        is_safe_for_every_dialect!("1,-2,3,-4");
    }

    #[test]
    fn test_is_unsafe_sql_input() {
        is_unsafe_for_every_dialect!("--");
        is_unsafe_for_every_dialect!("--1");
        is_unsafe_for_every_dialect!("-1--");
        is_unsafe_for_every_dialect!("---1");
        is_unsafe_for_every_dialect!("1,2,3,4--");
        is_unsafe_for_every_dialect!("1--,2,3,4");
        is_unsafe_for_every_dialect!("/* -1 */");
        is_unsafe_for_every_dialect!("# -1");
        is_unsafe_for_every_dialect!("1,2,#3,4");
        is_unsafe_for_every_dialect!("(1,2,3,4)");
        is_unsafe_for_every_dialect!("1,'2',3,4");
        is_unsafe_for_every_dialect!("SELECT -1");
    }

    #[test]
    fn test_incomplete_syntax() {
        is_unsafe_for_every_dialect!("$-$aa//");
        is_unsafe_for_every_dialect!("'");
        is_unsafe_for_every_dialect!("/* -1");
        is_unsafe_for_every_dialect!("1,2,3,4/*");
    }
}
