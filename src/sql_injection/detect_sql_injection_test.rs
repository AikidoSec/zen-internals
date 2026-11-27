#[cfg(test)]
mod tests {
    use crate::sql_injection::detect_sql_injection::{detect_sql_injection_str, DetectionReason};

    fn dialect(s: &str) -> i32 {
        match s {
            "mysql" => 8,
            "postgresql" => 9,
            "sqlite" => 12,
            "clickhouse" => 3,
            "generic" => 0,
            _ => panic!("Unknown dialect"),
        }
    }

    fn get_supported_dialects() -> Vec<i32> {
        vec![
            dialect("mysql"),
            dialect("postgresql"),
            dialect("sqlite"),
            dialect("clickhouse"),
            dialect("generic"),
        ]
    }

    macro_rules! is_injection {
        ($query:expr, $input:expr) => {
            for dia in get_supported_dialects().iter() {
                let result = detect_sql_injection_str($query, $input, dia.clone());
                assert!(
                    result.detected,
                    "should be an injection\nquery: {}\ninput: {}\ndialect: {}\nreason: {:?}\n",
                    $query,
                    $input,
                    dia.clone(),
                    result.reason
                )
            }
        };
        ($query:expr, $input:expr, $dialect:expr) => {
            assert!(detect_sql_injection_str($query, $input, $dialect).detected)
        };
    }
    macro_rules! not_injection {
        ($query:expr, $input:expr) => {
            for dia in get_supported_dialects().iter() {
                let result = detect_sql_injection_str($query, $input, dia.clone());
                assert!(
                    !(result.detected),
                    "should not be an injection\nquery: {}\ninput: {}\ndialect: {}\nreason: {:?}\n",
                    $query,
                    $input,
                    dia.clone(),
                    result.reason
                )
            }
        };
        ($query:expr, $input:expr, $dialect:expr) => {
            assert!(!(detect_sql_injection_str($query, $input, $dialect).detected))
        };
    }

    #[test]
    fn test_postgres_dollar_signs() {
        not_injection!(
            "SELECT * FROM users WHERE id = $$' OR 1=1 -- $$",
            "' OR 1=1 -- ",
            dialect("postgresql")
        );
        not_injection!(
            "SELECT * FROM users WHERE id = $$1; DROP TABLE users; -- $$",
            "1; DROP TABLE users; -- ",
            dialect("postgresql")
        );
        is_injection!(
            "SELECT * FROM users WHERE id = $$1$$ OR 1=1 -- $$",
            "1$$ OR 1=1 -- ",
            dialect("postgresql")
        );
    }

    #[test]
    fn test_character_combos() {
        is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "('"
        );

        // one character, after spaces removed cannot be injection :
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            ", "
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')          ;          ",
            "          ;          "
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')          6          ",
            "          6          "
        );

        not_injection!(
            "INSERT  INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "  "
        );
        not_injection!(
            "INSERT  INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "                 "
        );
    }

    #[test]
    fn test_it_still_flags_common_sql_patterns_with_more_stuff() {
        is_injection!(
          "select `recommendations`.*, (select count(*) from `recommendation_click_events` where `recommendation_click_events`.`recommendation_id` = recommendations.id) as `count__clicks`, (select count(*) from `recommendation_subscribe_events` where `recommendation_subscribe_events`.`recommendation_id` = recommendations.id) as `count__subscribers` from `recommendations` order by date DESC LIMIT 1",
          "date DESC LIMIT 1"
        );
        is_injection!(
          "select `recommendations`.*, (select count(*) from `recommendation_click_events` where `recommendation_click_events`.`recommendation_id` = recommendations.id) as `count__clicks`, (select count(*) from `recommendation_subscribe_events` where `recommendation_subscribe_events`.`recommendation_id` = recommendations.id) as `count__subscribers` from `recommendations` order by date DESC, id ASC limit 1",
          "date DESC, id ASC"
        );
    }

    #[test]
    fn test_with_pg_promise_placeholders() {
        // See https://github.com/vitaly-t/pg-promise?tab=readme-ov-file#named-parameters
        is_injection!(
            "INSERT INTO cats (name, age) VALUES (${name}, ${age})",
            "(${name}, ${age})",
            dialect("postgresql")
        );
    }

    #[test]
    fn test_injection_minus_sign() {
        is_injection!("SELECT * FROM users WHERE id IN (-1) -- ", "-1) -- ");
        is_injection!("SELECT * FROM users WHERE id IN (-1) -- -1", "-- -1");
        is_injection!(
            "SELECT * FROM users WHERE id IN (-1, 571, 639)",
            "-1, 571, 639"
        );
        is_injection!("SELECT * FROM users WHERE id IN (-1,571,639)", "-1,571,639");
    }

    #[test]
    fn test_alpha_with_spaces() {
        not_injection!("SELECT * FROM users WHERE status IS NULL", "IS N");
        not_injection!("SELECT * FROM users WHERE status IS NULL", "IS NU");

        is_injection!("SELECT * FROM users WHERE status IS  NULL", "IS  NU");
        is_injection!("SELECT * FROM users WHERE status IS NULL", "s IS N");
        is_injection!("SELECT * FROM users WHERE status IS NULL", "s IS NULL");
        is_injection!("SELECT * FROM users WHERE status = 1 OR TRUE", "1 OR TRUE");
        is_injection!(
            "SELECT * FROM users WHERE status = TRUE OR TRUE",
            "TRUE OR TRUE"
        );
        is_injection!(
            "SELECT * FROM users WHERE status = '' OR TRUE",
            "'' OR TRUE"
        );
        is_injection!(
            "SELECT * FROM users WHERE status = NULL OR TRUE",
            "NULL OR TRUE"
        );
    }

    #[test]
    fn test_time_zone() {
        not_injection!(
            r#"
                SELECT *::timestamptz AT TIME ZONE 'UTC' AS created_at_utc FROM events
            "#,
            "TIME ZONE"
        );
        is_injection!(
            r#"
                SELECT *::timestamptz AT TIME ZONE 'UTC' AS created_at_utc FROM events
            "#,
            "TIME ZONE 'UTC'"
        );
    }

    #[test]
    #[ignore] // The trailing % prevents a full string match.
    fn does_not_flag_safely_escaped_postgres_input_with_wildcard_suffix() {
        let query = "SELECT \"id\" FROM \"records\" WHERE \"name\" ILIKE 'A sentence that doesn''%' LIMIT 10";
        let input = "A sentence that doesn'";
        let result = detect_sql_injection_str(query, input, 9);

        assert!(
            !result.detected,
            "{result:?}\nquery: {query}\ninput: {input}"
        );
    }

}
