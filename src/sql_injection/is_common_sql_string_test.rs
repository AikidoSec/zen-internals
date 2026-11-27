#[cfg(test)]
mod tests {
    use crate::sql_injection::is_common_sql_string::is_common_sql_string;
    use crate::sql_injection::is_common_sql_string::COMMON_SQL_STRINGS;

    #[test]
    fn common_sql_strings_are_lowercase() {
        for s in COMMON_SQL_STRINGS {
            assert_eq!(
                s,
                s.to_lowercase(),
                "`{s}` is not lowercase; all entries in COMMON_SQL_STRINGS must be lowercase"
            );
        }
    }

    #[test]
    fn test_integers() {
        assert!(is_common_sql_string("-0"));
        assert!(is_common_sql_string("-1"));
        assert!(is_common_sql_string("-12"));
        assert!(is_common_sql_string("-123"));
        assert!(is_common_sql_string("-1234"));
        assert!(is_common_sql_string("1"));
        assert!(is_common_sql_string("12"));
        assert!(is_common_sql_string("123"));
        assert!(is_common_sql_string("0"));
    }

    #[test]
    fn test_single_quote_start_end() {
        assert!(is_common_sql_string("'a"));
        assert!(is_common_sql_string("'0"));
        assert!(is_common_sql_string("a'"));
        assert!(is_common_sql_string("0'"));

        assert!(is_common_sql_string("00'"));
        assert!(is_common_sql_string("aa'"));
        assert!(is_common_sql_string("'00"));
        assert!(is_common_sql_string("'aa"));

        assert!(is_common_sql_string("'product-123"));
        assert!(is_common_sql_string("product-123'"));
        assert!(is_common_sql_string("'user-id-456"));
        assert!(is_common_sql_string("user-id-456'"));

        assert!(!is_common_sql_string("'payload--drop"));
        assert!(!is_common_sql_string("payload--drop'"));

        assert!(!is_common_sql_string("';"));
        assert!(!is_common_sql_string(";'"));

        // underscore has special meaning in MySQL LIKE operator, so we don't allow it here
        assert!(!is_common_sql_string("'item_abc-def"));
        assert!(!is_common_sql_string("item_abc-def'"));

        // spaces are not allowed
        assert!(!is_common_sql_string("'user -id-456"));
        assert!(!is_common_sql_string("user -id-456'"));

        assert!(is_common_sql_string(&format!("{}'{}", "a".repeat(199), "")));
        assert!(!is_common_sql_string(&format!(
            "{}'{}",
            "a".repeat(200),
            ""
        )));
        assert!(is_common_sql_string(&format!("'{}{}", "a".repeat(199), "")));
        assert!(!is_common_sql_string(&format!(
            "'{}{}",
            "a".repeat(200),
            ""
        )));
    }

}
