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
    fn test_common_sql_strings() {
        COMMON_SQL_STRINGS.iter().for_each(|common_string| {
            assert!(
                is_common_sql_string(&common_string.to_lowercase()),
                "Failed for {}",
                common_string
            );
        });
    }

    #[test]
    fn test_looks_like_order_by() {
        assert!(is_common_sql_string("column_name asc"));
        assert!(is_common_sql_string("column_name desc"));
        assert!(is_common_sql_string("name asc"));
        assert!(is_common_sql_string("name desc"));
        assert!(is_common_sql_string("name1 asc"));
        assert!(is_common_sql_string("name1 desc"));
        assert!(is_common_sql_string("name_1 asc"));
        assert!(is_common_sql_string("name_1 desc"));
        assert!(is_common_sql_string("name_1_2 asc"));
        assert!(is_common_sql_string("name_1_2 desc"));
        assert!(is_common_sql_string("name_name_1 asc"));
        assert!(is_common_sql_string("name_name_1 desc"));
    }

    #[test]
    fn test_looks_like_order_by_false_positive() {
        assert!(!is_common_sql_string("order by column_name asc"));
        assert!(!is_common_sql_string("order by column_name desc"));
        assert!(!is_common_sql_string("column_name asc, column_name2 desc"));
        assert!(!is_common_sql_string("column_name asc, column_name2 desc;"));
        assert!(!is_common_sql_string("column_name asc;"));
        assert!(!is_common_sql_string("column_name desc;"));
        assert!(!is_common_sql_string(";column_name asc"));
        assert!(!is_common_sql_string(";column_name desc"));
        assert!(!is_common_sql_string("column_name asc limit 1"));
        assert!(!is_common_sql_string("column_name desc limit 1"));
        assert!(!is_common_sql_string(
            "column_name asc, column_name2 asc limit 1"
        ));
        assert!(!is_common_sql_string(
            "column_name desc, column_name2 desc limit 1"
        ));
        assert!(is_common_sql_string("1 "));
        assert!(!is_common_sql_string("asc1"));
        assert!(!is_common_sql_string("desc1"));
        assert!(is_common_sql_string("asc 1"));
        assert!(!is_common_sql_string("desc 1"));
        assert!(!is_common_sql_string("1asc"));
        assert!(!is_common_sql_string("1desc"));
        assert!(!is_common_sql_string("1;"));
        assert!(!is_common_sql_string("1--"));
        assert!(!is_common_sql_string("1/*"));
        assert!(is_common_sql_string("1 asc"));
        assert!(!is_common_sql_string("1 desc"));
        assert!(!is_common_sql_string("1name asc"));
        assert!(!is_common_sql_string("1name desc"));
        assert!(!is_common_sql_string("1_name asc"));
        assert!(!is_common_sql_string("1_name desc"));
        assert!(!is_common_sql_string("1_name_2 asc"));
        assert!(!is_common_sql_string("1_name_2 desc"));
        assert!(!is_common_sql_string("1_name_name asc"));
        assert!(!is_common_sql_string("1_name_name desc"));
        assert!(!is_common_sql_string("column_name asc "));
        assert!(!is_common_sql_string("column_name desc "));
        assert!(!is_common_sql_string("column_name asc;"));
        assert!(!is_common_sql_string("column_name desc;"));
        assert!(!is_common_sql_string("column_name asc--"));
        assert!(!is_common_sql_string("column_name desc--"));
        assert!(!is_common_sql_string("column_name asc/*"));
        assert!(!is_common_sql_string("column_name desc/*"));
        assert!(!is_common_sql_string("column_name asc-- "));
        assert!(!is_common_sql_string("column_name desc-- "));
        assert!(!is_common_sql_string("column_name asc/* "));
        assert!(!is_common_sql_string("column_name desc/* "));
    }

    #[test]
    fn test_it_returns_false_for_sql_operators() {
        assert!(!is_common_sql_string("="));
        assert!(!is_common_sql_string("!="));
        assert!(!is_common_sql_string("<>"));
        assert!(!is_common_sql_string(">"));
        assert!(!is_common_sql_string("<"));
        assert!(!is_common_sql_string(">="));
        assert!(!is_common_sql_string("&"));
        assert!(!is_common_sql_string("<= asc"));
        assert!(!is_common_sql_string("<= desc"));
        assert!(!is_common_sql_string("<= "));
        assert!(!is_common_sql_string("= asc"));
        assert!(!is_common_sql_string("= desc"));
        assert!(!is_common_sql_string("= "));
    }

    #[test]
    fn test_safe_two_char_payloads() {
        assert!(is_common_sql_string(":p"));
        assert!(is_common_sql_string(":d"));
        assert!(is_common_sql_string(":l"));
        assert!(is_common_sql_string("(:"));
        assert!(is_common_sql_string("(("));
        assert!(is_common_sql_string("d)"));
        assert!(is_common_sql_string("1)"));
        assert!(is_common_sql_string("(5"));
        assert!(is_common_sql_string("(1"));
        assert!(is_common_sql_string("(s"));
        assert!(is_common_sql_string("+1"));

        assert!(!is_common_sql_string("--"));
        assert!(!is_common_sql_string("/*"));
        assert!(!is_common_sql_string("*/"));
        assert!(!is_common_sql_string("';"));
        assert!(!is_common_sql_string("1;"));
        assert!(!is_common_sql_string("#1"));

        assert!(!is_common_sql_string("(1)"));
        assert!(!is_common_sql_string("(0)"));
        assert!(!is_common_sql_string("(a)"));
        assert!(!is_common_sql_string("(1)+"));
        assert!(!is_common_sql_string("1)+"));
        assert!(!is_common_sql_string("+(1"));
    }

    #[test]
    fn test_dot_star_common_sql_string() {
        assert!(is_common_sql_string(".*"));
    }

    #[test]
    fn test_it_returns_false_for_special_chars() {
        assert!(!is_common_sql_string("'"));
        assert!(!is_common_sql_string("\""));
        assert!(!is_common_sql_string(";"));
        assert!(!is_common_sql_string("\""));
        assert!(!is_common_sql_string("`"));
        assert!(!is_common_sql_string("~"));
        assert!(!is_common_sql_string("!"));
        assert!(!is_common_sql_string("@"));
        assert!(!is_common_sql_string("#"));
        assert!(!is_common_sql_string("$"));
        assert!(!is_common_sql_string("%"));
        assert!(!is_common_sql_string("^"));
        assert!(!is_common_sql_string("^ asc"));
        assert!(!is_common_sql_string("^ desc"));
        assert!(!is_common_sql_string("% asc"));
        assert!(!is_common_sql_string("% desc"));
        assert!(!is_common_sql_string("asc $"));
        assert!(!is_common_sql_string("desc $"));
        assert!(!is_common_sql_string("asc$"));
        assert!(!is_common_sql_string("desc$"));
    }

    #[test]
    fn test_it_sees_table_column_pattern() {
        assert!(is_common_sql_string("table.column"));
        assert!(is_common_sql_string("views.user_id"));
        assert!(is_common_sql_string("table_name.column_name"));
        assert!(is_common_sql_string("table_name.column_name1"));
        assert!(is_common_sql_string("table_name.column_name_1"));
        assert!(is_common_sql_string("table_name.column_name_1_2"));
        assert!(is_common_sql_string("table_name.column_1_name"));
        assert!(is_common_sql_string("table_name.column_name_name_1"));
        assert!(is_common_sql_string(".r"));
        assert!(is_common_sql_string(".id"));
        assert!(is_common_sql_string(".id_"));
        assert!(is_common_sql_string("r."));
        assert!(is_common_sql_string("r_."));
        assert!(!is_common_sql_string("r.r.r"));
        assert!(!is_common_sql_string(".test.test"));
    }

    #[test]
    fn test_it_returns_false_for_table_column_pattern_false_positive() {
        assert!(!is_common_sql_string(";table.column"));
        assert!(!is_common_sql_string("table.column;"));
        assert!(!is_common_sql_string("table.column "));
        assert!(!is_common_sql_string("table .column"));
        assert!(!is_common_sql_string("1_table.column"));
        assert!(!is_common_sql_string("1table.column"));
        assert!(!is_common_sql_string("= table.column"));
        assert!(!is_common_sql_string("table.column ="));
        assert!(!is_common_sql_string("table.column = "));
        assert!(!is_common_sql_string("table.column = 1"));
        assert!(!is_common_sql_string("table.column = 1;"));
        assert!(!is_common_sql_string("table.column = 1 "));
        assert!(!is_common_sql_string("table.column table.column"));
        assert!(!is_common_sql_string("table.column,table.column"));
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
    fn test_it_returns_false_if_its_not_an_integer() {
        assert!(!is_common_sql_string("--1"));
        assert!(!is_common_sql_string("1--"));
        assert!(!is_common_sql_string("-1-"));
        assert!(!is_common_sql_string("-1--"));
        assert!(!is_common_sql_string("-1 --"));
        assert!(!is_common_sql_string("-1 "));
        assert!(!is_common_sql_string("-1;"));
        assert!(!is_common_sql_string("-1\t"));
        assert!(!is_common_sql_string("-1\n"));
        assert!(!is_common_sql_string("-1\n;"));
        assert!(!is_common_sql_string("--"));
        assert!(!is_common_sql_string("-- -1"));
        assert!(!is_common_sql_string("-1,"));
        assert!(!is_common_sql_string("-1(--)"));
        assert!(!is_common_sql_string("-1 /*"));
        assert!(!is_common_sql_string("-1 /* abc */"));
    }

    #[test]
    fn test_stringified_arrays() {
        assert!(is_common_sql_string("[]"));
        assert!(!is_common_sql_string("[ ]"));
        assert!(!is_common_sql_string("[1]"));
        assert!(!is_common_sql_string("[[]]"));
    }

    #[test]
    fn test_decimals() {
        assert!(is_common_sql_string("1.0"));
        assert!(is_common_sql_string("0.1"));
        assert!(is_common_sql_string("-1.0"));
        assert!(is_common_sql_string("-0.1"));
        assert!(is_common_sql_string("1.5265654651"));
    }

    #[test]
    fn test_digit_space_alpha() {
        assert!(is_common_sql_string("1 a"));
        assert!(is_common_sql_string("9 z"));
        assert!(is_common_sql_string("0 m"));
        assert!(is_common_sql_string("00 m"));
        assert!(is_common_sql_string("0 mm"));
        assert!(is_common_sql_string("00 mm"));

        assert!(!is_common_sql_string("0  m"));
        assert!(!is_common_sql_string("'0 m"));
        assert!(!is_common_sql_string("0;m"));
    }

    #[test]
    fn test_non_decimals() {
        assert!(!is_common_sql_string("1."));
        assert!(!is_common_sql_string(".1"));
        assert!(!is_common_sql_string("1.0.0"));
        assert!(!is_common_sql_string("."));
    }

    #[test]
    fn test_single_line_comment_with_single_quote() {
        assert!(!is_common_sql_string("--"));
        assert!(!is_common_sql_string("--'"));
        assert!(!is_common_sql_string("'--"));
    }

    #[test]
    fn test_short_alphanumeric_with_spaces() {
        assert!(is_common_sql_string("1 li"));
        assert!(is_common_sql_string("1 ab"));
        assert!(is_common_sql_string("ab 1"));
        assert!(is_common_sql_string("1 abc"));

        assert!(!is_common_sql_string("1;li"));
        assert!(!is_common_sql_string("1'li"));
    }

    #[test]
    fn test_alpha_with_spaces() {
        assert!(is_common_sql_string("is n"));
        assert!(is_common_sql_string("is nu"));

        assert!(!is_common_sql_string("OR"));
        assert!(!is_common_sql_string(" OR "));
        assert!(!is_common_sql_string("TRUE OR TRUE IS TRUE"));
        assert!(!is_common_sql_string("TRUE OR TRUE"));
        assert!(!is_common_sql_string("is  nu"));
        assert!(!is_common_sql_string("is nul"));
        assert!(!is_common_sql_string("is null abc"));
        assert!(!is_common_sql_string("%is n%"));
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

    #[test]
    fn test_digits_ending_with_parenthesis() {
        assert!(is_common_sql_string("1)"));
        assert!(is_common_sql_string("123)"));

        assert!(!is_common_sql_string("(123)"));
        assert!(!is_common_sql_string("(123"));
        assert!(!is_common_sql_string("1 )"));
        assert!(!is_common_sql_string("1) --"));
        assert!(!is_common_sql_string("1)--"));
    }

    #[test]
    fn test_double_quote_start_end() {
        assert!(is_common_sql_string(r#""a"#));
        assert!(is_common_sql_string(r#""0"#));
        assert!(is_common_sql_string(r#"a""#));
        assert!(is_common_sql_string(r#"0""#));

        assert!(is_common_sql_string(r#"00""#));
        assert!(is_common_sql_string(r#"aa""#));
        assert!(is_common_sql_string(r#""00"#));
        assert!(is_common_sql_string(r#""aa"#));

        assert!(is_common_sql_string(r#""product-123"#));
        assert!(is_common_sql_string(r#"product-123""#));
        assert!(is_common_sql_string(r#""user-id-456"#));
        assert!(is_common_sql_string(r#"user-id-456""#));

        assert!(!is_common_sql_string(r#""payload--drop"#));
        assert!(!is_common_sql_string(r#"payload--drop""#));

        assert!(!is_common_sql_string(r#"";"#));
        assert!(!is_common_sql_string(r#";""#));

        // underscore has special meaning in MySQL LIKE operator, so we don't allow it here
        // (Only when ANSI_QUOTES SQL mode is enabled)
        assert!(!is_common_sql_string(r#""item_abc-def"#));
        assert!(!is_common_sql_string(r#"item_abc-def""#));

        // spaces are not allowed
        assert!(!is_common_sql_string(r#""user -id-456"#));
        assert!(!is_common_sql_string(r#"user -id-456""#));

        assert!(is_common_sql_string(&format!(
            "{}\"{}",
            "a".repeat(199),
            ""
        )));
        assert!(!is_common_sql_string(&format!(
            "{}\"{}",
            "a".repeat(200),
            ""
        )));
        assert!(is_common_sql_string(&format!(
            "\"{}{}",
            "a".repeat(199),
            ""
        )));
        assert!(!is_common_sql_string(&format!(
            "\"{}{}",
            "a".repeat(200),
            ""
        )));
    }

    #[test]
    fn test_trailing_comma() {
        assert!(is_common_sql_string("username,"));
        assert!(is_common_sql_string("user name,"));

        assert!(!is_common_sql_string(",username,"));
        assert!(!is_common_sql_string("user,name,"));
        assert!(!is_common_sql_string(",user,name"));
        assert!(!is_common_sql_string("user,name"));
        assert!(!is_common_sql_string(",user name,"));
        assert!(!is_common_sql_string("username,,"));
        assert!(!is_common_sql_string(",,username"));
        assert!(!is_common_sql_string(",username"));
        assert!(!is_common_sql_string(",user name"));

        let at_limit = format!("{},", "a".repeat(39));
        assert!(is_common_sql_string(&at_limit));
        let over_limit = format!("{}a,", "a".repeat(39));
        assert!(!is_common_sql_string(&over_limit));
    }
}
