#[cfg(test)]
mod tests {
    use crate::sql_injection::is_common_sql_string::is_common_sql_string;
    use crate::sql_injection::is_common_sql_string::COMMON_SQL_STRINGS;

    #[test]
    fn test_common_sql_strings() {
        COMMON_SQL_STRINGS.iter().for_each(|common_string| {
            assert_eq!(
                is_common_sql_string(&common_string.to_lowercase()),
                true,
                "Failed for {}",
                common_string
            );
        });
    }

    #[test]
    fn test_looks_like_order_by() {
        assert_eq!(is_common_sql_string("column_name asc"), true);
        assert_eq!(is_common_sql_string("column_name desc"), true);
        assert_eq!(is_common_sql_string("name asc"), true);
        assert_eq!(is_common_sql_string("name desc"), true);
        assert_eq!(is_common_sql_string("name1 asc"), true);
        assert_eq!(is_common_sql_string("name1 desc"), true);
        assert_eq!(is_common_sql_string("name_1 asc"), true);
        assert_eq!(is_common_sql_string("name_1 desc"), true);
        assert_eq!(is_common_sql_string("name_1_2 asc"), true);
        assert_eq!(is_common_sql_string("name_1_2 desc"), true);
        assert_eq!(is_common_sql_string("name_name_1 asc"), true);
        assert_eq!(is_common_sql_string("name_name_1 desc"), true);
    }

    #[test]
    fn test_looks_like_order_by_false_positive() {
        assert_eq!(is_common_sql_string("order by column_name asc"), false);
        assert_eq!(is_common_sql_string("order by column_name desc"), false);
        assert_eq!(
            is_common_sql_string("column_name asc, column_name2 desc"),
            false
        );
        assert_eq!(
            is_common_sql_string("column_name asc, column_name2 desc;"),
            false
        );
        assert_eq!(is_common_sql_string("column_name asc;"), false);
        assert_eq!(is_common_sql_string("column_name desc;"), false);
        assert_eq!(is_common_sql_string(";column_name asc"), false);
        assert_eq!(is_common_sql_string(";column_name desc"), false);
        assert_eq!(is_common_sql_string("column_name asc limit 1"), false);
        assert_eq!(is_common_sql_string("column_name desc limit 1"), false);
        assert_eq!(
            is_common_sql_string("column_name asc, column_name2 asc limit 1"),
            false
        );
        assert_eq!(
            is_common_sql_string("column_name desc, column_name2 desc limit 1"),
            false
        );
        assert_eq!(is_common_sql_string("asc1"), false);
        assert_eq!(is_common_sql_string("desc1"), false);
        assert_eq!(is_common_sql_string("asc 1"), false);
        assert_eq!(is_common_sql_string("desc 1"), false);
        assert_eq!(is_common_sql_string("1asc"), false);
        assert_eq!(is_common_sql_string("1desc"), false);
        assert_eq!(is_common_sql_string("1 "), false);
        assert_eq!(is_common_sql_string("1;"), false);
        assert_eq!(is_common_sql_string("1--"), false);
        assert_eq!(is_common_sql_string("1/*"), false);
        assert_eq!(is_common_sql_string("1 asc"), false);
        assert_eq!(is_common_sql_string("1 desc"), false);
        assert_eq!(is_common_sql_string("1name asc"), false);
        assert_eq!(is_common_sql_string("1name desc"), false);
        assert_eq!(is_common_sql_string("1_name asc"), false);
        assert_eq!(is_common_sql_string("1_name desc"), false);
        assert_eq!(is_common_sql_string("1_name_2 asc"), false);
        assert_eq!(is_common_sql_string("1_name_2 desc"), false);
        assert_eq!(is_common_sql_string("1_name_name asc"), false);
        assert_eq!(is_common_sql_string("1_name_name desc"), false);
        assert_eq!(is_common_sql_string("column_name asc "), false);
        assert_eq!(is_common_sql_string("column_name desc "), false);
        assert_eq!(is_common_sql_string("column_name asc;"), false);
        assert_eq!(is_common_sql_string("column_name desc;"), false);
        assert_eq!(is_common_sql_string("column_name asc--"), false);
        assert_eq!(is_common_sql_string("column_name desc--"), false);
        assert_eq!(is_common_sql_string("column_name asc/*"), false);
        assert_eq!(is_common_sql_string("column_name desc/*"), false);
        assert_eq!(is_common_sql_string("column_name asc-- "), false);
        assert_eq!(is_common_sql_string("column_name desc-- "), false);
        assert_eq!(is_common_sql_string("column_name asc/* "), false);
        assert_eq!(is_common_sql_string("column_name desc/* "), false);
    }

    #[test]
    fn test_it_returns_false_for_sql_operators() {
        assert_eq!(is_common_sql_string("="), false);
        assert_eq!(is_common_sql_string("!="), false);
        assert_eq!(is_common_sql_string("<>"), false);
        assert_eq!(is_common_sql_string(">"), false);
        assert_eq!(is_common_sql_string("<"), false);
        assert_eq!(is_common_sql_string(">="), false);
        assert_eq!(is_common_sql_string("&"), false);
        assert_eq!(is_common_sql_string("<= asc"), false);
        assert_eq!(is_common_sql_string("<= desc"), false);
        assert_eq!(is_common_sql_string("<= "), false);
        assert_eq!(is_common_sql_string("= asc"), false);
        assert_eq!(is_common_sql_string("= desc"), false);
        assert_eq!(is_common_sql_string("= "), false);
    }

    #[test]
    fn test_it_returns_false_for_special_chars() {
        assert_eq!(is_common_sql_string("'"), false);
        assert_eq!(is_common_sql_string(";"), false);
        assert_eq!(is_common_sql_string("\""), false);
        assert_eq!(is_common_sql_string("`"), false);
        assert_eq!(is_common_sql_string("~"), false);
        assert_eq!(is_common_sql_string("!"), false);
        assert_eq!(is_common_sql_string("@"), false);
        assert_eq!(is_common_sql_string("#"), false);
        assert_eq!(is_common_sql_string("$"), false);
        assert_eq!(is_common_sql_string("%"), false);
        assert_eq!(is_common_sql_string("^"), false);
        assert_eq!(is_common_sql_string("^ asc"), false);
        assert_eq!(is_common_sql_string("^ desc"), false);
        assert_eq!(is_common_sql_string("% asc"), false);
        assert_eq!(is_common_sql_string("% desc"), false);
        assert_eq!(is_common_sql_string("asc $"), false);
        assert_eq!(is_common_sql_string("desc $"), false);
        assert_eq!(is_common_sql_string("asc$"), false);
        assert_eq!(is_common_sql_string("desc$"), false);
    }

    #[test]
    fn test_it_sees_table_column_pattern() {
        assert_eq!(is_common_sql_string("table.column"), true);
        assert_eq!(is_common_sql_string("views.user_id"), true);
        assert_eq!(is_common_sql_string("table_name.column_name"), true);
        assert_eq!(is_common_sql_string("table_name.column_name1"), true);
        assert_eq!(is_common_sql_string("table_name.column_name_1"), true);
        assert_eq!(is_common_sql_string("table_name.column_name_1_2"), true);
        assert_eq!(is_common_sql_string("table_name.column_1_name"), true);
        assert_eq!(is_common_sql_string("table_name.column_name_name_1"), true);
        assert_eq!(is_common_sql_string(".r"), true);
        assert_eq!(is_common_sql_string(".id"), true);
        assert_eq!(is_common_sql_string(".id_"), true);
    }

    #[test]
    fn test_it_returns_false_for_table_column_pattern_false_positive() {
        assert_eq!(is_common_sql_string(";table.column"), false);
        assert_eq!(is_common_sql_string("table.column;"), false);
        assert_eq!(is_common_sql_string("table.column "), false);
        assert_eq!(is_common_sql_string("table .column"), false);
        assert_eq!(is_common_sql_string("1_table.column"), false);
        assert_eq!(is_common_sql_string("1table.column"), false);
        assert_eq!(is_common_sql_string("= table.column"), false);
        assert_eq!(is_common_sql_string("table.column ="), false);
        assert_eq!(is_common_sql_string("table.column = "), false);
        assert_eq!(is_common_sql_string("table.column = 1"), false);
        assert_eq!(is_common_sql_string("table.column = 1;"), false);
        assert_eq!(is_common_sql_string("table.column = 1 "), false);
        assert_eq!(is_common_sql_string("table.column table.column"), false);
        assert_eq!(is_common_sql_string("table.column,table.column"), false);
    }

    #[test]
    fn test_integers() {
        assert_eq!(is_common_sql_string("-0"), true);
        assert_eq!(is_common_sql_string("-1"), true);
        assert_eq!(is_common_sql_string("-12"), true);
        assert_eq!(is_common_sql_string("-123"), true);
        assert_eq!(is_common_sql_string("-1234"), true);
        assert_eq!(is_common_sql_string("1"), true);
        assert_eq!(is_common_sql_string("12"), true);
        assert_eq!(is_common_sql_string("123"), true);
        assert_eq!(is_common_sql_string("0"), true);
    }

    #[test]
    fn test_it_returns_false_if_its_not_an_integer() {
        assert_eq!(is_common_sql_string("--1"), false);
        assert_eq!(is_common_sql_string("1--"), false);
        assert_eq!(is_common_sql_string("-1-"), false);
        assert_eq!(is_common_sql_string("-1--"), false);
        assert_eq!(is_common_sql_string("-1.0"), false);
        assert_eq!(is_common_sql_string("-1 --"), false);
        assert_eq!(is_common_sql_string("-1 "), false);
        assert_eq!(is_common_sql_string("-1;"), false);
        assert_eq!(is_common_sql_string("-1\t"), false);
        assert_eq!(is_common_sql_string("-1\n"), false);
        assert_eq!(is_common_sql_string("-1\n;"), false);
        assert_eq!(is_common_sql_string("--"), false);
        assert_eq!(is_common_sql_string("-- -1"), false);
        assert_eq!(is_common_sql_string("-1,"), false);
        assert_eq!(is_common_sql_string("-1(--)"), false);
        assert_eq!(is_common_sql_string("-1 /*"), false);
        assert_eq!(is_common_sql_string("-1 /* abc */"), false);
    }

    #[test]
    fn test_stringified_arrays() {
        assert_eq!(is_common_sql_string("[]"), true);
        assert_eq!(is_common_sql_string("[ ]"), false);
        assert_eq!(is_common_sql_string("[1]"), false);
        assert_eq!(is_common_sql_string("[[]]"), false);
    }
}
