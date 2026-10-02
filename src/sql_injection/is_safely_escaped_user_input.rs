use super::helpers::select_dialect_based_on_enum::select_dialect_based_on_enum;
use sqlparser::dialect::{ClickHouseDialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect};
use sqlparser::tokenizer::Token;

pub(super) fn is_safely_escaped_user_input(
    query: &str,
    userinput: &str,
    dialect: i32,
    tokens: &[Token],
) -> bool {
    let sql_dialect = select_dialect_based_on_enum(dialect);

    // Handle edge case where user input starts or ends with a single quote
    // You can escape single quotes by prepending them with another single quote
    // e.g. SELECT a FROM b WHERE b.a = '1; SELECT SLEEP(10) -- -''';
    //                                   ^^^^^^^^^^^^^^^^^^^^^^^^^^ 1; SELECT SLEEP(10) -- -'
    // This will only occur when the user input starts or ends with a single quote
    // We wouldn't find an exact match if there's a single quote in the middle of the user input
    let starts_or_ends_with_single_quote = userinput.starts_with('\'') || userinput.ends_with('\'');
    let supports_single_quote_escaping = sql_dialect.is::<ClickHouseDialect>()
        || sql_dialect.is::<MySqlDialect>()
        || sql_dialect.is::<SQLiteDialect>()
        || sql_dialect.is::<PostgreSqlDialect>();
    // Backslash escaping can change where a string ends, for example
    // when PostgreSQL's standard_conforming_strings setting is off.
    let query_has_backslash = query.contains('\\');

    if starts_or_ends_with_single_quote && supports_single_quote_escaping && !query_has_backslash {
        let expected_single_quotes = if userinput.starts_with('\'') { 1 } else { 0 }
            + if userinput.ends_with('\'') { 1 } else { 0 };

        let amount_of_single_quotes = userinput.matches('\'').count();
        if amount_of_single_quotes == expected_single_quotes {
            let escaped_userinput = userinput.replace('\'', "''");
            let escaped_userinput_occurrences = query.matches(&escaped_userinput).count();
            let userinput_occurrences = query.matches(userinput).count();

            if escaped_userinput_occurrences == 1 && userinput_occurrences == 1 {
                return tokens.iter().any(
                    |token| matches!(token, Token::SingleQuotedString(s) if *s == escaped_userinput),
                );
            }
        }
    }

    false
}
