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

    // e.g. SELECT * FROM users WHERE name = 'hello\\'
    //                                        ^^^^^^ hello\
    let ends_with_backslash = userinput.ends_with('\\');
    let is_mysql = sql_dialect.is::<MySqlDialect>();
    if ends_with_backslash && is_mysql {
        let userinput_has_quotes = userinput.contains('\'') || userinput.contains('"');
        // Skip this shortcut if strings contain quotes because NO_BACKSLASH_ESCAPES
        // can change where strings end and we don't know the connection's SQL mode.
        let query_has_escaped_quotes = tokens.iter().any(|token| match token {
            Token::SingleQuotedString(s) | Token::NationalStringLiteral(s) => s.contains('\''),
            Token::DoubleQuotedString(s) => s.contains('"'),
            _ => false,
        });

        if !userinput_has_quotes && !query_has_escaped_quotes {
            let amount_of_backslashes = userinput.matches('\\').count();
            if amount_of_backslashes == 1 {
                let escaped_userinput = userinput.replace('\\', "\\\\");
                let escaped_occurrences = tokens
                    .iter()
                    .filter(
                        |token| matches!(token, Token::SingleQuotedString(s) if *s == escaped_userinput),
                    )
                    .count();
                let input_occurrences = query.matches(userinput).count();

                if escaped_occurrences > 0 && escaped_occurrences == input_occurrences {
                    return true;
                }
            }
        }
    }

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
