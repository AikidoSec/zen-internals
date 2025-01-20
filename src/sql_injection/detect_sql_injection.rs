use super::have_comments_changed::have_comments_changed;
use super::is_common_sql_string::is_common_sql_string;
use super::tokenize_query::tokenize_query;
use crate::diff_in_vec_len;
use sqlparser::tokenizer::Token;

const SPACE_CHAR: char = ' ';

// `userinput` and `query` provided to this function should already be lowercase.
pub fn detect_sql_injection_str(query: &str, userinput: &str, dialect: i32) -> bool {
    if !query.contains(userinput) {
        // If the query does not contain the user input, it's not an injection.
        return false;
    }

    // "SELECT *", "INSERT INTO", ... will occur in most queries
    // If the user input is equal to any of these, we can assume it's not an injection.
    if is_common_sql_string(userinput) {
        return false;
    }

    // Remove leading and trailing spaces from user input
    let trimmed_userinput = userinput.trim_matches(SPACE_CHAR);

    if trimmed_userinput.len() <= 1 {
        // If the trimmed user input is one character or empty, no injection took place.
        return false;
    }

    // Tokenize query :
    let tokens = tokenize_with_fallback(query, dialect);
    if tokens.len() <= 0 {
        if dialect == 3 && query.contains(';') && has_multiple_statements(query, dialect) {
            // Clickhouse does not support multiple statements
            // The first statement will still be executed if of the other statements is still valid
            // We'll assume the original query is valid
            // If the query with user input replaced is valid, we'll assume it's an injection because it created a new statement
            let query_without_input = replace_user_input_with_safe_str(query, userinput);
            let tokens_without_input =
                tokenize_with_fallback(query_without_input.as_str(), dialect);

            if tokens_without_input.len() > 0 {
                return true;
            }
        }

        // Tokens are empty, probably a parsing issue with original query, return false.
        return false;
    }

    // Replace user input with string of equal length and tokenize again :
    let query_without_input = replace_user_input_with_safe_str(query, userinput);
    let tokens_without_input = tokenize_with_fallback(query_without_input.as_str(), dialect);

    // Check delta for both comment tokens and all tokens in general :
    if diff_in_vec_len!(tokens, tokens_without_input) {
        // If a delta exists in all tokens, mark this as an injection.
        return true;
    }

    if have_comments_changed(tokens, tokens_without_input) {
        // This checks if structure of comments in the query is altered after removing user input.
        // It makes sure the lengths of all single line and multiline comments are all still the same
        // And makes sure no extra comments were added or that the order was altered.
        return true;
    }

    return false;
}

fn has_multiple_statements(query: &str, dialect: i32) -> bool {
    assert!(query.contains(';'));

    for (i, c) in query.char_indices() {
        if c == ';' {
            let statement = &query[..i + 1];
            let tokens_stripped = tokenize_with_fallback(statement, dialect);
            if tokens_stripped.len() > 0 {
                if let Some(Token::SemiColon) = tokens_stripped.last() {
                    let remaining = &query[i + 1..];

                    if remaining.trim().len() <= 0 {
                        return false;
                    }

                    return true;
                    //return tokenize_query(remaining, dialect).len() <= 0;
                }
            }
        }
    }

    return false;
}

fn replace_user_input_with_safe_str(query: &str, user_input: &str) -> String {
    let trimmed_user_input = user_input.trim_matches(SPACE_CHAR);
    let safe_replace_str = "a".repeat(trimmed_user_input.len());

    query.replace(trimmed_user_input, safe_replace_str.as_str())
}

fn tokenize_with_fallback(query: &str, dialect: i32) -> Vec<Token> {
    let query_tokens = tokenize_query(query, dialect);
    if query_tokens.len() <= 0 && dialect != 0 {
        // Dialect is not generic and query_tokens are empty, make fallback
        return tokenize_query(query, 0);
    }

    return query_tokens;
}
