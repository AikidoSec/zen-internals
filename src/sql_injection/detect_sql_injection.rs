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

    // Tokenize query :
    let tokens = tokenize_with_fallback(query, dialect);

    // Tokens are empty, this means that the query is invalid
    if tokens.len() <= 0 {
        if dialect == 3 && extra_statement_was_created_by_user_input(query, userinput, dialect) {
            // Clickhouse does not support multiple statements
            // The first statement will still be executed if the other statements are invalid
            // We'll assume the original query is valid
            // If the query with user input replaced is valid, we'll assume it's an injection because it created a new statement
            return true;
        }

        // If the query is invalid, we can't determine if it's an injection
        return false;
    }

    // Remove leading and trailing spaces from userinput :
    let trimmed_userinput = userinput.trim_matches(SPACE_CHAR);

    if trimmed_userinput.len() <= 1 {
        // If the trimmed userinput is one character or empty, no injection took place.
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

fn extra_statement_was_created_by_user_input(query: &str, userinput: &str, dialect: i32) -> bool {
    if !has_multiple_statements(query, dialect) {
        return false;
    }

    let query_without_input = replace_user_input_with_safe_str(query, userinput);
    let tokens_without_input = tokenize_with_fallback(query_without_input.as_str(), dialect);

    if tokens_without_input.len() <= 0 {
        // Invalid query without user input
        return false;
    }

    return is_single_statement(&tokens_without_input);
}

fn is_single_statement(tokens: &Vec<Token>) -> bool {
    let has_semicolon = tokens.iter().any(|x| matches!(x, Token::SemiColon));

    if !has_semicolon {
        return true;
    }

    matches!(tokens.last(), Some(Token::SemiColon)) && has_semicolon
}

/// Check if the query has multiple statements
/// The other statements can be invalid
fn has_multiple_statements(query: &str, dialect: i32) -> bool {
    if !query.contains(';') {
        return false;
    }

    // Find the first valid statement and see if there's anything left
    for (i, c) in query.char_indices() {
        if c == ';' {
            let statement = &query[..i + 1];
            let tokens = tokenize_with_fallback(statement, dialect);
            if tokens.len() > 0 {
                if let Some(Token::SemiColon) = tokens.last() {
                    let remaining = &query[i + 1..];

                    return remaining.trim().len() > 0;
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
