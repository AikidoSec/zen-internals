use super::have_comments_changed::have_comments_changed;
use super::is_common_sql_string::is_common_sql_string;
use super::tokenize_query::tokenize_query;
use crate::diff_in_vec_len;
use crate::helpers::find_all_matches::find_all_matches;
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
    if tokens.len() <= 0 {
        // Tokens are empty, probably a parsing issue with original query, return false.
        return false;
    }

    // Special case for single or double quotes at start and/or end of user input
    // Normally if the user input is properly escaped, we wouldn't find an exact match in the query
    // However, if the user input is `'value` and single quote is used to escape
    // `'value` becomes `'''value'` in the query so we still find an exact match
    if userinput.contains("'") || userinput.contains(r#"""#) {
        let mut matches = find_all_matches(query, userinput).len();

        fn is_quoted_match(input: &str, userinput: &str, quote: char) -> bool {
            let quoted_start = format!("{quote}{userinput}");
            let quoted_end = format!("{userinput}{quote}");
            let fully_quoted = format!("{quote}{userinput}{quote}");

            input == quoted_start || input == quoted_end || input == fully_quoted
        }

        for token in tokens.iter() {
            match token {
                Token::SingleQuotedString(s) if is_quoted_match(s, userinput, '\'') => matches -= 1,
                Token::DoubleQuotedString(s) if is_quoted_match(s, userinput, '"') => matches -= 1,
                _ => {}
            }
        }

        if matches == 0 {
            // All matches were found in strings, so it's not an injection.
            return false;
        }
    }

    // Remove leading and trailing spaces from userinput :
    let trimmed_userinput = userinput.trim_matches(SPACE_CHAR);

    // Tokenize query without user input :
    if trimmed_userinput.len() <= 1 {
        // If the trimmed userinput is one character or empty, no injection took place.
        return false;
    }

    // Replace user input with string of equal length and tokenize again :
    let safe_replace_str = "a".repeat(trimmed_userinput.len());
    let query_without_input: &str = &query.replace(trimmed_userinput, safe_replace_str.as_str());
    let tokens_without_input = tokenize_with_fallback(query_without_input, dialect);

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

fn tokenize_with_fallback(query: &str, dialect: i32) -> Vec<Token> {
    let query_tokens = tokenize_query(query, dialect);
    if query_tokens.len() <= 0 && dialect != 0 {
        // Dialect is not generic and query_tokens are empty, make fallback
        return tokenize_query(query, 0);
    }

    return query_tokens;
}
