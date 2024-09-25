use super::comment_structure_altered::comment_structure_altered;
use super::tokenize_query::tokenize_query;
use crate::tokens_have_delta;
use sqlparser::tokenizer::Token;

// `userinput` and `query` provided to this function should already be lowercase.
pub fn detect_sql_injection_str(query: &str, userinput: &str, dialect: i32) -> bool {
    // Tokenize query :
    let tokens = tokenize_with_fallback(query, dialect);
    if tokens.len() <= 0 {
        // Tokens are empty, probably a parsing issue with original query, return false.
        return false;
    }

    // Tokenize query without user input :
    let query_without_input: &str = &query.replace(userinput, "str");
    let tokens_without_input = tokenize_with_fallback(query_without_input, dialect);

    // Check delta for both comment tokens and all tokens in general :
    if tokens_have_delta!(tokens, tokens_without_input) {
        // If a delta exists in all tokens, mark this as an injection.
        return true;
    }
    return comment_structure_altered(tokens, tokens_without_input);
}

fn tokenize_with_fallback(query: &str, dialect: i32) -> Vec<Token> {
    let query_tokens = tokenize_query(query, dialect);
    if query_tokens.len() <= 0 && dialect != 0 {
        // Dialect is not generic and query_tokens are empty, make fallback
        return tokenize_query(query, 0);
    }
    return query_tokens;
}
