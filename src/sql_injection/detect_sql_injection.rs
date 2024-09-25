use super::is_whitespace_token::is_whitespace_token;
use super::tokenize_query::tokenize_query;
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

    // Check delta for both whitespace tokens and all tokens in general :
    let tokens_general_delta = tokens.len().abs_diff(tokens_without_input.len());
    if tokens_general_delta != 0 {
        // If a delta exists in all tokens, mark this as an injection.
        return true;
    }
    let tokens_whitespace_delta = delta_whitespace_tokens(tokens, tokens_without_input);
    if tokens_whitespace_delta != 0 {
        // A delta exists in whitespace tokens, regardless of input the amount of whitespace
        // tokens, like comments, should remain the same.
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

fn delta_whitespace_tokens(tokens1: Vec<Token>, tokens2: Vec<Token>) -> usize {
    let dangerous_tokens1: Vec<_> = tokens1
        .iter()
        .filter(|&token| is_whitespace_token(token))
        .collect();
    let dangerous_tokens2: Vec<_> = tokens2
        .iter()
        .filter(|&token| is_whitespace_token(token))
        .collect();

    return dangerous_tokens2.len().abs_diff(dangerous_tokens1.len());
}
