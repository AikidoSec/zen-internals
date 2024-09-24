use super::is_whitespace_token::is_whitespace_token;
use super::tokenize_query::tokenize_query;
use sqlparser::tokenizer::Token;

pub fn detect_sql_injection_str(query: &str, userinput: &str, dialect: i32) -> bool {
    if userinput.chars().all(char::is_alphanumeric) {
        // Userinput is alphanumerical, ignore.
        return false;
    }
    if userinput.len() <= 3 || query.len() < userinput.len() {
        // Ignore small user input or a query that's too small.
        return false;
    }

    // Lowercase both query and userinput
    let query_lower: &str = &query.to_lowercase();
    let userinput_lower: &str = &userinput.to_lowercase();

    if !query_lower.contains(userinput_lower) {
        // Userinput is not inside query, so not an injection.
        return false;
    }

    // Tokenize query :
    let tokens = tokenize_with_fallback(query, dialect);
    if tokens.len() <= 0 {
        // Tokens are empty, probably a parsing issue, return false.
        return false;
    }
    // Tokenize query without user input :
    // We replace with "COUNT" since this is a Word and matched as a safe token.
    let query_without_input: &str = &query_lower.replace(userinput_lower, "COUNT");
    let tokens_without_input = tokenize_with_fallback(query_without_input, dialect);

    // Return true if a delta exists, because this indicates a possible injection :
    return delta_dangerous_tokens(tokens, tokens_without_input) != 0;
}

fn tokenize_with_fallback(query: &str, dialect: i32) -> Vec<Token> {
    let query_tokens = tokenize_query(query, dialect);
    if query_tokens.len() <= 0 && dialect != 0 {
        // Dialect is not generic and query_tokens are empty, make fallback
        return tokenize_query(query, 0);
    }
    return query_tokens;
}

fn delta_dangerous_tokens(tokens1: Vec<Token>, tokens2: Vec<Token>) -> usize {
    let dangerous_tokens1: Vec<_> = tokens1
        .iter()
        .filter(|&token| is_dangerous_token(token))
        .collect();
    let dangerous_tokens2: Vec<_> = tokens2
        .iter()
        .filter(|&token| is_dangerous_token(token))
        .collect();

    return dangerous_tokens2.len() - dangerous_tokens1.len();
}
