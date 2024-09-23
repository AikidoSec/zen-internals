use super::is_dangerous_token::is_dangerous_token;
use super::tokenize_query::tokenize_query;

pub fn detect_sql_injection_str(query: &str, userinput: &str, dialect: i32) -> bool {
    if userinput.len() <= 3 || query.len() < userinput.len() {
        // Ignore small user input or a query that's too small.
        return false;
    }
    if !query.contains(userinput) {
        // Userinput is not inside query, so not an injection.
        return false;
    }
    // Count dangerous tokens in query :
    let dangerous_tokens = count_dangerous_tokens(query, dialect);

    // Count dangerous tokens in query without user input :
    // We replace with "COUNT" since this is a Word and matched as a safe token.
    let query_without_input: &str = &query.replace(userinput, "COUNT");
    let dangerous_tokens_without_input = count_dangerous_tokens(query_without_input, dialect);

    println!(
        "Dangerous Tokens with input : {}, Dangerous tokens without input : {}",
        dangerous_tokens, dangerous_tokens_without_input
    );
    // If the amount of dangerous tokens does not match this probably means an injection took place.
    dangerous_tokens != dangerous_tokens_without_input
}

fn count_dangerous_tokens(query: &str, dialect: i32) -> usize {
    let query_tokens = tokenize_query(query, dialect);
    let dangerous_tokens: Vec<_> = query_tokens
        .iter()
        .filter(|&token| is_dangerous_token(token))
        .collect();
    return dangerous_tokens.len();
}
