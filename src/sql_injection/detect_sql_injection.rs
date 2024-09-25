use super::comment_structure_altered::comment_structure_altered;
use super::tokenize_query::tokenize_query;
use crate::tokens_have_delta;
use sqlparser::{
    keywords::Keyword,
    tokenizer::{Token, Whitespace},
};

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
        if userinput_is_safe(userinput, dialect) {
            // Do a check on the user input, if it's safe we can safely ignore the delta.
            return false;
        }
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

fn userinput_is_safe(userinput: &str, dialect: i32) -> bool {
    // Check if userinput is only spaces and NoKeyword's, we regard this as safe
    let userinput_tokens: Vec<Token> = tokenize_with_fallback(userinput, dialect);
    if userinput_tokens.len() <= 0 {
        // Length of tokens is zero or lower, sql probably invalid, we can not mark this as safe.
        return false;
    }
    return userinput_tokens.iter().all(is_safe_userinput_token);
}

fn is_safe_userinput_token(token: &Token) -> bool {
    // Returns true if the token is a space or a word that isn't a sql keyword.
    if let Token::Whitespace(whitespace) = token {
        if let Whitespace::Space = whitespace {
            return true;
        }
    } else if let Token::Word(word) = token {
        if let Keyword::NoKeyword = word.keyword {
            return true;
        }
    }
    return false;
}
