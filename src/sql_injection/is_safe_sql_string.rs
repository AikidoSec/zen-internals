use crate::sql_injection::tokenize_query::tokenize_query;
use sqlparser::tokenizer::{Token, Whitespace};

pub fn is_safe_sql_string(user_input: &str, dialect: i32) -> bool {
    let tokens = tokenize_query(user_input, dialect);

    if tokens.len() == 0 {
        return false;
    }

    tokens.iter().all(|token| match token {
        Token::Minus => true,                         // Allow minus sign
        Token::Comma => true,                         // Allow commas
        Token::Whitespace(Whitespace::Space) => true, // Allow spaces
        Token::Whitespace(Whitespace::Tab) => true,   // Allow tabs
        Token::Number(_, _) => true,                  // Allow numbers
        _ => false,                                   // Returns `false` for all other tokens
    })
}
