use sqlparser::tokenizer::*;
pub fn is_whitespace_token(token: &Token) -> bool {
    match token {
        Token::Whitespace(_) => true,
        _ => false,
    }
}
