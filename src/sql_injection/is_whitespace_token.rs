use sqlparser::tokenizer::{Token, Whitespace};
pub fn is_whitespace_token(token: &Token) -> bool {
    match token {
        Token::Whitespace(_) => true,
        _ => false,
    }
}

pub fn is_singleline_comment(token: &Token) -> bool {
    match token {
        Token::Whitespace(whitespace) => match whitespace {
            Whitespace::SingleLineComment { .. } => true,
            _ => false,
        },
        _ => false,
    }
}

pub fn is_multiline_comment(token: &Token) -> bool {
    match token {
        Token::Whitespace(whitespace) => match whitespace {
            Whitespace::MultiLineComment(_) => true,
            _ => false,
        },
        _ => false,
    }
}
