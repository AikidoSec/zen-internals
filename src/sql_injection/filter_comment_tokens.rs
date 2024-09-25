use sqlparser::tokenizer::{Token, Whitespace};

pub fn get_singleline_comments(tokens: Vec<Token>) -> Vec<[String; 2]> {
    let singleline_comments: Vec<[String; 2]> = tokens
        .iter()
        .filter_map(|token| filter_tokens_for_singeline(token))
        .collect();

    return singleline_comments;
}

pub fn get_multiline_comments(tokens: Vec<Token>) -> Vec<String> {
    let multiline_comments: Vec<String> = tokens
        .iter()
        .filter_map(|token| filter_tokens_for_multiline(token))
        .collect();

    return multiline_comments;
}

fn filter_tokens_for_singeline(token: &Token) -> Option<[String; 2]> {
    match token {
        Token::Whitespace(whitespace) => {
            if let Whitespace::SingleLineComment { comment, prefix } = whitespace {
                return Some([comment.clone(), prefix.clone()]);
            }
            return None;
        }
        _ => None,
    }
}

fn filter_tokens_for_multiline(token: &Token) -> Option<String> {
    match token {
        Token::Whitespace(whitespace) => {
            if let Whitespace::MultiLineComment(comment) = whitespace {
                return Some(comment.clone());
            }
            return None;
        }
        _ => None,
    }
}
