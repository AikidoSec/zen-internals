use sqlparser::tokenizer::{Token, Whitespace};

/* Function filter_for_comments_tokens,
 * Filters token vectors and returns a new Vector with only Whitespace: either Multiline,
 * or singleline comments. Example :
 *  tokens vector : [Number(..), Eq, Number(..), Token::Whitespace(Space), Token::Whitespace(MultiLineComment(" Multiline Comment "))]
 *  output : [Whitespace(MultiLineComment(" Multiline Comment ")] (Returns whitespace vector)
 */
pub fn filter_for_comment_tokens(tokens: Vec<Token>) -> Vec<Whitespace> {
    let mut comments_vector: Vec<Whitespace> = Vec::new();
    for token in tokens {
        if let Token::Whitespace(whitespace) = token {
            // Token is whitespace, if this token is singleline comment or multiline,
            // Add to comments_vector.
            let whitespace_is_comment = match whitespace {
                Whitespace::SingleLineComment { .. } => true,
                Whitespace::MultiLineComment(_) => true,
                _ => false,
            };
            if whitespace_is_comment {
                comments_vector.push(whitespace);
            }
        }
    }
    comments_vector
}
