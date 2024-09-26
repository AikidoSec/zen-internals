use sqlparser::tokenizer::{Token, Whitespace};

/* Function `get_singleline_comments`
* Returns : Vector of a tuple (comment, prefix). Example :
*  query : `1=1 -- This is a lovely single line comment.`
*  tokens vector : [Number(..), Eq, Number(..), Whitespace(Space),
       Whitespace(SingleLineComment { comment: " This is a lovely single line comment.", prefix: "--" })]
*  Output : [(" This is a lovely single line comment.", "--")]
*/
pub fn get_singleline_comments(tokens: Vec<Token>) -> Vec<(String, String)> {
    let singleline_comments: Vec<(String, String)> = tokens
        .iter()
        .filter_map(|token| filter_tokens_for_singeline(token))
        .collect();

    return singleline_comments;
}

/* Function `get_multiline_comments`
 * Returns : Vector of all multiline comments as strings. Example :
 *  query : ``
 *  tokens vector : [Number(..), Eq, Number(..), Whitespace(Space), Whitespace(MultiLineComment(" Multiline Comment "))]
 *  Output : [" Multiline Comment "]
 */
pub fn get_multiline_comments(tokens: Vec<Token>) -> Vec<String> {
    let multiline_comments: Vec<String> = tokens
        .iter()
        .filter_map(|token| filter_tokens_for_multiline(token))
        .collect();

    return multiline_comments;
}

fn filter_tokens_for_singeline(token: &Token) -> Option<(String, String)> {
    match token {
        Token::Whitespace(whitespace) => {
            if let Whitespace::SingleLineComment { comment, prefix } = whitespace {
                return Some((comment.clone(), prefix.clone()));
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
