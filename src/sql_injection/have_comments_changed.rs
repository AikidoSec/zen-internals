use super::filter_for_comment_tokens::filter_for_comment_tokens;
use crate::diff_in_vec_len;
use sqlparser::tokenizer::{Token, Whitespace};

/*
 * Takes in token input from two queries, and filters them using get_singleline_comments and
 * get_multiline_comments (See filter_comment_tokens.rs). Afterwards makes these checks  :
 * - Makes sure amount of singleline & multiline comments remains the same
 * - Makes sure the prefix and length of comment remains the same for singeline
 * - Makes sure the length of the comment remains the same for multiline
 */
pub fn have_comments_changed(tokens1: Vec<Token>, tokens2: Vec<Token>) -> bool {
    // Filter token vectors based on type (singleline and multiline)
    let comments1: Vec<Whitespace> = filter_for_comment_tokens(tokens1);
    let comments2: Vec<Whitespace> = filter_for_comment_tokens(tokens2);

    // Do an early return if the lengths don't match -> structure is different.
    if diff_in_vec_len!(comments1, comments2) {
        return true;
    }

    // Loop over comments :
    for i in 0..comments1.len() {
        let comment1: Whitespace = comments1[i].clone();
        let comment2: Whitespace = comments2[i].clone();
        if let Whitespace::SingleLineComment { comment, prefix } = comment1 {
            if whitespace_differs_from_singleline(comment, prefix, comment2) {
                return true;
            }
        } else if let Whitespace::MultiLineComment(comment) = comment1 {
            if whitespace_differs_from_multiline(comment, comment2) {
                return true;
            }
        }
    }

    return false;
}

/* Optimalization to keep in mind : We only check length of comments since in case of attack
 *      the length of the comment will only be able to increase.
*/
fn whitespace_differs_from_singleline(
    comment1: String,
    prefix1: String,
    whitespace2: Whitespace,
) -> bool {
    match whitespace2 {
        Whitespace::SingleLineComment { comment, prefix } => {
            if comment.len().abs_diff(comment1.len()) != 0 {
                // The length of both comments are not the same which means the structure is altered
                // This could mean e.g. that due to an injection a comment has been made longer.
                return true;
            }
            if prefix != prefix1 {
                // The prefixes differ for both comments (e.g. Prefix of -- Good Afternoon is "--")
                // If prefixes differ this is a sign that comment structure was altered
                return true;
            }
            return false;
        }
        _ => true, // So if it's a multiline whitespace for example.
    }
}

/* Optimalization to keep in mind : We only check length of comments since in case of attack
 *      the length of the comment will only be able to increase.
*/
fn whitespace_differs_from_multiline(comment1: String, whitespace2: Whitespace) -> bool {
    match whitespace2 {
        // The length of both comments are not the same -> Strucutre is altered.
        Whitespace::MultiLineComment(comment2) => comment2.len().abs_diff(comment1.len()) != 0,
        _ => true, // So if it's a singleline whitespace for example.
    }
}
