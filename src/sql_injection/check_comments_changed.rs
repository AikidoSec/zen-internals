use super::filter_comment_tokens::*;
use crate::diff_in_vec_len;
use sqlparser::tokenizer::Token;

/*
 * Takes in token input from two queries, and filters them using get_singleline_comments and
 * get_multiline_comments (See filter_comment_tokens.rs). Afterwards makes these checks  :
 * - Makes sure amount of singleline & multiline comments remains the same
 * - Makes sure the prefix and length of comment remains the same for singeline
 * - Makes sure the length of the comment remains the same for multiline
 */
pub fn check_comments_changed(tokens1: Vec<Token>, tokens2: Vec<Token>) -> bool {
    // Filter token vectors based on type (singleline and multiline)
    let singlelines1 = get_singleline_comments(tokens1.clone());
    let singlelines2 = get_singleline_comments(tokens2.clone());
    let multilines1 = get_multiline_comments(tokens1);
    let multilines2 = get_multiline_comments(tokens2);

    // Do an early return if the lengths don't match -> structure is different.
    if diff_in_vec_len!(singlelines1, singlelines2) || diff_in_vec_len!(multilines1, multilines2) {
        return true;
    }

    // Check if the structure of singleline and/or multiline comments is altered.
    if structure_of_singlelines_altered(singlelines1, singlelines2) {
        return true;
    }
    if structure_of_multilines_altered(multilines1, multilines2) {
        return true;
    }

    return false;
}

/* Function structure_of_singlelines_altered
 * Returns true if the structure of the vectors of single lines does not match (i.e. prefix or comment length)
 * Optimalization to keep in mind : We only check length of comments since in case of attack
 *      the length of the comment will only be able to increase.
 */
fn structure_of_singlelines_altered(
    singlelines1: Vec<(String, String)>,
    singlelines2: Vec<(String, String)>,
) -> bool {
    for i in 0..singlelines1.len() {
        let singleline1 = &singlelines1[i];
        let singleline2 = &singlelines2[i];

        // the first element (.0) of a single line tuple is the comment : (i.e. "Good Afternoon" in -- Good Afternoon)
        let comment1_len = singleline1.0.len();
        let comment2_len: usize = singleline2.0.len();
        if comment1_len.abs_diff(comment2_len) != 0 {
            // The length of both comments are not the same which means the structure is altered
            // This could mean e.g. that due to an injection a comment has been made longer.
            return true;
        }
        if singleline1.1 != singleline2.1 {
            // The second element (.1) contains prefix.
            // The prefixes differ for both comments (e.g. Prefix of -- Good Afternoon is "--")
            // If prefixes differ this is a sign that comment structure was altered
            return true;
        }
    }

    return false;
}

fn structure_of_multilines_altered(multilines1: Vec<String>, multilines2: Vec<String>) -> bool {
    for i in 0..multilines1.len() {
        let multiline1 = &multilines1[i];
        let multiline2 = &multilines2[i];
        if multiline1.len().abs_diff(multiline2.len()) != 0 {
            // The length of both comments are not the same -> Strucutre is altered.
            return true;
        }
    }
    return false;
}
