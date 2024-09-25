use super::filter_comment_tokens::*;
use crate::tokens_have_delta;
use sqlparser::tokenizer::Token;

pub fn comment_structure_altered(tokens1: Vec<Token>, tokens2: Vec<Token>) -> bool {
    // First things first, we need to get these token lists both sorted :
    let tokens1_singeline = get_singleline_comments(tokens1.clone());
    let tokens2_singleline = get_singleline_comments(tokens2.clone());
    let tokens1_multiline = get_multiline_comments(tokens1);
    let tokens2_multiline = get_multiline_comments(tokens2);

    // Now we do an early true return if the lengths don't match (i.e. the structure is altered)
    if tokens_have_delta!(tokens1_singeline, tokens2_singleline) {
        return true;
    }
    if tokens_have_delta!(tokens1_multiline, tokens2_multiline) {
        return true;
    }

    // Now we check the actual structure, starting with singeline comments :
    // prefix should remain the same and the length of the comments.
    for i in 0..tokens1_singeline.len() {
        let token1_singeline = &tokens1_singeline[i];
        let token2_singeline = &tokens2_singleline[i];
        let comment1_len = token1_singeline.0.len();
        let comment2_len = token2_singeline.0.len();
        if comment1_len.abs_diff(comment2_len) != 0 {
            // The length of both comments are not the same, return true.
            return true;
        }
        if token1_singeline.1 != token2_singeline.1 {
            // The prefix differs, return true.
            return true;
        }
    }
    // Test structure for multiline comments : length of comments should be the same.
    for i in 0..tokens1_multiline.len() {
        let multiline1 = &tokens1_multiline[i];
        let multiline2 = &tokens2_multiline[i];
        if multiline1.len().abs_diff(multiline2.len()) != 0 {
            // The length of both comments are not the same, return true.
            return true;
        }
    }

    return false;
}
