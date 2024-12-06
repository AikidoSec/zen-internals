use crate::diff_in_vec_len;
use oxc::allocator::Vec;
use oxc::ast::Comment;

pub fn have_comments_changed(comments1: &Vec<Comment>, comments2: &Vec<Comment>) -> bool {
    // Check if the count of comments did not change
    if diff_in_vec_len!(comments1, comments2) {
        return true;
    }

    // Check if the comments are the same
    for i in 0..comments1.len() {
        let comment1 = &comments1[i];
        let comment2 = &comments2[i];

        // Check if the length of each comment is the same
        let comment1_len = comment1.span.end - comment1.span.start;
        let comment2_len = comment2.span.end - comment2.span.start;
        if comment1_len != comment2_len {
            return true;
        }
    }

    return false;
}
