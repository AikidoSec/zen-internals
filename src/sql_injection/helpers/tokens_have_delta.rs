use sqlparser::tokenizer::Token;

// Checks if there is a delta between the length of the two tokens.
pub fn tokens_have_delta(tokens1: Vec<Token>, tokens2: Vec<Token>) -> bool {
    let delta: usize = tokens1.len().abs_diff(tokens2.len());
    return delta != 0;
}
