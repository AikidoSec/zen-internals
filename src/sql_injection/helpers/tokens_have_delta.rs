// Checks if there is a delta between the length of the two token vectors.
#[macro_export]
macro_rules! tokens_have_delta {
    ($tokens1:expr, $tokens2:expr) => {
        $tokens1.len().abs_diff($tokens2.len()) != 0
    };
}
