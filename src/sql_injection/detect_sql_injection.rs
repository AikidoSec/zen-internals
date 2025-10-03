use super::have_comments_changed::have_comments_changed;
use super::is_common_sql_string::is_common_sql_string;
use super::tokenize_query::tokenize_query;
use crate::diff_in_vec_len;

const SPACE_CHAR: char = ' ';
pub struct SqlInjectionDetectionResult {
    pub detected: bool,
    pub reason: DetectionReason,
}
pub enum DetectionReason {
    // not an injection
    UserInputNotInQuery,
    CommonSQLString,
    FailedToTokenizeQuery,
    UserInputTooSmall,
    NoChangesFound,
    // injection
    TokensHaveDelta,
    CommentStructureAltered,
}

// `userinput` and `query` provided to this function should already be lowercase.
pub fn detect_sql_injection_str(
    query_raw: &str,
    userinput_raw: &str,
    dialect: i32,
) -> SqlInjectionDetectionResult {
    let query: String = query_raw.to_lowercase();
    let userinput: String = userinput_raw.to_lowercase();

    if !query.contains(&userinput) {
        // If the query does not contain the user input, it's not an injection.
        return SqlInjectionDetectionResult {
            detected: false,
            reason: DetectionReason::UserInputNotInQuery,
        };
    }

    // "SELECT *", "INSERT INTO", ... will occur in most queries
    // If the user input is equal to any of these, we can assume it's not an injection.
    if is_common_sql_string(&userinput) {
        return SqlInjectionDetectionResult {
            detected: false,
            reason: DetectionReason::CommonSQLString,
        };
    }

    // Tokenize query :
    let tokens = tokenize_query(&query, dialect);
    if tokens.len() <= 0 {
        // Tokens are empty, probably a parsing issue with original query, return false.
        return SqlInjectionDetectionResult {
            detected: false,
            reason: DetectionReason::FailedToTokenizeQuery,
        };
    }

    // Remove leading and trailing spaces from userinput :
    let trimmed_userinput = userinput.trim_matches(SPACE_CHAR);

    // Tokenize query without user input :
    if trimmed_userinput.len() <= 1 {
        // If the trimmed userinput is one character or empty, no injection took place.
        return SqlInjectionDetectionResult {
            detected: false,
            reason: DetectionReason::UserInputTooSmall,
        };
    }

    // Replace user input with string of equal length and tokenize again :
    let safe_replace_str = "a".repeat(trimmed_userinput.len());
    let query_without_input: &str = &query.replace(trimmed_userinput, safe_replace_str.as_str());
    let tokens_without_input = tokenize_query(query_without_input, dialect);

    // Check delta for both comment tokens and all tokens in general :
    if diff_in_vec_len!(tokens, tokens_without_input) {
        // If a delta exists in all tokens, mark this as an injection.
        return SqlInjectionDetectionResult {
            detected: true,
            reason: DetectionReason::TokensHaveDelta,
        };
    }

    if have_comments_changed(tokens, tokens_without_input) {
        // This checks if structure of comments in the query is altered after removing user input.
        // It makes sure the lengths of all single line and multiline comments are all still the same
        // And makes sure no extra comments were added or that the order was altered.
        return SqlInjectionDetectionResult {
            detected: true,
            reason: DetectionReason::CommentStructureAltered,
        };
    }

    return SqlInjectionDetectionResult {
        detected: false,
        reason: DetectionReason::NoChangesFound,
    };
}
