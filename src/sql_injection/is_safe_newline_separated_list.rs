use super::have_comments_changed::have_comments_changed;
use super::tokenize_query::tokenize_query;
use regex::Regex;
use sqlparser::tokenizer::Token;
use std::sync::LazyLock;

static NUMBER_LIST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9., \r\n]+$").expect("invalid regex"));

/// Allows comma separated number lists that contain newlines,
/// e.g. `1234,\n56789,\n23456` from `... IN (1234,\n56789,\n23456)`.
///
/// A newline ends a single line comment (`-- ...`, `# ...`), so if the input is inside one,
/// the rest of that line would run as SQL. Therefore the input is only considered safe if
/// replacing it with a harmless string of equal length leaves the comments unchanged.
pub(super) fn is_safe_newline_separated_list(
    query: &str,
    userinput: &str,
    tokens: &[Token],
    dialect: i32,
) -> bool {
    if !userinput.contains(['\n', '\r'])
        || !userinput.contains(',')
        || !userinput.bytes().any(|b| b.is_ascii_digit())
        || !NUMBER_LIST.is_match(userinput)
    {
        return false;
    }

    let trimmed_userinput = userinput.trim_matches(' ');
    let safe_replace_str = "a".repeat(trimmed_userinput.len());
    let query_without_input = query.replace(trimmed_userinput, safe_replace_str.as_str());
    let tokens_without_input = tokenize_query(&query_without_input, dialect);

    // We only compare comments here, not the token count
    // as (1234,\n56789,\n23456) -> (aaaa...) always changes the token count
    !have_comments_changed(tokens.to_vec(), tokens_without_input)
}
