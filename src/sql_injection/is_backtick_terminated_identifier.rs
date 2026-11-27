use super::helpers::select_dialect_based_on_enum::select_dialect_based_on_enum;
use regex::Regex;
use sqlparser::dialect::{MySqlDialect, SQLiteDialect};
use std::sync::LazyLock;

static BACKTICK_TERMINATED_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*`$").expect("invalid regex"));

pub(super) fn is_backtick_terminated_identifier(input: &str, dialect_id: i32) -> bool {
    if !input.ends_with('`') {
        return false;
    }
    // Masking "de`" in `item_code` would remove the column's closing backtick.
    let dialect = select_dialect_based_on_enum(dialect_id);
    (dialect.is::<MySqlDialect>() || dialect.is::<SQLiteDialect>())
        && BACKTICK_TERMINATED_IDENTIFIER.is_match(input)
}
