use regex::Regex;
use std::sync::LazyLock;

pub const COMMON_SQL_STRINGS: [&str; 27] = [
    "SELECT *",
    "SELECT COUNT(*)",
    "INSERT INTO",
    "INNER JOIN",
    "LEFT JOIN",
    "RIGHT JOIN",
    "LEFT OUTER JOIN",
    "RIGHT OUTER JOIN",
    "DELETE FROM",
    "ORDER BY",
    "GROUP BY",
    "ON CONFLICT",
    "ON CONFLICT DO UPDATE",
    "ON CONFLICT DO NOTHING",
    "ON DUPLICATE KEY",
    "ON DUPLICATE KEY UPDATE",
    "DO UPDATE",
    "DO NOTHING",
    "COUNT(*)",
    "IS NULL",
    "IS NOT NULL",
    "IS NOT",
    "NOT EXISTS",
    "DISTINCT ON",
    "[]",
    "NOT IN",
    "TIME ZONE",
];

// Macro to create a static regex that is compiled only once.
macro_rules! regex {
    ($re:expr $(,)?) => {{
        static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new($re).expect("invalid regex"));
        &*RE
    }};
}

pub fn is_common_sql_string(user_input: &str) -> bool {
    let is_common_sql_string = COMMON_SQL_STRINGS
        .iter()
        .map(|s| s.to_lowercase())
        .any(|common_string| user_input == common_string);

    if is_common_sql_string {
        return true;
    }

    if user_input.len() <= 5 && regex!(r"^[a-z]+ [a-z]+$").is_match(user_input) {
        // It's very difficult to exploit a query using a short string of only letters and space.
        return true;
    }

    // Allow short strings with letters, digits and spaces
    // e.g. `select * from "table" where "id" = $1 limit $2`
    //                                           ^^^ `1 l`
    if user_input.len() <= 3 && regex!(r"^[ 0-9a-z]+$").is_match(user_input) {
        return true;
    }

    // e.g. SELECT * FROM users WHERE users.active= 1
    // If the payload is `e=` the replaced query will be
    // SELECT * FROM users WHERE users.activaa 1
    // The structure of the query will not be the same
    // it's very difficult to exploit a query using just "e=" as the user input.
    if user_input.len() == 2
        && user_input.ends_with("=")
        && regex!(r"^[a-z]=$").is_match(user_input)
    {
        // If the user input is just a single letter followed by an equal sign, it's not an injection.
        return true;
    }

    if user_input.contains("asc") || user_input.contains("desc") {
        // Check if the user input is a common SQL pattern like "column_name ASC"
        // e.g. https://ghost.org/docs/content-api/#order (Ghost validates the order parameter)
        // SQL identifiers can't start with a number
        return regex!(r"^[a-z_][a-z0-9_]* +(asc|desc)$").is_match(user_input);
    }

    // For the following exemptions there is a consideration to be made that allowing this user input
    // could mean an injection happens with a 2nd field. However this seems unlikely as that 2nd field
    // is also subject to the same scans, so it would be having to use exemptions for both of the fields
    // to cause an injection.
    // example: SELECT * FROM users WHERE user_id = '${user id}' AND name = '${user_name}'

    // e.g. 'a or '1 or 'product-id-123
    if user_input.starts_with("'") && user_input.len() <= 200 && !user_input.contains("--") {
        if regex!(r"^'[a-z0-9-]+$").is_match(user_input) {
            return true;
        }
    }

    // e.g. a' or 1' or product-id-123'
    if user_input.ends_with("'") && user_input.len() <= 200 && !user_input.contains("--") {
        if regex!(r"^[a-z0-9-]+'$").is_match(user_input) {
            return true;
        }
    }

    // e.g. "a or "1 or "product-id-123
    if user_input.starts_with("\"") && user_input.len() <= 200 && !user_input.contains("--") {
        if regex!(r#"^"[a-z0-9-]+$"#).is_match(user_input) {
            return true;
        }
    }

    // e.g. a" or 1" or product-id-123"
    if user_input.ends_with("\"") && user_input.len() <= 200 && !user_input.contains("--") {
        if regex!(r#"^[a-z0-9-]+"$"#).is_match(user_input) {
            return true;
        }
    }

    if user_input.contains(".") {
        // Check if it is just a decimal (e.g. `16.2`)
        if regex!(r"^-?[0-9]+\.[0-9]+$").is_match(user_input) {
            return true;
        }

        // Check if the user input looks like a table.column pattern
        // e.g. SELECT * FROM table WHERE table.redirect_uri = 'value'
        // If the payload is `.r` the replaced query will be
        // SELECT * FROM table WHERE tableaaedirect_uri = 'value'
        // The structure changes from table.column_name to just column_name
        //
        // This pattern catches:
        // - `table.column`
        // - `table.`
        // - `.column`
        let looks_like_table_column =
            regex!(r"^(\.[a-z_][a-z0-9_]*|[a-z_][a-z0-9_]*\.|[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)$");

        return looks_like_table_column.is_match(user_input);
    }

    // Allow integers like `1`, `-1` or `-2`
    // We have to be careful with minus signs, as they can be used for SQL injections
    if regex!(r"^-?[0-9]+$").is_match(user_input) {
        return true;
    }

    return false;
}
