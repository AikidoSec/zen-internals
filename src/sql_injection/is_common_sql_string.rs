use regex::Regex;

pub const COMMON_SQL_STRINGS: [&str; 23] = [
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
    "NOT EXISTS",
    "DISTINCT ON",
];

pub fn is_common_sql_string(user_input: &str) -> bool {
    let is_common_sql_string = COMMON_SQL_STRINGS
        .iter()
        .map(|s| s.to_lowercase())
        .any(|common_string| user_input == common_string);

    if is_common_sql_string {
        return true;
    }

    if user_input.contains("asc") || user_input.contains("desc") {
        // Check if the user input is a common SQL pattern like "column_name ASC"
        // e.g. https://ghost.org/docs/content-api/#order (Ghost validates the order parameter)
        let looks_like_order_by: Regex =
            Regex::new(r"(?i)^[a-zA-Z_][a-zA-Z0-9_]* +(ASC|DESC)$").unwrap();

        return looks_like_order_by.is_match(user_input);
    }

    return false;
}
