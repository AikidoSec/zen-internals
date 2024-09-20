use sqlparser::dialect::*;
use sqlparser::tokenizer::*;

pub fn detect_sql_injection(query: &str, userinput: &str) -> bool {
    false
}
