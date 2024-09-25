use crate::sql_injection::helpers::select_dialect_based_on_enum::select_dialect_based_on_enum;
use sqlparser::tokenizer::*;

pub fn tokenize_query(sql: &str, dialect: i32) -> Vec<Token> {
    let dialect = select_dialect_based_on_enum(dialect);
    /*
    "When [unescape mode] is false, the tokenizer provides the raw strings as provided
    in the query.  This can be helpful for programs that wish to
    recover the *exact* original query text without normalizing
    the escaping" ~ https://github.com/sqlparser-rs/sqlparser-rs/blob/main/src/tokenizer.rs#L591-L620
    */
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql).with_unescape(false);
    match tokenizer.tokenize() {
        Ok(tokens) => tokens, // Return the tokens if successful
        Err(e) => {
            println!("Tokenization error: {}", e);
            Vec::new() // Return empty vector if unsuccessfull.
        }
    }
}
