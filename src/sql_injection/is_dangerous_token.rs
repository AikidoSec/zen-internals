use sqlparser::ast::DollarQuotedString;
use sqlparser::keywords::Keyword;
use sqlparser::tokenizer::*;

// Safe string tokens :
// https://github.com/sqlparser-rs/sqlparser-rs/blob/affe8b549884a351ead4f35aa8bdf4cae8c93e4b/src/tokenizer.rs#L65C1-L105C30
const SAFE_STRING_TOKENS: [Token; 17] = [
    Token::SingleQuotedString(String::new()), // Placeholder, as we need a String
    Token::DoubleQuotedString(String::new()), // Placeholder, as we need a String
    Token::TripleSingleQuotedString(String::new()), // Triple single quoted strings
    Token::TripleDoubleQuotedString(String::new()), // Triple double quoted strings
    Token::DollarQuotedString(DollarQuotedString {
        value: String::new(),
        tag: None,
    }), // Dollar quoted string
    Token::SingleQuotedByteStringLiteral(String::new()), // Byte string literal
    Token::DoubleQuotedByteStringLiteral(String::new()), // Byte string literal
    Token::TripleSingleQuotedByteStringLiteral(String::new()), // Triple single quoted byte string
    Token::TripleDoubleQuotedByteStringLiteral(String::new()), // Triple double quoted byte string
    Token::SingleQuotedRawStringLiteral(String::new()), // Single quoted raw string
    Token::DoubleQuotedRawStringLiteral(String::new()), // Double quoted raw string
    Token::TripleSingleQuotedRawStringLiteral(String::new()), // Triple single quoted raw string
    Token::TripleDoubleQuotedRawStringLiteral(String::new()), // Triple double quoted raw string
    Token::NationalStringLiteral(String::new()), // National string literal
    Token::EscapedStringLiteral(String::new()), // Escaped string literal
    Token::UnicodeStringLiteral(String::new()), // Unicode string literal
    Token::HexStringLiteral(String::new()),   // Hexadecimal string literal
];

// General safe tokens :
const GENERAL_SAFE_TOKENS: [Token; 3] = [
    Token::EOF, // An end-of-file marker, not a real token
    Token::Word(Word {
        value: String::new(),
        quote_style: None,
        keyword: Keyword::DEFAULT,
    }), // A keyword (like SELECT) or an optionally quoted SQL identifier
    Token::Whitespace(Whitespace::MultiLineComment(String::new())), // Whitespace (space, tab, etc)
];

pub fn is_dangerous_token(token: Token) -> bool {
    // Check if the token is in the safe string tokens
    for safe_token in &SAFE_STRING_TOKENS {
        if &token == safe_token {
            return false; // Not dangerous
        }
    }

    // Check if the token is in the general safe tokens
    for general_safe_token in &GENERAL_SAFE_TOKENS {
        if &token == general_safe_token {
            return false; // Not dangerous
        }
    }

    // If the token is not in either safe list, it is considered dangerous
    true
}
