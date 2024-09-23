use sqlparser::tokenizer::*;

pub fn is_dangerous_token(token: &Token) -> bool {
    match token {
        // Safe string tokens :
        // https://github.com/sqlparser-rs/sqlparser-rs/blob/affe8b549884a351ead4f35aa8bdf4cae8c93e4b/src/tokenizer.rs#L65C1-L105C30
        Token::SingleQuotedString(_) => false,
        Token::DoubleQuotedString(_) => false,
        Token::TripleSingleQuotedString(_) => false,
        Token::TripleDoubleQuotedString(_) => false,
        Token::DollarQuotedString(_) => false,
        Token::SingleQuotedByteStringLiteral(_) => false,
        Token::DoubleQuotedByteStringLiteral(_) => false,
        Token::TripleSingleQuotedByteStringLiteral(_) => false,
        Token::TripleDoubleQuotedByteStringLiteral(_) => false,
        Token::SingleQuotedRawStringLiteral(_) => false,
        Token::DoubleQuotedRawStringLiteral(_) => false,
        Token::TripleSingleQuotedRawStringLiteral(_) => false,
        Token::TripleDoubleQuotedRawStringLiteral(_) => false,
        Token::NationalStringLiteral(_) => false,
        Token::EscapedStringLiteral(_) => false,
        Token::UnicodeStringLiteral(_) => false,
        Token::HexStringLiteral(_) => false,

        // General safe tokens
        Token::EOF => false,
        Token::Word(_) => false,
        Token::Whitespace(_) => false,

        // All other tokens are considered dangerous
        _ => true,
    }
}
