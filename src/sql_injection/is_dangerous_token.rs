use sqlparser::keywords::Keyword;
use sqlparser::tokenizer::*;
pub fn is_dangerous_token(token: &Token) -> bool {
    // Check if token is "word" so we can check against safe keywords list :
    if let Token::Word(word) = token {
        // Return true if the word is not a Keyword, this is marked as dangerous.
        return match word.keyword {
            Keyword::NoKeyword => true,
            _ => false,
        };
    }
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
        Token::Number(_, _) => false,
        Token::Whitespace(_) => false,
        Token::Comma => false,

        // All other tokens are considered dangerous
        _ => true,
    }
}
