use oxc_lexer::TokenKind;

use super::tokenize_code::TokenizedCode;

pub fn have_tokens_changed(
    code: &str,
    tokens: &TokenizedCode,
    code_without_input: &str,
    tokens_without_input: &TokenizedCode,
) -> bool {
    if tokens.token_count() != tokens_without_input.token_count()
        || !tokens.comments().eq(tokens_without_input.comments())
    {
        return true;
    }

    let mut previous_end = 0;
    let mut other_previous_end = 0;
    for ((kind, span), (other_kind, other_span)) in
        tokens.tokens().zip(tokens_without_input.tokens())
    {
        if normalize_kind(kind) != normalize_kind(other_kind) {
            return true;
        }
        let Some(before) = code.get(previous_end..span.start) else {
            return false;
        };
        let Some(other_before) = code_without_input.get(other_previous_end..other_span.start)
        else {
            return false;
        };
        // Line terminators inside comments can change automatic semicolon insertion.
        if has_line_break(before) != has_line_break(other_before) {
            return true;
        }
        previous_end = span.end;
        other_previous_end = other_span.end;
    }
    false
}

fn normalize_kind(kind: TokenKind) -> TokenKind {
    match kind {
        TokenKind::IdentEscaped => TokenKind::Ident,
        TokenKind::PrivateIdentEscaped => TokenKind::PrivateIdent,
        TokenKind::StringCooked => TokenKind::String,
        TokenKind::TemplateNoSubCooked => TokenKind::TemplateNoSub,
        TokenKind::TemplateHeadCooked => TokenKind::TemplateHead,
        TokenKind::TemplateMiddleCooked => TokenKind::TemplateMiddle,
        TokenKind::TemplateTailCooked => TokenKind::TemplateTail,
        _ => kind,
    }
}

pub fn has_line_break(text: &str) -> bool {
    text.contains(['\n', '\r', '\u{2028}', '\u{2029}'])
}
