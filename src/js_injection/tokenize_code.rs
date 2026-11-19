use std::{cell::RefCell, ops::Range};

use oxc_lexer::{Lexer, TokenKind, PAD};

use super::helpers::select_sourcetype_based_on_enum::select_sourcetype_based_on_enum;

thread_local! {
    static LEXER: RefCell<Lexer> = RefCell::new(Lexer::new());
}

pub struct TokenizedCode {
    tokens: Vec<(TokenKind, Range<u32>)>,
    comments: Vec<(u8, u32)>,
    has_errors: bool,
}

impl TokenizedCode {
    fn from_lexer(lexer: &Lexer) -> Self {
        Self {
            tokens: lexer
                .kinds()
                .iter()
                .zip(&lexer.spans)
                .take(lexer.sig_len)
                .map(|(&kind, span)| (kind, span.start..span.end))
                .collect(),
            comments: lexer
                .lanes
                .comments
                .iter()
                .map(|comment| (comment.kind as u8, comment.span.end - comment.span.start))
                .collect(),
            has_errors: !lexer.lanes.diags.is_empty(),
        }
    }

    pub fn tokens(&self) -> impl Iterator<Item = (TokenKind, Range<usize>)> + '_ {
        self.tokens
            .iter()
            .map(|(kind, span)| (*kind, span.start as usize..span.end as usize))
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    pub fn comments(&self) -> impl Iterator<Item = (u8, u32)> + '_ {
        self.comments.iter().copied()
    }

    pub fn has_errors(&self) -> bool {
        self.has_errors
    }

    fn has_module_syntax(&self) -> bool {
        let mut depth = 0usize;
        let mut tokens = self.tokens().peekable();
        while let Some((kind, _)) = tokens.next() {
            match kind {
                TokenKind::LParen | TokenKind::LBracket | TokenKind::LBrace => depth += 1,
                TokenKind::RParen | TokenKind::RBracket | TokenKind::RBrace => {
                    depth = depth.saturating_sub(1);
                }
                TokenKind::KwExport if depth == 0 => return true,
                TokenKind::KwImport
                    if matches!(tokens.peek(), Some((TokenKind::Dot, _)))
                        || (depth == 0
                            && !matches!(tokens.peek(), Some((TokenKind::LParen, _)))) =>
                {
                    return true;
                }
                _ => {}
            }
        }
        false
    }
}

pub fn tokenize_code(source: &str, sourcetype: i32) -> Option<TokenizedCode> {
    let len = u32::try_from(source.len()).ok()?;
    let capacity = len.checked_add(PAD as u32)?;
    let mut padded = Vec::new();
    padded.try_reserve_exact(capacity as usize).ok()?;
    padded.extend_from_slice(source.as_bytes());
    padded.resize(capacity as usize, 0);

    let tokenize = |lexer: &mut Lexer| {
        let mut options = select_sourcetype_based_on_enum(sourcetype);
        // Oxc's lex_utf8 helper removes false TSX diagnostics by comparing each diagnostic
        // with every skipped type range. Crafted input can make that cleanup quadratic.
        // Detection only compares tokens, and the safe-input check rejects any remaining error.
        lexer.lex(&padded, len as usize, options);
        let mut tokens = TokenizedCode::from_lexer(lexer);
        if !matches!(sourcetype, 1..=4) && tokens.has_module_syntax() {
            options.source_type_module = true;
            lexer.lex(&padded, len as usize, options);
            tokens = TokenizedCode::from_lexer(lexer);
        }
        tokens
    };

    // Do not retain a large input's scratch buffers on every host thread.
    if source.len() > 64 * 1024 {
        return Some(tokenize(&mut Lexer::new()));
    }
    LEXER.with(|lexer| {
        let mut lexer = lexer.try_borrow_mut().ok()?;
        Some(tokenize(&mut lexer))
    })
}
