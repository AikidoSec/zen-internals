use crate::diff_in_vec_len;
use oxc::allocator::{Allocator, Vec};
use oxc::ast::ast::Program;
use oxc::ast::{AstKind, Visit};

pub fn have_statements_changed(
    program1: &Program,
    program2: &Program,
    allocator: &Allocator,
) -> bool {
    let tokens1 = get_ast_kind_tokens(program1, allocator);
    let tokens2 = get_ast_kind_tokens(program2, allocator);

    // If the number of tokens is different, it's an injection.
    if diff_in_vec_len!(tokens1, tokens2) {
        return true;
    }

    false
}

fn get_ast_kind_tokens<'a>(
    program: &'a Program<'a>,
    allocator: &'a Allocator,
) -> Vec<'a, AstKind<'a>> {
    let mut ast_pass = ASTPass {
        tokens: Vec::new_in(allocator),
    };
    ast_pass.visit_program(program);
    ast_pass.tokens
}

struct ASTPass<'a> {
    tokens: Vec<'a, AstKind<'a>>,
}

impl<'a> Visit<'a> for ASTPass<'a> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        self.tokens.push(kind);
    }
}
