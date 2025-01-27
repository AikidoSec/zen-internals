use oxc::allocator::Allocator;
use oxc::ast::ast::BinaryOperator;
use oxc::ast::{AstKind, Visit};
use oxc::parser::{ParseOptions, Parser};
use oxc::span::SourceType;

// Safe operators
const SAFE_OPERATORS: [BinaryOperator; 6] = [
    BinaryOperator::Addition,
    BinaryOperator::Subtraction,
    BinaryOperator::Multiplication,
    BinaryOperator::Division,
    BinaryOperator::Exponential,
    BinaryOperator::Remainder,
];

pub fn is_safe_js_input(user_input: &str, allocator: &Allocator, source_type: SourceType) -> bool {
    let parser_result = Parser::new(allocator, user_input, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            ..ParseOptions::default()
        })
        .parse();

    if parser_result.panicked || !parser_result.errors.is_empty() {
        return false;
    }

    let mut ast_pass = ASTPass {
        contains_only_safe_tokens: true,
    };
    ast_pass.visit_program(&parser_result.program);

    ast_pass.contains_only_safe_tokens
}

struct ASTPass {
    contains_only_safe_tokens: bool,
}

impl<'a> Visit<'a> for ASTPass {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        match kind {
            // Allow without additional checks, all subnodes of the AST will still be checked, so e.g. a sequence of unsafe tokens will be caught
            AstKind::ExpressionStatement(_) // Allow expressions, this contains the more specific expression type, like BinaryExpression
            | AstKind::NumericLiteral(_) // Allow numbers (e.g. 1, 3.14, 5e8)
            | AstKind::ParenthesizedExpression(_) // Allow parentheses
            | AstKind::SequenceExpression(_) => {} // Allow sequences, like 1, 2, 3
            // Check if program comments, directives or hashbang are present
            AstKind::Program(p) => {
                if p.comments.len() > 0 || p.directives.len() > 0 || p.hashbang.is_some() {
                    self.contains_only_safe_tokens = false;
                }
            }
            // Check if operator is allowed
            AstKind::BinaryExpression(b) => {
                // Check if the binary operator is safe
                if !SAFE_OPERATORS.contains(&b.operator) {
                    self.contains_only_safe_tokens = false;
                }
            }
            // Default to unsafe
            _ => {
                self.contains_only_safe_tokens = false;
            }
        }
    }
}
