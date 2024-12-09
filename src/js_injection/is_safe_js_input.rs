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
    let parser_result = Parser::new(&allocator, &user_input, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            ..ParseOptions::default()
        })
        .parse();

    if parser_result.panicked || parser_result.errors.len() > 0 {
        return false;
    }

    let mut ast_pass = ASTPass {
        contains_only_safe_tokens: true,
    };
    ast_pass.visit_program(&parser_result.program);

    return ast_pass.contains_only_safe_tokens;
}

struct ASTPass {
    contains_only_safe_tokens: bool,
}

impl<'a> Visit<'a> for ASTPass {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        match kind {
            // Allow without additional checks
            AstKind::ExpressionStatement(_)
            | AstKind::NumericLiteral(_)
            | AstKind::ParenthesizedExpression(_)
            | AstKind::SequenceExpression(_) => {}
            AstKind::Program(p) => {
                if p.comments.len() > 0 || p.directives.len() > 0 || p.hashbang.is_some() {
                    self.contains_only_safe_tokens = false;
                }
            }
            AstKind::BinaryExpression(b) => {
                // Check if the binary operator is safe
                if !SAFE_OPERATORS.contains(&b.operator) {
                    self.contains_only_safe_tokens = false;
                }
            }
            _ => {
                println!("Kind: {:?}", kind);
                self.contains_only_safe_tokens = false;
            }
        }
    }
}
