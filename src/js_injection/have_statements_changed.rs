use oxc::ast::ast::Program;
use oxc::ast::AstKind;
use oxc_ast_visit::Visit;

pub fn have_statements_changed(program1: &Program, program2: &Program) -> bool {
    count_ast_nodes(program1) != count_ast_nodes(program2)
}

fn count_ast_nodes(program: &Program) -> usize {
    let mut pass = ASTCounter { count: 0 };
    pass.visit_program(program);
    pass.count
}

struct ASTCounter {
    count: usize,
}

impl<'a> Visit<'a> for ASTCounter {
    fn enter_node(&mut self, _kind: AstKind<'a>) {
        self.count += 1;
    }
}
