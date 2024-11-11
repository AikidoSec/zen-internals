use crate::diff_in_vec_len;
use oxc::allocator::Vec;
use oxc::ast::ast::Statement;
use oxc::span::GetSpan;

pub fn have_statements_changed(statements1: &Vec<Statement>, statements2: &Vec<Statement>) -> bool {
    // If the number of top level statements is different, it's an injection.
    if diff_in_vec_len!(statements1, statements2) {
        return true;
    }

    // Check for each statement if the length of the statement is the same
    for i in 0..statements1.len() {
        let statement1 = &statements1[i];
        let statement2 = &statements2[i];

        let statement1_len = get_statement_span_length(statement1);
        let statement2_len = get_statement_span_length(statement2);
        if statement1_len != statement2_len {
            println!("{:?} {:?}", statement1, statement2);
            // Todo Iterate over sub statements
            // The only way seems to be to use a match with every possible statement type
        }
    }

    return false;
}

fn get_statement_span_length(statement: &Statement) -> u32 {
    let span = GetSpan::span(statement);
    return span.end - span.start;
}
