use super::have_comments_changed::have_comments_changed;
use super::helpers::select_sourcetype_based_on_enum::select_sourcetype_based_on_enum;
use crate::diff_in_vec_len;
use oxc::allocator::Allocator;
use oxc::parser::{ParseOptions, Parser};
use oxc::span::SourceType;

pub fn detect_js_injection_str(code: &str, userinput: &str, sourcetype: i32) -> bool {
    if !code.contains(userinput) {
        // If the query does not contain the user input, it's not an injection.
        return false;
    }

    if userinput.len() <= 1 {
        // We assume that a single character cannot be an injection.
        return false;
    }

    let allocator = Allocator::default();
    let source_type: SourceType = select_sourcetype_based_on_enum(sourcetype);

    let parser_result = Parser::new(&allocator, &code, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            ..ParseOptions::default()
        })
        .parse();

    if parser_result.panicked || parser_result.errors.len() > 0 {
        return false;
    }

    let code_without_input: &str = &code.replace(userinput, "str");

    let parser_result_without_input = Parser::new(&allocator, &code_without_input, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            ..ParseOptions::default()
        })
        .parse();

    if parser_result_without_input.panicked || parser_result_without_input.errors.len() > 0 {
        return false;
    }

    if diff_in_vec_len!(
        parser_result.program.body,
        parser_result_without_input.program.body
    ) {
        // If the number of statements is different, it's an injection.
        return true;
    }

    if have_comments_changed(
        &parser_result.program.comments,
        &parser_result_without_input.program.comments,
    ) {
        // If the number of comments is different, it's an injection.
        return true;
    }

    // Todo hashbang, directives

    return false;
}
