use super::have_comments_changed::have_comments_changed;
use super::have_statements_changed::have_statements_changed;
use super::helpers::select_sourcetype_based_on_enum::select_sourcetype_based_on_enum;
use super::is_safe_js_input::is_safe_js_input;
use oxc::allocator::Allocator;
use oxc::parser::{ParseOptions, Parser, ParserReturn};
use oxc::span::SourceType;

fn parse_js<'a>(
    allocator: &'a Allocator,
    code: &'a str,
    source_type: SourceType,
) -> ParserReturn<'a> {
    Parser::new(allocator, code, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            ..ParseOptions::default()
        })
        .parse()
}

fn parses_ok(result: &ParserReturn) -> bool {
    !result.panicked && result.errors.is_empty()
}

pub fn detect_js_injection_str(code: &str, userinput: &str, sourcetype: i32) -> bool {
    if userinput.len() <= 1 {
        // We assume that a single character cannot be an injection.
        return false;
    }

    if userinput.len() > code.len() {
        // If the user input is longer than the code, it's not an injection.
        return false;
    }

    if !code.contains(userinput) {
        // If the query does not contain the user input, it's not an injection.
        return false;
    }

    let allocator = Allocator::default();
    let source_type: SourceType = select_sourcetype_based_on_enum(sourcetype);

    if is_safe_js_input(userinput, &allocator, source_type) {
        // Ignore some non dangerous inputs, e.g. math
        return false;
    }

    let mut parser_result = parse_js(&allocator, code, source_type);

    // Some code is only valid JS in an expression position, e.g. a bare
    // `function() {}` passed as a value (as done with MongoDB)
    // That's a syntax error as a standalone statement: "Function statements require a function name",
    // so retry wrapped in parens.
    // The closing paren goes on its own line so it isn't swallowed if the code ends in a `//` line comment.
    let wrapped_code;
    let mut wrap_in_parens = false;

    if !parses_ok(&parser_result) {
        wrapped_code = format!("({code}\n)");
        let wrapped_result = parse_js(&allocator, &wrapped_code, source_type);

        if !parses_ok(&wrapped_result) {
            return false;
        }
        wrap_in_parens = true;
        parser_result = wrapped_result;
    }

    let safe_replace_str = "a".repeat(userinput.len());
    let mut code_without_input: String = code.replace(userinput, &safe_replace_str);
    if wrap_in_parens {
        code_without_input = format!("({code_without_input}\n)");
    }

    let mut parser_result_without_input = parse_js(&allocator, &code_without_input, source_type);

    if !parses_ok(&parser_result_without_input) {
        // Try to parse by replacing the user input with a empty string.
        code_without_input = code.replace(userinput, "");
        if wrap_in_parens {
            code_without_input = format!("({code_without_input}\n)");
        }

        parser_result_without_input = parse_js(&allocator, &code_without_input, source_type);

        if !parses_ok(&parser_result_without_input) {
            return false;
        }
    }

    if have_comments_changed(
        &parser_result.program.comments,
        &parser_result_without_input.program.comments,
    ) {
        // If the number of comments is different, it's an injection.
        return true;
    }

    if have_statements_changed(&parser_result.program, &parser_result_without_input.program) {
        return true;
    }

    false
}
