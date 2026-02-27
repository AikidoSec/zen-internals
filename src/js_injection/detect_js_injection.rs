use super::have_comments_changed::have_comments_changed;
use super::have_statements_changed::have_statements_changed;
use super::helpers::select_sourcetype_based_on_enum::select_sourcetype_based_on_enum;
use super::is_safe_js_input::is_safe_js_input;
use oxc::allocator::Allocator;
use oxc::parser::{ParseOptions, Parser};
use oxc::span::SourceType;

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

    let parser_result = Parser::new(&allocator, &code, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            ..ParseOptions::default()
        })
        .parse();

    if parser_result.panicked || parser_result.errors.len() > 0 {
        return false;
    }

    let safe_replace_str = "a".repeat(userinput.len());
    let mut code_without_input: String = code.replace(userinput, &safe_replace_str);

    let mut parser_result_without_input = Parser::new(&allocator, &code_without_input, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            ..ParseOptions::default()
        })
        .parse();

    if parser_result_without_input.panicked || parser_result_without_input.errors.len() > 0 {
        // Try to parse by replacing the user input with a empty string.
        code_without_input = code.replace(userinput, "");

        parser_result_without_input = Parser::new(&allocator, &code_without_input, source_type)
            .with_options(ParseOptions {
                allow_return_outside_function: true,
                ..ParseOptions::default()
            })
            .parse();

        if parser_result_without_input.panicked || parser_result_without_input.errors.len() > 0 {
            // Both the replacement and removal of user input cause parse errors.
            // This means the user input provides structural syntax to the surrounding code.
            // If the input contains structural JS tokens, it is almost certainly an injection.
            return contains_js_structural_elements(userinput);
        }
    }

    if have_comments_changed(
        &parser_result.program.comments,
        &parser_result_without_input.program.comments,
    ) {
        // If the number of comments is different, it's an injection.
        return true;
    }

    if have_statements_changed(
        &parser_result.program,
        &parser_result_without_input.program,
        &allocator,
    ) {
        return true;
    }

    return false;
}

// Fallback injection detection when AST comparison is not possible due to parse errors.
// Only use when replacing and removing the user input both produce parse errors!
// In that case the user input must be supplying syntax the surrounding code depends on,
// which is a strong signal of code injection.
// Also in this case it is not possible that the user input is only a string literal.
fn contains_js_structural_elements(input: &str) -> bool {
    // Statement separator, ternary operator, block delimiters, arrow functions
    if input.contains(';')
        || input.contains('?')
        || input.contains('{')
        || input.contains('}')
        || input.contains("=>")
    {
        return true;
    }
    // Control-flow keywords that bridge code blocks.
    // No word-boundary check is needed: any input where the keyword is embedded inside
    // an alphanumeric identifier (e.g. "catchError") consists of pure alphanumeric chars,
    // so the "aaa..." replacement always succeeds and the double-fail path is never reached.
    let lower = input.to_lowercase();
    lower.contains("catch")
        || lower.contains("else")
        || lower.contains("finally")
        || lower.contains("case")
        || lower.contains("do")
}
