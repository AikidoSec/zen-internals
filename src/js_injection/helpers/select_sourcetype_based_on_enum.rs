use oxc::span::SourceType;

/*
0 -> CJS
1 -> MJS
2 -> TS
3 -> TSX
Default -> CJS
*/
pub fn select_sourcetype_based_on_enum(enumerator: i32) -> SourceType {
    // 0 is generic type.
    match enumerator {
        0 => SourceType::cjs(),
        1 => SourceType::mjs(),
        2 => SourceType::ts(),
        3 => SourceType::tsx(),
        _ => SourceType::cjs(),
    }
}
