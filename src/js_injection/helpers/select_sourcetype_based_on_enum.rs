use oxc_lexer::LexOptions;

/*
0 -> JS, auto-detect CJS or ESM
1 -> TypeScript (ESM)
2 -> CJS
3 -> MJS (ESM)
4 -> TSX
Default -> JS, auto-detect CJS or ESM
*/
pub fn select_sourcetype_based_on_enum(enumerator: i32) -> LexOptions {
    LexOptions {
        source_type_module: matches!(enumerator, 1 | 3 | 4),
        ts: matches!(enumerator, 1 | 4),
        jsx: enumerator == 4,
        ..LexOptions::default()
    }
}
