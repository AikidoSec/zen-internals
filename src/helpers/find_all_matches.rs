pub fn find_all_matches(haystack: &str, needle: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut start = 0;

    while let Some(pos) = haystack[start..].find(needle) {
        let match_pos = start + pos;
        positions.push(match_pos);
        start = match_pos + 1;
    }

    positions
}
