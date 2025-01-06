#[cfg(test)]
mod tests {
    use crate::helpers::find_all_matches::find_all_matches;

    #[test]
    fn test_find_all_matches() {
        let haystack = "hello world hello world hello world";
        let needle = "world";
        let expected = vec![6, 18, 30];
        let result = find_all_matches(haystack, needle);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_no_matches() {
        let haystack = "hello world hello world hello world";
        let needle = "foo";
        let expected = vec![];
        let result = find_all_matches(haystack, needle);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_empty_haystack() {
        let haystack = "";
        let needle = "world";
        let expected = vec![];
        let result = find_all_matches(haystack, needle);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_empty_needle() {
        let haystack = "hello world hello world hello world";
        let needle = "";
        let expected = vec![];
        let result = find_all_matches(haystack, needle);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_empty_haystack_and_needle() {
        let haystack = "";
        let needle = "";
        let expected = vec![];
        let result = find_all_matches(haystack, needle);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_single_char() {
        let haystack = "hello world hello world hello world";
        let needle = "w";
        let expected = vec![6, 18, 30];
        let result = find_all_matches(haystack, needle);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_overlapping_matches() {
        let haystack = "aaa";
        let needle = "aa";
        let expected = vec![0, 1];
        let result = find_all_matches(haystack, needle);
        assert_eq!(result, expected);
    }
}
