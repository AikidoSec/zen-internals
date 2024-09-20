#[cfg(test)]
mod tests {
    use crate::helpers::try_parse_url_path::try_parse_url_path;

    #[test]
    fn test_try_parse_url_path_nothing_found() {
        assert_eq!(try_parse_url_path("abc"), None);
    }

    #[test]
    fn test_try_parse_url_path_for_root() {
        assert_eq!(try_parse_url_path("/"), Some("/".to_string()));
    }

    #[test]
    fn test_try_parse_url_path_for_relative_url() {
        assert_eq!(try_parse_url_path("/posts"), Some("/posts".to_string()));
    }

    #[test]
    fn test_try_parse_url_path_for_relative_url_with_query() {
        assert_eq!(
            try_parse_url_path("/posts?abc=def"),
            Some("/posts".to_string())
        );
    }

    #[test]
    fn test_try_parse_url_path_for_absolute_url() {
        assert_eq!(
            try_parse_url_path("http://localhost/posts/3"),
            Some("/posts/3".to_string())
        );
    }

    #[test]
    fn test_try_parse_url_path_for_absolute_url_with_query() {
        assert_eq!(
            try_parse_url_path("http://localhost/posts/3?abc=def"),
            Some("/posts/3".to_string())
        );
    }

    #[test]
    fn test_try_parse_url_path_for_absolute_url_with_hash() {
        assert_eq!(
            try_parse_url_path("http://localhost/posts/3#abc"),
            Some("/posts/3".to_string())
        );
    }

    #[test]
    fn test_try_parse_url_path_for_absolute_url_with_query_and_hash() {
        assert_eq!(
            try_parse_url_path("http://localhost/posts/3?abc=def#ghi"),
            Some("/posts/3".to_string())
        );
    }

    #[test]
    fn test_try_parse_url_path_for_absolute_url_with_query_and_hash_no_path() {
        assert_eq!(
            try_parse_url_path("http://localhost/?abc=def#ghi"),
            Some("/".to_string())
        );
    }

    #[test]
    fn test_try_parse_url_path_for_absolute_url_with_query_no_path() {
        assert_eq!(
            try_parse_url_path("http://localhost?abc=def"),
            Some("/".to_string())
        );
    }

    #[test]
    fn test_try_parse_url_path_for_absolute_url_with_hash_no_path() {
        assert_eq!(
            try_parse_url_path("http://localhost#abc"),
            Some("/".to_string())
        );
    }
}
