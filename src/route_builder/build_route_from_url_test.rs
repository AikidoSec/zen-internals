#[cfg(test)]
mod tests {
    use crate::route_builder::build_route_from_url::build_route_from_url_str;

    #[test]
    fn test_invalid_urls() {
        assert_eq!(build_route_from_url_str(""), None);
        assert_eq!(build_route_from_url_str("http"), None);
    }

    #[test]
    fn test_root_urls() {
        assert_eq!(build_route_from_url_str("/"), Some("/".to_string()));
        assert_eq!(
            build_route_from_url_str("http://localhost/"),
            Some("/".to_string())
        );
    }

    #[test]
    fn test_replace_numbers() {
        assert_eq!(
            build_route_from_url_str("/posts/3"),
            Some("/posts/:number".to_string())
        );
        assert_eq!(
            build_route_from_url_str("http://localhost/posts/3"),
            Some("/posts/:number".to_string())
        );
        assert_eq!(
            build_route_from_url_str("http://localhost/posts/3/"),
            Some("/posts/:number".to_string())
        );
        assert_eq!(
            build_route_from_url_str("http://localhost/posts/3/comments/10"),
            Some("/posts/:number/comments/:number".to_string())
        );
        assert_eq!(
            build_route_from_url_str("/blog/2023/05/great-article"),
            Some("/blog/:number/:number/great-article".to_string())
        );
    }

    #[test]
    fn test_replace_dates() {
        assert_eq!(
            build_route_from_url_str("/posts/2023-05-01"),
            Some("/posts/:date".to_string())
        );
        assert_eq!(
            build_route_from_url_str("/posts/2023-05-01/"),
            Some("/posts/:date".to_string())
        );
        assert_eq!(
            build_route_from_url_str("/posts/2023-05-01/comments/2023-05-01"),
            Some("/posts/:date/comments/:date".to_string())
        );
        assert_eq!(
            build_route_from_url_str("/posts/01-05-2023"),
            Some("/posts/:date".to_string())
        );
    }

    #[test]
    fn test_ignore_comma_numbers() {
        assert_eq!(
            build_route_from_url_str("/posts/3,000"),
            Some("/posts/3,000".to_string())
        );
    }

    #[test]
    fn test_ignore_api_version_numbers() {
        assert_eq!(
            build_route_from_url_str("/v1/posts/3"),
            Some("/v1/posts/:number".to_string())
        );
    }

    #[test]
    fn test_replace_uuids() {
        let uuids = [
            "d9428888-122b-11e1-b85c-61cd3cbb3210",
            "000003e8-2363-21ef-b200-325096b39f47",
            "a981a0c2-68b1-35dc-bcfc-296e52ab01ec",
            "109156be-c4fb-41ea-b1b4-efe1671c5836",
            "90123e1c-7512-523e-bb28-76fab9f2f73d",
            "1ef21d2f-1207-6660-8c4f-419efbd44d48",
            "017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
            "0d8f23a0-697f-83ae-802e-48f3756dd581",
        ];
        for uuid in &uuids {
            assert_eq!(
                build_route_from_url_str(&format!("/posts/{}", uuid)),
                Some("/posts/:uuid".to_string())
            );
        }
    }

    #[test]
    fn test_ignore_invalid_uuids() {
        assert_eq!(
            build_route_from_url_str("/posts/00000000-0000-1000-6000-000000000000"),
            Some("/posts/00000000-0000-1000-6000-000000000000".to_string())
        );
    }

    #[test]
    fn test_ignore_strings() {
        assert_eq!(
            build_route_from_url_str("/posts/abc"),
            Some("/posts/abc".to_string())
        );
    }

    #[test]
    fn test_replace_email_addresses() {
        assert_eq!(
            build_route_from_url_str("/login/john.doe@acme.com"),
            Some("/login/:email".to_string())
        );
        assert_eq!(
            build_route_from_url_str("/login/john.doe+alias@acme.com"),
            Some("/login/:email".to_string())
        );
    }

    #[test]
    fn test_replace_ip_addresses() {
        assert_eq!(
            build_route_from_url_str("/block/1.2.3.4"),
            Some("/block/:ip".to_string())
        );
        assert_eq!(
            build_route_from_url_str("/block/2001:2:ffff:ffff:ffff:ffff:ffff:ffff"),
            Some("/block/:ip".to_string())
        );
        assert_eq!(
            build_route_from_url_str("/block/64:ff9a::255.255.255.255"),
            Some("/block/:ip".to_string())
        );
        assert_eq!(
            build_route_from_url_str("/block/100::"),
            Some("/block/:ip".to_string())
        );
        assert_eq!(
            build_route_from_url_str("/block/fec0::"),
            Some("/block/:ip".to_string())
        );
        assert_eq!(
            build_route_from_url_str("/block/227.202.96.196"),
            Some("/block/:ip".to_string())
        );
    }
    #[test]
    fn test_replace_secrets() {
        assert_eq!(
            build_route_from_url_str("/confirm/CnJ4DunhYfv2db6T1FRfciRBHtlNKOYrjoz"),
            Some("/confirm/:secret".to_string())
        );
    }
}
