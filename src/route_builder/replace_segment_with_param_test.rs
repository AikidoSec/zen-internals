#[cfg(test)]
mod tests {
    use crate::route_builder::replace_segment_with_param::replace_segment_with_param;
    #[test]
    fn test_emails() {
        assert_eq!(
            replace_segment_with_param("test@aikido.dev"),
            ":email".to_string()
        );
        assert_eq!(
            replace_segment_with_param("john@outlook.be"),
            ":email".to_string()
        );
        assert_eq!(
            replace_segment_with_param("john.doe278@gmail.com"),
            ":email".to_string()
        );
        assert_eq!(
            replace_segment_with_param("john.doe@example.com"),
            ":email".to_string()
        );
        assert_eq!(
            replace_segment_with_param("johndoe678@test.aikido20.dev"),
            ":email".to_string()
        );
    }

    #[test]
    fn test_number() {
        assert_eq!(
            replace_segment_with_param("18273981"),
            ":number".to_string()
        );
        assert_eq!(
            replace_segment_with_param("18682.138182"),
            "18682.138182".to_string()
        );
        assert_eq!(replace_segment_with_param("0"), ":number".to_string());
        assert_eq!(
            replace_segment_with_param("1234567890"),
            ":number".to_string()
        );
    }

    #[test]
    fn test_uuid() {
        assert_eq!(
            replace_segment_with_param("123e4567-e89b-12d3-a456-426614174000"),
            ":uuid".to_string()
        );
        assert_eq!(
            replace_segment_with_param("00000000-0000-0000-0000-000000000000"),
            ":uuid".to_string()
        );
        assert_eq!(
            replace_segment_with_param("ffffffff-ffff-ffff-ffff-ffffffffffff"),
            ":uuid".to_string()
        );
        assert_eq!(
            replace_segment_with_param("not-a-uuid"),
            "not-a-uuid".to_string()
        );
    }

    #[test]
    fn test_date() {
        assert_eq!(
            replace_segment_with_param("2023-10-05"),
            ":date".to_string()
        );
        assert_eq!(
            replace_segment_with_param("05-10-2023"),
            ":date".to_string()
        );
        assert_eq!(
            replace_segment_with_param("2023/10/05"),
            "2023/10/05".to_string()
        );
        assert_eq!(
            replace_segment_with_param("10-05-23"),
            "10-05-23".to_string()
        );
    }

    #[test]
    fn test_ip_address() {
        assert_eq!(replace_segment_with_param("192.168.1.1"), ":ip".to_string());
        assert_eq!(
            replace_segment_with_param("255.255.255.255"),
            ":ip".to_string()
        );
        assert_eq!(replace_segment_with_param("::1"), ":ip".to_string());
        assert_eq!(
            replace_segment_with_param("invalid_ip"),
            "invalid_ip".to_string()
        );
    }

    #[test]
    fn test_hashes() {
        assert_eq!(
            replace_segment_with_param("d41d8cd98f00b204e9800998ecf8427e"),
            ":hash".to_string()
        );
        assert_eq!(
            replace_segment_with_param("a3f5e4d2c1b0a3f5e4d2c1b0a3f5e4d2c1b0a3f5"),
            ":hash".to_string()
        );
        assert_eq!(
            replace_segment_with_param(
                "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
            ),
            "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2".to_string()
        );
        assert_eq!(
            replace_segment_with_param("not_a_hash"),
            "not_a_hash".to_string()
        );
    }

    #[test]
    fn test_secrets() {
        assert_eq!(
            replace_segment_with_param("my_secret_value"),
            "my_secret_value".to_string()
        );
        assert_eq!(
            replace_segment_with_param("afeh238278!khf5_he&"),
            ":secret".to_string()
        );
        assert_eq!(
            replace_segment_with_param("anotherSecret!"),
            "anotherSecret!".to_string()
        );
        assert_eq!(
            replace_segment_with_param("not_a_secret"),
            "not_a_secret".to_string()
        );
    }

    #[test]
    fn test_bson_objectids() {
        assert_eq!(
            replace_segment_with_param("66ec29159d00113616fc7184"),
            ":objectId".to_string()
        )
    }
}
