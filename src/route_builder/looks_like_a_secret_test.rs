#[cfg(test)]
mod tests {
    use crate::route_builder::looks_like_a_secret::looks_like_a_secret;
    use rand::Rng; // Import the Rng trait for random number generation

    const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const NUMBERS: &str = "0123456789";
    const SPECIALS: &str = "!#$%^&*|;:<>";

    fn secret_from_charset(length: usize, charset: &str) -> String {
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                charset
                    .chars()
                    .nth(rng.gen_range(0..charset.len()))
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(looks_like_a_secret(""), false);
    }

    #[test]
    fn test_short_strings() {
        let short_strings = vec![
            "c",
            "NR",
            "7t3",
            "4qEK",
            "KJr6s",
            "KXiW4a",
            "Fupm2Vi",
            "jiGmyGfg",
            "SJPLzVQ8t",
            "OmNf04j6mU",
        ];
        for s in short_strings {
            assert_eq!(looks_like_a_secret(s), false);
        }
    }

    #[test]
    fn test_long_strings() {
        assert_eq!(looks_like_a_secret("rsVEExrR2sVDONyeWwND"), true);
        assert_eq!(looks_like_a_secret(":2fbg;:qf$BRBc<2AG8&"), true);
    }

    #[test]
    fn test_very_long_strings() {
        assert_eq!(
            looks_like_a_secret("efDJHhzvkytpXoMkFUgag6shWJktYZ5QUrUCTfecFELpdvaoAT3tekI4ZhpzbqLt"),
            true
        );
        assert_eq!(
            looks_like_a_secret("XqSwF6ySwMdTomIdmgFWcMVXWf5L0oVvO5sIjaCPI7EjiPvRZhZGWx3A6mLl1HXPOHdUeabsjhngW06JiLhAchFwgtUaAYXLolZn75WsJVKHxEM1mEXhlmZepLCGwRAM"),
            true
        );
    }

    #[test]
    fn test_contains_white_space() {
        assert_eq!(looks_like_a_secret("rsVEExrR2sVDONyeWwND "), false);
    }

    #[test]
    fn test_less_than_2_charsets() {
        assert_eq!(
            looks_like_a_secret(&secret_from_charset(10, LOWERCASE)),
            false
        );
        assert_eq!(
            looks_like_a_secret(&secret_from_charset(10, UPPERCASE)),
            false
        );
        assert_eq!(
            looks_like_a_secret(&secret_from_charset(10, NUMBERS)),
            false
        );
        assert_eq!(
            looks_like_a_secret(&secret_from_charset(10, SPECIALS)),
            false
        );
    }

    #[test]
    fn test_common_url_terms() {
        let url_terms = vec![
            "development",
            "programming",
            "applications",
            "implementation",
            "environment",
            "technologies",
            "documentation",
            "demonstration",
            "configuration",
            "administrator",
            "visualization",
            "international",
            "collaboration",
            "opportunities",
            "functionality",
            "customization",
            "specifications",
            "optimization",
            "contributions",
            "accessibility",
            "subscription",
            "subscriptions",
            "infrastructure",
            "architecture",
            "authentication",
            "sustainability",
            "notifications",
            "announcements",
            "recommendations",
            "communication",
            "compatibility",
            "enhancement",
            "integration",
            "performance",
            "improvements",
            "introduction",
            "capabilities",
            "communities",
            "credentials",
            "integration",
            "permissions",
            "validation",
            "serialization",
            "deserialization",
            "rate-limiting",
            "throttling",
            "load-balancer",
            "microservices",
            "endpoints",
            "data-transfer",
            "encryption",
            "authorization",
            "bearer-token",
            "multipart",
            "urlencoded",
            "api-docs",
            "postman",
            "json-schema",
            "serialization",
            "deserialization",
            "rate-limiting",
            "throttling",
            "load-balancer",
            "api-gateway",
            "microservices",
            "endpoints",
            "data-transfer",
            "encryption",
            "signature",
            "poppins-bold-webfont.woff2",
            "karla-bold-webfont.woff2",
            "startEmailBasedLogin",
            "jenkinsFile",
            "ConnectionStrings.config",
            "coach",
            "login",
            "payment_methods",
            "activity_logs",
            "feedback_responses",
            "balance_transactions",
            "customer_sessions",
            "payment_intents",
            "billing_portal",
            "subscription_items",
            "namedLayouts",
            "PlatformAction",
            "quickActions",
            "queryLocator",
            "relevantItems",
            "parameterizedSearch",
        ];
        for term in url_terms {
            assert_eq!(looks_like_a_secret(term), false);
        }
    }

    #[test]
    fn test_known_word_separators() {
        assert_eq!(looks_like_a_secret("this-is-a-secret-1"), false);
    }

    #[test]
    fn test_number_is_not_a_secret() {
        assert_eq!(looks_like_a_secret("1234567890"), false);
        assert_eq!(looks_like_a_secret("1234567890".repeat(2).as_str()), false);
    }

    #[test]
    fn test_known_secrets() {
        let secrets = vec![
            "yqHYTS<agpi^aa1",
            "hIofuWBifkJI5iVsSNKKKDpBfmMqJJwuXMxau6AS8WZaHVLDAMeJXo3BwsFyrIIm",
            "AG7DrGi3pDDIUU1PrEsj",
            "CnJ4DunhYfv2db6T1FRfciRBHtlNKOYrjoz",
            "Gic*EfMq:^MQ|ZcmX:yW1",
            "AG7DrGi3pDDIUU1PrEsj",
        ];
        for secret in secrets {
            assert_eq!(looks_like_a_secret(secret), true);
        }
    }
}
