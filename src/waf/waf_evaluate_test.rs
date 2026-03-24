use crate::waf::waf_evaluate::WafEngine;
use crate::waf::waf_result::{RequestData, RuleInput};

fn make_request(path: &str) -> RequestData {
    RequestData {
        host: "example.com".to_string(),
        method: "GET".to_string(),
        path: path.to_string(),
        query: "".to_string(),
        uri: path.to_string(),
        full_uri: format!("https://example.com{}", path),
        user_agent: None,
        cookie: None,
        referer: None,
        x_forwarded_for: None,
        body: None,
        ip_src: "1.2.3.4".to_string(),
    }
}

#[test]
fn test_path_traversal_match() {
    let mut engine = WafEngine::new();
    let result = engine.set_rules(&[RuleInput {
        id: "rule1".to_string(),
        expression: r#"http.request.uri.path contains "/etc/passwd""#.to_string(),
        action: "block".to_string(),
    }]);
    assert!(result.success);

    let result = engine
        .evaluate(&make_request("/files/../etc/passwd"))
        .unwrap();
    assert!(result.matched);
    assert_eq!(result.rule_id.unwrap(), "rule1");
}

#[test]
fn test_no_match() {
    let mut engine = WafEngine::new();
    engine.set_rules(&[RuleInput {
        id: "rule1".to_string(),
        expression: r#"http.request.uri.path contains "/etc/passwd""#.to_string(),
        action: "block".to_string(),
    }]);

    let result = engine.evaluate(&make_request("/index.html")).unwrap();
    assert!(!result.matched);
}

#[test]
fn test_regex_matching() {
    let mut engine = WafEngine::new();
    let result = engine.set_rules(&[RuleInput {
        id: "sqli".to_string(),
        expression: r#"http.request.uri.query matches "union\s+select""#.to_string(),
        action: "block".to_string(),
    }]);
    assert!(result.success);

    let mut request = make_request("/search");
    request.query = "?q=1 union  select * from users".to_string();
    request.uri = "/search?q=1 union  select * from users".to_string();

    let result = engine.evaluate(&request).unwrap();
    assert!(result.matched);
    assert_eq!(result.rule_id.unwrap(), "sqli");
}

#[test]
fn test_ip_cidr_matching() {
    let mut engine = WafEngine::new();
    let result = engine.set_rules(&[RuleInput {
        id: "ip_block".to_string(),
        expression: r#"ip.src in {192.168.0.0/16}"#.to_string(),
        action: "block".to_string(),
    }]);
    assert!(result.success);

    let mut request = make_request("/");
    request.ip_src = "192.168.1.42".to_string();

    let result = engine.evaluate(&request).unwrap();
    assert!(result.matched);
    assert_eq!(result.rule_id.unwrap(), "ip_block");
}

#[test]
fn test_compound_expression() {
    let mut engine = WafEngine::new();
    engine.set_rules(&[RuleInput {
        id: "compound".to_string(),
        expression: r#"http.request.method == "POST" and http.request.uri.path contains "/admin""#
            .to_string(),
        action: "block".to_string(),
    }]);

    // POST to /admin - should match
    let mut request = make_request("/admin/users");
    request.method = "POST".to_string();
    assert!(engine.evaluate(&request).unwrap().matched);

    // GET to /admin - should NOT match
    let request = make_request("/admin/users");
    assert!(!engine.evaluate(&request).unwrap().matched);
}

#[test]
fn test_invalid_expression_returns_error() {
    let mut engine = WafEngine::new();
    let result = engine.set_rules(&[RuleInput {
        id: "bad".to_string(),
        expression: "this is not valid syntax !!!".to_string(),
        action: "block".to_string(),
    }]);
    assert!(!result.success);
    assert_eq!(result.rule_id.unwrap(), "bad");
    assert!(result.error.is_some());
}

#[test]
fn test_user_agent_regex() {
    let mut engine = WafEngine::new();
    engine.set_rules(&[RuleInput {
        id: "scanner".to_string(),
        expression: r#"http.user_agent matches "(?i)(sqlmap|nikto|nmap)""#.to_string(),
        action: "block".to_string(),
    }]);

    let mut request = make_request("/");
    request.user_agent = Some("sqlmap/1.0".to_string());

    assert!(engine.evaluate(&request).unwrap().matched);
}

#[test]
fn test_multiple_rules_first_match_wins() {
    let mut engine = WafEngine::new();
    engine.set_rules(&[
        RuleInput {
            id: "rule1".to_string(),
            expression: r#"http.request.method == "DELETE""#.to_string(),
            action: "block".to_string(),
        },
        RuleInput {
            id: "rule2".to_string(),
            expression: r#"http.request.uri.path contains "/admin""#.to_string(),
            action: "log".to_string(),
        },
    ]);

    let request = make_request("/admin");
    let result = engine.evaluate(&request).unwrap();
    assert!(result.matched);
    assert_eq!(result.rule_id.unwrap(), "rule2");
    assert_eq!(result.action.unwrap(), "log");
}

#[test]
fn test_optional_field_missing_no_match() {
    let mut engine = WafEngine::new();
    engine.set_rules(&[RuleInput {
        id: "ua".to_string(),
        expression: r#"http.user_agent contains "bot""#.to_string(),
        action: "block".to_string(),
    }]);

    // user_agent is None - should not match (empty string doesn't contain "bot")
    let request = make_request("/");
    assert!(!engine.evaluate(&request).unwrap().matched);
}

#[test]
fn test_set_rules_clears_previous() {
    let mut engine = WafEngine::new();
    engine.set_rules(&[RuleInput {
        id: "old".to_string(),
        expression: r#"http.request.uri.path contains "/old""#.to_string(),
        action: "block".to_string(),
    }]);

    engine.set_rules(&[RuleInput {
        id: "new".to_string(),
        expression: r#"http.request.uri.path contains "/new""#.to_string(),
        action: "block".to_string(),
    }]);

    assert!(!engine.evaluate(&make_request("/old")).unwrap().matched);
    assert!(engine.evaluate(&make_request("/new")).unwrap().matched);
}

#[test]
fn test_invalid_ip_returns_error() {
    let mut engine = WafEngine::new();
    engine.set_rules(&[RuleInput {
        id: "rule1".to_string(),
        expression: r#"http.request.uri.path contains "/test""#.to_string(),
        action: "block".to_string(),
    }]);

    let mut request = make_request("/test");
    request.ip_src = "not-an-ip".to_string();

    let result = engine.evaluate(&request);
    assert!(result.is_err());
}
