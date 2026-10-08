use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct RuleInput {
    pub id: String,
    pub expression: String,
    #[serde(default = "default_action")]
    pub action: String,
}

fn default_action() -> String {
    "block".to_string()
}

#[derive(Serialize)]
pub struct SetRulesResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

#[derive(Serialize)]
pub struct EvaluateResult {
    pub matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

#[derive(Deserialize)]
pub struct RequestData {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub uri: String,
    #[serde(default)]
    pub full_uri: String,
    pub user_agent: Option<String>,
    pub cookie: Option<String>,
    pub referer: Option<String>,
    pub x_forwarded_for: Option<String>,
    pub body: Option<String>,
    pub ip_src: String,
}
