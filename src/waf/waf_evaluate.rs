use crate::waf::http_scheme::build_http_scheme;
use crate::waf::waf_result::{EvaluateResult, RequestData, RuleInput, SetRulesResult};
use std::net::IpAddr;
use wirefilter::{ExecutionContext, Scheme};

struct ValidatedRule {
    id: String,
    action: String,
    expression: String,
}

pub struct WafEngine {
    scheme: Scheme,
    rules: Vec<ValidatedRule>,
}

impl WafEngine {
    pub fn new() -> Self {
        WafEngine {
            scheme: build_http_scheme(),
            rules: Vec::new(),
        }
    }

    pub fn set_rules(&mut self, rule_inputs: &[RuleInput]) -> SetRulesResult {
        let mut validated = Vec::with_capacity(rule_inputs.len());

        for input in rule_inputs {
            match self.scheme.parse(&input.expression) {
                Ok(_) => {
                    validated.push(ValidatedRule {
                        id: input.id.clone(),
                        action: input.action.clone(),
                        expression: input.expression.clone(),
                    });
                }
                Err(e) => {
                    return SetRulesResult {
                        success: false,
                        error: Some(e.to_string()),
                        rule_id: Some(input.id.clone()),
                    };
                }
            };
        }

        self.rules = validated;

        SetRulesResult {
            success: true,
            error: None,
            rule_id: None,
        }
    }

    pub fn evaluate(&self, request: &RequestData) -> Result<EvaluateResult, String> {
        if self.rules.is_empty() {
            return Ok(EvaluateResult {
                matched: false,
                rule_id: None,
                action: None,
            });
        }

        let ip: IpAddr = request
            .ip_src
            .parse()
            .map_err(|_| format!("Invalid IP address: {}", request.ip_src))?;

        for rule in &self.rules {
            let ast = match self.scheme.parse(&rule.expression) {
                Ok(ast) => ast,
                Err(_) => continue,
            };
            let filter = ast.compile();

            let mut ctx = ExecutionContext::new(&self.scheme);
            populate_context(&mut ctx, request, ip);

            match filter.execute(&ctx) {
                Ok(true) => {
                    return Ok(EvaluateResult {
                        matched: true,
                        rule_id: Some(rule.id.clone()),
                        action: Some(rule.action.clone()),
                    });
                }
                _ => continue,
            }
        }

        Ok(EvaluateResult {
            matched: false,
            rule_id: None,
            action: None,
        })
    }
}

fn populate_context<'a>(
    ctx: &mut ExecutionContext<'a>,
    request: &'a RequestData,
    ip: IpAddr,
) {
    let _ = ctx.set_field_value("http.host", request.host.as_str());
    let _ = ctx.set_field_value("http.request.method", request.method.as_str());
    let _ = ctx.set_field_value("http.request.uri", request.uri.as_str());
    let _ = ctx.set_field_value("http.request.uri.path", request.path.as_str());
    let _ = ctx.set_field_value("http.request.uri.query", request.query.as_str());
    let _ = ctx.set_field_value("http.request.full_uri", request.full_uri.as_str());
    let _ = ctx.set_field_value(
        "http.user_agent",
        request.user_agent.as_deref().unwrap_or(""),
    );
    let _ = ctx.set_field_value("http.cookie", request.cookie.as_deref().unwrap_or(""));
    let _ = ctx.set_field_value(
        "http.referer",
        request.referer.as_deref().unwrap_or(""),
    );
    let _ = ctx.set_field_value(
        "http.x_forwarded_for",
        request.x_forwarded_for.as_deref().unwrap_or(""),
    );
    let _ = ctx.set_field_value(
        "http.request.body.raw",
        request.body.as_deref().unwrap_or(""),
    );
    let _ = ctx.set_field_value("ip.src", ip);
}
