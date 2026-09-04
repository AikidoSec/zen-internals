use crate::waf::http_scheme::build_http_scheme;
use crate::waf::waf_result::{EvaluateResult, RequestData, RuleInput, SetRulesResult};
use wirefilter::{ExecutionContext, Filter, Scheme};

struct ValidatedRule {
    id: String,
    action: String,
    filter: Filter,
    expression_size: usize,
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

    pub fn from_rules(rule_inputs: &[RuleInput]) -> Result<Self, SetRulesResult> {
        let mut engine = Self::new();
        let result = engine.set_rules(rule_inputs);
        if result.success {
            Ok(engine)
        } else {
            Err(result)
        }
    }

    pub fn set_rules(&mut self, rule_inputs: &[RuleInput]) -> SetRulesResult {
        let mut validated = Vec::with_capacity(rule_inputs.len());

        for input in rule_inputs {
            match self.scheme.parse(&input.expression) {
                Ok(ast) => {
                    validated.push(ValidatedRule {
                        id: input.id.clone(),
                        action: input.action.clone(),
                        filter: ast.compile(),
                        expression_size: input.expression.len(),
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

    pub fn memory_size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.rules.capacity() * std::mem::size_of::<ValidatedRule>()
            + self
                .rules
                .iter()
                .map(|rule| rule.id.capacity() + rule.action.capacity() + rule.expression_size)
                .sum::<usize>()
    }

    pub fn evaluate(&self, request: &RequestData) -> Result<EvaluateResult, String> {
        if self.rules.is_empty() {
            return Ok(EvaluateResult {
                matched: false,
                rule_id: None,
                action: None,
            });
        }

        let mut ctx = ExecutionContext::new(&self.scheme);
        populate_context(&mut ctx, request)?;

        for rule in &self.rules {
            if rule.filter.execute(&ctx).unwrap_or(false) {
                return Ok(EvaluateResult {
                    matched: true,
                    rule_id: Some(rule.id.clone()),
                    action: Some(rule.action.clone()),
                });
            }
        }

        Ok(EvaluateResult {
            matched: false,
            rule_id: None,
            action: None,
        })
    }
}

impl Default for WafEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn populate_context<'a>(
    ctx: &mut ExecutionContext<'a>,
    request: &'a RequestData,
) -> Result<(), String> {
    set_field(ctx, "http.host", request.host.as_str())?;
    set_field(ctx, "http.request.method", request.method.as_str())?;
    set_field(ctx, "http.request.uri", request.uri.as_str())?;
    set_field(ctx, "http.request.uri.path", request.path.as_str())?;
    set_field(ctx, "http.request.uri.query", request.query.as_str())?;
    set_field(ctx, "http.request.full_uri", request.full_uri.as_str())?;
    set_field(
        ctx,
        "http.user_agent",
        request.user_agent.as_deref().unwrap_or(""),
    )?;
    set_field(ctx, "http.cookie", request.cookie.as_deref().unwrap_or(""))?;
    set_field(
        ctx,
        "http.referer",
        request.referer.as_deref().unwrap_or(""),
    )?;
    set_field(
        ctx,
        "http.x_forwarded_for",
        request.x_forwarded_for.as_deref().unwrap_or(""),
    )?;
    set_field(
        ctx,
        "http.request.body.raw",
        request.body.as_deref().unwrap_or(""),
    )?;

    if let Ok(ip) = request.ip_src.parse::<std::net::IpAddr>() {
        ctx.set_field_value_from_name("ip.src", ip)
            .map_err(|error| error.to_string())?;
    }

    Ok(())
}

fn set_field<'a>(ctx: &mut ExecutionContext<'a>, name: &str, value: &'a str) -> Result<(), String> {
    ctx.set_field_value_from_name(name, value)
        .map(|_| ())
        .map_err(|error| error.to_string())
}
