use std::{borrow::Cow, io::Read};

use aws_smithy_eventstream::frame::read_message_from;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rama::http::{HeaderMap, header::CONTENT_TYPE};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// OpenAI Chat Completions, OpenAI Responses or Anthropic Messages, recognised by path.
    Common,
    /// Gemini's own API, plus its OpenAI-compatible Chat Completions.
    Gemini,
    /// Bedrock Runtime: Converse and InvokeModel, streaming or not.
    Bedrock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provider {
    /// LiteLLM's provider name where LiteLLM has one, so the backend can price the call.
    pub name: &'static str,
    pub api: Api,
}

const fn common(name: &'static str) -> Provider {
    Provider {
        name,
        api: Api::Common,
    }
}

/// `*` matches exactly one DNS label. The OpenAI-compatible hosts are every provider on
/// <https://models.dev/api.json> with an OpenAI-compatible API on a public https host.
static PROVIDERS: &[(&str, Provider)] = &[
    ("agentrouter.org", common("agentrouter")),
    ("ai-gateway.helicone.ai", common("helicone")),
    ("ai-gateway.vercel.sh", common("vercel_ai_gateway")),
    ("ai.zenifra.com", common("zenifra")),
    ("aki.io", common("aki-io")),
    ("api-gw.klok.ipaas.se", common("klokintegration")),
    ("api-inference.modelscope.cn", common("modelscope")),
    ("api-sherlock.cloudferro.com", common("cloudferro-sherlock")),
    ("api.302.ai", common("302ai")),
    ("api.abliteration.ai", common("abliteration-ai")),
    ("api.above.dev", common("above")),
    ("api.ai-router.dev", common("ai-router")),
    ("api.aiand.com", common("aiand")),
    ("api.aixy-gateway.com", common("aixy")),
    ("api.ambient.xyz", common("ambient")),
    ("api.anyapi.ai", common("anyapi")),
    ("api.auriko.ai", common("auriko")),
    ("api.berget.ai", common("berget")),
    ("api.cerebras.ai", common("cerebras")),
    ("api.clarifai.com", common("clarifai")),
    ("api.claudin.io", common("claudinio")),
    ("api.cline.bot", common("cline-pass")),
    ("api.code.umans.ai", common("umans-ai")),
    ("api.cortecs.ai", common("cortecs")),
    ("api.crossmodel.ai", common("crossmodel")),
    ("api.deepinfra.com", common("deepinfra")),
    ("api.deepseek.com", common("deepseek")),
    ("api.dinference.com", common("dinference")),
    ("api.empiriolabs.ai", common("empiriolabs")),
    ("api.fireworks.ai", common("fireworks_ai")),
    ("api.friendli.ai", common("friendliai")),
    ("api.getlilac.com", common("lilac")),
    ("api.githubcopilot.com", common("github_copilot")),
    ("api.gmi-serving.com", common("gmi")),
    ("api.greenpt.ai", common("greenpt")),
    ("api.groq.com", common("groq")),
    ("api.hpc-ai.com", common("hpc-ai")),
    ("api.impossibl.com", common("impossibl")),
    ("api.inceptionlabs.ai", common("inception")),
    ("api.inceptron.io", common("inceptron")),
    ("api.inference.crusoecloud.com", common("crusoe")),
    ("api.inference.wandb.ai", common("wandb")),
    ("api.intelligence.io.solutions", common("io-net")),
    ("api.iteracompute.com", common("iteracompute")),
    ("api.jiekou.ai", common("jiekou")),
    ("api.kilo.ai", common("kilo")),
    ("api.lab.vispark.in", common("vispark")),
    ("api.lkeap.cloud.tencent.com", common("tencent-token-plan")),
    ("api.llama.com", common("meta_llama")),
    ("api.llmgateway.io", common("llmgateway")),
    ("api.llmtech.eu", common("llmtech")),
    ("api.longcat.chat", common("longcat")),
    ("api.lucidquery.com", common("lucidquery")),
    ("api.meganova.ai", common("meganova")),
    ("api.melious.ai", common("melious")),
    ("api.meta.ai", common("meta")),
    ("api.mistral.ai", common("mistral")),
    ("api.modeloracle.com", common("model-oracle-ai")),
    ("api.moonshot.ai", common("moonshot")),
    ("api.moonshot.cn", common("moonshotai-cn")),
    ("api.morphllm.com", common("morph")),
    ("api.nan.builders", common("nan")),
    ("api.neuralwatt.com", common("neuralwatt")),
    ("api.nova.amazon.com", common("amazon_nova")),
    ("api.novita.ai", common("novita")),
    ("api.ofox.ai", common("ofox")),
    (
        "api.openai-compat.model-serving.eu01.onstackit.cloud",
        common("stackit"),
    ),
    ("api.openai.com", common("openai")),
    ("api.openreason.app", common("openreason")),
    ("api.orcarouter.ai", common("orcarouter")),
    ("api.pendra.ai", common("pendra")),
    ("api.perplexity.ai", common("perplexity")),
    ("api.pioneer.ai", common("pioneer")),
    ("api.poe.com", common("poe")),
    ("api.qhaigc.net", common("qihang-ai")),
    ("api.qnaigc.com", common("qiniu-ai")),
    ("api.regolo.ai", common("regolo-ai")),
    ("api.routing.run", common("routing-run")),
    ("api.sakana.ai", common("sakana")),
    ("api.sarvam.ai", common("sarvam")),
    ("api.scaleway.ai", common("scaleway")),
    ("api.scnet.cn", common("scnet-token-plan")),
    ("api.scx.ai", common("scx-ai")),
    ("api.siliconflow.cn", common("siliconflow-cn")),
    ("api.siliconflow.com", common("siliconflow")),
    ("api.stdcmpt.com", common("standardcompute")),
    ("api.stepfun.ai", common("stepfun-ai")),
    ("api.stepfun.com", common("stepfun")),
    ("api.synthetic.new", common("synthetic")),
    ("api.tbox.cn", common("bailing")),
    ("api.tensorx.ai", common("tensorx")),
    ("api.thegrid.ai", common("the-grid-ai")),
    ("api.together.xyz", common("together_ai")),
    ("api.tokenfactory.nebius.com", common("nebius")),
    ("api.tokengo.com", common("tokengo")),
    ("api.tokenrouter.com", common("tokenrouter")),
    ("api.trustedrouter.com", common("trustedrouter")),
    ("api.unorouter.com", common("unorouter")),
    ("api.upstage.ai", common("upstage")),
    ("api.vivgrid.com", common("vivgrid")),
    ("api.vultrinference.com", common("vultr")),
    ("api.wallabytoken.com", common("wallaby")),
    ("api.xiaomimimo.com", common("xiaomi_mimo")),
    ("api.z.ai", common("zai")),
    ("api.zeldoc.ai", common("zeldoc")),
    ("apihub.agnes-ai.com", common("agnes")),
    ("apis.iflow.cn", common("iflowcn")),
    ("app.frogbot.ai", common("frogbot")),
    ("ark.cn-beijing.volces.com", common("volcengine")),
    ("chat.d.run", common("drun")),
    ("cloud-api.near.ai", common("nearai")),
    (
        "coding-intl.dashscope.aliyuncs.com",
        common("alibaba-coding-plan"),
    ),
    (
        "coding-plan-endpoint.kuaecloud.net",
        common("kuae-cloud-coding-plan"),
    ),
    (
        "coding.dashscope.aliyuncs.com",
        common("alibaba-coding-plan-cn"),
    ),
    ("crof.ai", common("crof")),
    ("daoxe.com", common("daoxe")),
    ("dashscope-intl.aliyuncs.com", common("dashscope")),
    ("dashscope.aliyuncs.com", common("alibaba-cn")),
    ("go.fastrouter.ai", common("fastrouter")),
    ("hyper.charm.land", common("hyper")),
    ("infer.flow7.org", common("infer")),
    ("inference.baseten.co", common("baseten")),
    ("inference.coralbricks.ai", common("coralbricks")),
    ("inference.do-ai.run", common("digitalocean")),
    ("inference.hetzner.com", common("hetzner")),
    ("inference.net", common("inference")),
    ("inference.poolside.ai", common("poolside")),
    ("inference.tinfoil.sh", common("tinfoil")),
    ("inference.us-west.modal.direct", common("modal")),
    ("kenari.id", common("kenari")),
    ("llm.chutes.ai", common("chutes")),
    ("llm.submodel.ai", common("submodel")),
    ("llmtr.com", common("llmtr")),
    ("maas-api.ebcloud.com", common("ebcloud")),
    ("moark.com", common("moark")),
    ("model.inferx.net", common("inferx")),
    ("modelishub.com", common("modelis")),
    ("models.mixlayer.ai", common("mixlayer")),
    ("models.think.evroc.com", common("evroc")),
    ("nano-gpt.com", common("nano-gpt")),
    ("oai.endpoints.kepler.ai.cloud.ovh.net", common("ovhcloud")),
    ("ollama.com", common("ollama-cloud")),
    ("open.bigmodel.cn", common("zhipuai")),
    ("openai.blueclaw.network", common("blueclaw")),
    ("openai.bothub.ru", common("bothub")),
    ("opencode.ai", common("opencode")),
    ("openrouter.ai", common("openrouter")),
    ("pass.wafer.ai", common("wafer.ai")),
    ("routellm.abacus.ai", common("abacus")),
    ("router.huggingface.co", common("huggingface")),
    ("router.neosmith.ai", common("neosmith")),
    ("router.requesty.ai", common("requesty")),
    (
        "token-plan-ams.xiaomimimo.com",
        common("xiaomi-token-plan-ams"),
    ),
    (
        "token-plan-cn.xiaomimimo.com",
        common("xiaomi-token-plan-cn"),
    ),
    (
        "token-plan-sgp.xiaomimimo.com",
        common("xiaomi-token-plan-sgp"),
    ),
    (
        "token-plan.ap-southeast-1.maas.aliyuncs.com",
        common("alibaba-token-plan"),
    ),
    (
        "token-plan.cn-beijing.maas.aliyuncs.com",
        common("alibaba-token-plan-cn"),
    ),
    ("token.sensenova.cn", common("sensenova")),
    ("tokenhub.tencentmaas.com", common("tencent-tokenhub")),
    ("vancine.com", common("vancine")),
    ("www.xpersona.co", common("xpersona")),
    ("zenmux.ai", common("zenmux")),
    ("api.x.ai", common("xai")),
    ("*.openai.azure.com", common("azure")),
    ("*.cognitiveservices.azure.com", common("azure")),
    ("api.anthropic.com", common("anthropic")),
    ("api.kimi.com", common("kimi")),
    ("cc.freemodel.dev", common("freemodel")),
    ("api.subconscious.dev", common("subconscious")),
    ("api.minimax.io", common("minimax")),
    ("api.minimaxi.com", common("minimax")),
    (
        "generativelanguage.googleapis.com",
        Provider {
            name: "gemini",
            api: Api::Gemini,
        },
    ),
    (
        "bedrock-runtime.*.amazonaws.com",
        Provider {
            name: "bedrock",
            api: Api::Bedrock,
        },
    ),
    (
        "bedrock-runtime-fips.*.amazonaws.com",
        Provider {
            name: "bedrock",
            api: Api::Bedrock,
        },
    ),
];

/// The host patterns of [`PROVIDERS`], sent to Zen in the `ready` line.
pub fn hosts() -> impl Iterator<Item = &'static str> {
    PROVIDERS.iter().map(|(pattern, _)| *pattern)
}

impl Provider {
    pub fn from_host(host: &str) -> Option<Self> {
        PROVIDERS
            .iter()
            .find(|(pattern, _)| host_matches(pattern, host))
            .map(|(_, provider)| *provider)
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let mut pattern_labels = pattern.split('.');
    let mut host_labels = host.split('.');
    loop {
        match (pattern_labels.next(), host_labels.next()) {
            (None, None) => return true,
            (Some("*"), Some(label)) if !label.is_empty() => {}
            (Some(expected), Some(label)) if expected.eq_ignore_ascii_case(label) => {}
            _ => return false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireFormat {
    ChatCompletions,
    Responses,
    AnthropicMessages,
    Gemini { path_model: String },
    BedrockConverse { path_model: String, stream: bool },
    BedrockInvoke { path_model: String, stream: bool },
}

/// Recognises an LLM call from the provider and the request path (without query) of a POST.
pub fn detect(provider: Provider, path: &str) -> Option<WireFormat> {
    match provider.api {
        Api::Bedrock => detect_bedrock(path),
        _ if path.ends_with("/chat/completions") => Some(WireFormat::ChatCompletions),
        Api::Common if path.ends_with("/responses") => Some(WireFormat::Responses),
        Api::Common if path.ends_with("/v1/messages") => Some(WireFormat::AnthropicMessages),
        Api::Common => None,
        Api::Gemini => {
            let rest = path
                .strip_prefix("/v1beta/models/")
                .or_else(|| path.strip_prefix("/v1/models/"))?;
            let (model, method) = rest.split_once(':')?;
            (!model.is_empty()
                && !model.contains('/')
                && matches!(method, "generateContent" | "streamGenerateContent"))
            .then(|| WireFormat::Gemini {
                path_model: model.to_owned(),
            })
        }
    }
}

/// `/model/{modelId}/{operation}`, where the model id is percent-encoded.
fn detect_bedrock(path: &str) -> Option<WireFormat> {
    let (model, operation) = path.strip_prefix("/model/")?.split_once('/')?;
    let path_model = bedrock_model(model)?;
    match operation {
        "converse" | "converse-stream" => Some(WireFormat::BedrockConverse {
            path_model,
            stream: operation == "converse-stream",
        }),
        "invoke" | "invoke-with-response-stream" => Some(WireFormat::BedrockInvoke {
            path_model,
            stream: operation == "invoke-with-response-stream",
        }),
        _ => None,
    }
}

/// Model ids and inference profile ids are reported as is, also when wrapped in an ARN.
/// Other ARNs (provisioned throughput, custom models, application inference profiles) only
/// name the account's own resource, so they give an empty model.
fn bedrock_model(encoded: &str) -> Option<String> {
    let model = percent_encoding::percent_decode_str(encoded)
        .decode_utf8()
        .ok()?;
    if model.is_empty() {
        return None;
    }
    if !model.starts_with("arn:") {
        return Some(model.into_owned());
    }
    // arn:partition:bedrock:region:account:resource-type/resource-id
    let resource = model.splitn(6, ':').nth(5)?;
    Some(match resource.split_once('/') {
        Some(("foundation-model" | "inference-profile", id)) => id.to_owned(),
        _ => String::new(),
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AiCall {
    pub provider: &'static str,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub tools_called: Vec<String>,
}

/// Parses a completed call. `response_body` must already be decoded (see [`decode`]).
/// Returns `None` when the response is not in the expected wire format.
pub fn parse(
    provider: Provider,
    format: &WireFormat,
    request_body: Option<&[u8]>,
    response_body: &[u8],
    response_headers: &HeaderMap,
) -> Option<AiCall> {
    let is_sse = response_headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/event-stream"));
    let mut call = match (format, is_sse) {
        (WireFormat::ChatCompletions, false) => {
            chat_completions_object(&serde_json::from_slice(response_body).ok()?)?
        }
        (WireFormat::ChatCompletions, true) => chat_completions_sse(response_body)?,
        (WireFormat::Responses, false) => {
            responses_object(&serde_json::from_slice(response_body).ok()?)?
        }
        (WireFormat::Responses, true) => responses_sse(response_body)?,
        (WireFormat::AnthropicMessages, false) => {
            anthropic_object(&serde_json::from_slice(response_body).ok()?)?
        }
        (WireFormat::AnthropicMessages, true) => anthropic_sse(response_body)?,
        (WireFormat::Gemini { .. }, false) => gemini_json(response_body)?,
        (WireFormat::Gemini { .. }, true) => gemini_chunks(sse_data(response_body))?,
        (WireFormat::BedrockConverse { stream: false, .. }, _) => {
            bedrock_converse_object(&serde_json::from_slice(response_body).ok()?)?
        }
        (WireFormat::BedrockConverse { stream: true, .. }, _) => {
            bedrock_converse_stream(response_body)?
        }
        (WireFormat::BedrockInvoke { stream: false, .. }, _) => {
            bedrock_invoke_json(response_body, response_headers)
        }
        (WireFormat::BedrockInvoke { stream: true, .. }, _) => {
            bedrock_invoke_stream(response_body)?
        }
    };
    call.provider = provider.name;
    // Bedrock's response only names the model without the Bedrock id (`claude-sonnet-4-5`
    // instead of `anthropic.claude-sonnet-4-5-20250929-v1:0`), LiteLLM prices the Bedrock id.
    if let WireFormat::BedrockConverse { path_model, .. }
    | WireFormat::BedrockInvoke { path_model, .. } = format
        && !path_model.is_empty()
    {
        call.model = path_model.clone();
    }
    if call.model.is_empty() {
        call.model = request_body
            .and_then(|body| serde_json::from_slice::<Value>(body).ok())
            .and_then(|request| {
                request
                    .get("model")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .or_else(|| match format {
                WireFormat::Gemini { path_model } => Some(path_model.clone()),
                _ => None,
            })
            .unwrap_or_default();
    }
    Some(call)
}

/// Decodes a `Content-Encoding`d body, refusing to produce more than `limit` bytes.
pub fn decode<'a>(
    content_encoding: Option<&str>,
    body: &'a [u8],
    limit: usize,
) -> Option<Cow<'a, [u8]>> {
    let encoding = content_encoding
        .unwrap_or("identity")
        .trim()
        .to_ascii_lowercase();
    let reader: Box<dyn Read + '_> = match encoding.as_str() {
        "" | "identity" => return (body.len() <= limit).then_some(Cow::Borrowed(body)),
        "gzip" | "x-gzip" => Box::new(flate2::read::GzDecoder::new(body)),
        "deflate" => Box::new(flate2::read::ZlibDecoder::new(body)),
        "br" => Box::new(brotli::Decompressor::new(body, 4096)),
        _ => return None,
    };
    let mut decoded = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut decoded)
        .ok()?;
    (decoded.len() <= limit).then_some(Cow::Owned(decoded))
}

fn sse_data(body: &[u8]) -> impl Iterator<Item = Value> + '_ {
    body.split(|byte| *byte == b'\n').filter_map(|line| {
        let data = line.strip_prefix(b"data:")?.trim_ascii();
        if data == b"[DONE]" {
            return None;
        }
        serde_json::from_slice(data).ok()
    })
}

fn u64_at(value: &Value, pointer: &str) -> u64 {
    value.pointer(pointer).and_then(Value::as_u64).unwrap_or(0)
}

fn str_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn set_model(call: &mut AiCall, value: &Value, pointer: &str) {
    if let Some(model) = str_at(value, pointer).filter(|model| !model.is_empty()) {
        call.model = model.to_owned();
    }
}

fn items<'a>(value: &'a Value, pointer: &str) -> impl Iterator<Item = &'a Value> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn chat_completions_usage(call: &mut AiCall, usage: &Value) {
    call.input_tokens = u64_at(usage, "/prompt_tokens");
    call.output_tokens = u64_at(usage, "/completion_tokens");
    call.cache_read_tokens = u64_at(usage, "/prompt_tokens_details/cached_tokens");
    call.cache_write_tokens = u64_at(usage, "/prompt_tokens_details/cache_write_tokens");
}

fn chat_completions_object(response: &Value) -> Option<AiCall> {
    response.get("choices")?.as_array()?;
    let mut call = AiCall::default();
    set_model(&mut call, response, "/model");
    if let Some(usage) = response.get("usage") {
        chat_completions_usage(&mut call, usage);
    }
    for choice in items(response, "/choices") {
        for tool_call in items(choice, "/message/tool_calls") {
            if let Some(name) =
                str_at(tool_call, "/function/name").or_else(|| str_at(tool_call, "/custom/name"))
            {
                call.tools_called.push(name.to_owned());
            }
        }
        if let Some(name) = str_at(choice, "/message/function_call/name") {
            call.tools_called.push(name.to_owned());
        }
    }
    Some(call)
}

fn chat_completions_sse(body: &[u8]) -> Option<AiCall> {
    let mut call = AiCall::default();
    let mut seen_chunk = false;
    let mut named_tool_calls: Vec<(u64, u64)> = Vec::new();
    for chunk in sse_data(body) {
        seen_chunk = true;
        set_model(&mut call, &chunk, "/model");
        // Groq reports streaming usage under x_groq.usage instead of usage.
        if let Some(usage) = chunk
            .get("usage")
            .or_else(|| chunk.pointer("/x_groq/usage"))
            .filter(|usage| usage.is_object())
        {
            chat_completions_usage(&mut call, usage);
        }
        for choice in items(&chunk, "/choices") {
            let choice_index = u64_at(choice, "/index");
            for tool_call in items(choice, "/delta/tool_calls") {
                let Some(name) = str_at(tool_call, "/function/name") else {
                    continue;
                };
                let key = (choice_index, u64_at(tool_call, "/index"));
                if !named_tool_calls.contains(&key) {
                    named_tool_calls.push(key);
                    call.tools_called.push(name.to_owned());
                }
            }
            // Legacy `functions` streaming: only the first delta of the call carries the name.
            if let Some(name) =
                str_at(choice, "/delta/function_call/name").filter(|name| !name.is_empty())
            {
                call.tools_called.push(name.to_owned());
            }
        }
    }
    seen_chunk.then_some(call)
}

fn responses_object(response: &Value) -> Option<AiCall> {
    response.get("output")?.as_array()?;
    let mut call = AiCall::default();
    set_model(&mut call, response, "/model");
    call.input_tokens = u64_at(response, "/usage/input_tokens");
    call.output_tokens = u64_at(response, "/usage/output_tokens");
    call.cache_read_tokens = u64_at(response, "/usage/input_tokens_details/cached_tokens");
    call.cache_write_tokens = u64_at(response, "/usage/input_tokens_details/cache_write_tokens");
    for item in items(response, "/output") {
        if matches!(
            str_at(item, "/type"),
            Some("function_call" | "custom_tool_call" | "mcp_call")
        ) && let Some(name) = str_at(item, "/name")
        {
            call.tools_called.push(name.to_owned());
        }
    }
    Some(call)
}

fn responses_sse(body: &[u8]) -> Option<AiCall> {
    sse_data(body)
        .filter(|event| {
            matches!(
                str_at(event, "/type"),
                Some("response.completed" | "response.incomplete" | "response.failed")
            )
        })
        .find_map(|event| responses_object(event.get("response")?))
}

fn anthropic_usage(call: &mut AiCall, usage: &Value) {
    let set = |field: &mut u64, key: &str| {
        if let Some(value) = usage.get(key).and_then(Value::as_u64) {
            *field = value;
        }
    };
    set(&mut call.input_tokens, "input_tokens");
    set(&mut call.output_tokens, "output_tokens");
    set(&mut call.cache_read_tokens, "cache_read_input_tokens");
    set(&mut call.cache_write_tokens, "cache_creation_input_tokens");
}

fn anthropic_tool(call: &mut AiCall, block: &Value) {
    if matches!(
        str_at(block, "/type"),
        Some("tool_use" | "server_tool_use" | "mcp_tool_use")
    ) && let Some(name) = str_at(block, "/name")
    {
        call.tools_called.push(name.to_owned());
    }
}

fn anthropic_object(message: &Value) -> Option<AiCall> {
    message.get("content")?.as_array()?;
    let mut call = AiCall::default();
    set_model(&mut call, message, "/model");
    if let Some(usage) = message.get("usage") {
        anthropic_usage(&mut call, usage);
    }
    for block in items(message, "/content") {
        anthropic_tool(&mut call, block);
    }
    Some(call)
}

/// Returns true for `message_start`, the event every Messages stream begins with.
fn anthropic_event(call: &mut AiCall, event: &Value) -> bool {
    match str_at(event, "/type") {
        Some("message_start") => {
            set_model(call, event, "/message/model");
            if let Some(usage) = event.pointer("/message/usage") {
                anthropic_usage(call, usage);
            }
            return true;
        }
        Some("message_delta") => {
            if let Some(usage) = event.get("usage") {
                anthropic_usage(call, usage);
            }
        }
        Some("content_block_start") => {
            if let Some(block) = event.get("content_block") {
                anthropic_tool(call, block);
            }
        }
        _ => {}
    }
    false
}

fn anthropic_sse(body: &[u8]) -> Option<AiCall> {
    let mut call = AiCall::default();
    let mut seen_message_start = false;
    for event in sse_data(body) {
        seen_message_start |= anthropic_event(&mut call, &event);
    }
    seen_message_start.then_some(call)
}

fn bedrock_usage(call: &mut AiCall, usage: &Value) {
    call.input_tokens = u64_at(usage, "/inputTokens");
    call.output_tokens = u64_at(usage, "/outputTokens");
    call.cache_read_tokens = u64_at(usage, "/cacheReadInputTokens");
    call.cache_write_tokens = u64_at(usage, "/cacheWriteInputTokens");
}

fn bedrock_converse_object(response: &Value) -> Option<AiCall> {
    response.pointer("/output/message")?.as_object()?;
    let mut call = AiCall::default();
    if let Some(usage) = response.get("usage") {
        bedrock_usage(&mut call, usage);
    }
    for block in items(response, "/output/message/content") {
        if let Some(name) = str_at(block, "/toolUse/name") {
            call.tools_called.push(name.to_owned());
        }
    }
    Some(call)
}

/// Yields the `(event type, JSON payload)` of each event in an `application/vnd.amazon.eventstream`
/// body, skipping exceptions. Stops at the first frame that does not decode.
fn event_stream(body: &[u8]) -> impl Iterator<Item = (String, Value)> + '_ {
    let mut remaining = body;
    std::iter::from_fn(move || {
        while !remaining.is_empty() {
            let message = read_message_from(&mut remaining).ok()?;
            let header = |name: &str| {
                message
                    .headers()
                    .iter()
                    .find(|header| header.name().as_str() == name)
                    .and_then(|header| header.value().as_string().ok())
                    .map(|value| value.as_str().to_owned())
            };
            if header(":message-type").as_deref() != Some("event") {
                continue;
            }
            let (Some(event_type), Ok(payload)) = (
                header(":event-type"),
                serde_json::from_slice(message.payload()),
            ) else {
                continue;
            };
            return Some((event_type, payload));
        }
        None
    })
}

fn bedrock_converse_stream(body: &[u8]) -> Option<AiCall> {
    let mut call = AiCall::default();
    let mut seen_event = false;
    for (event_type, payload) in event_stream(body) {
        match event_type.as_str() {
            "messageStart" => seen_event = true,
            "contentBlockStart" => {
                if let Some(name) = str_at(&payload, "/start/toolUse/name") {
                    call.tools_called.push(name.to_owned());
                }
            }
            "metadata" => {
                seen_event = true;
                if let Some(usage) = payload.get("usage") {
                    bedrock_usage(&mut call, usage);
                }
            }
            _ => {}
        }
    }
    seen_event.then_some(call)
}

/// InvokeModel bodies are in the model's own format. Bedrock reports the tokens of every model
/// in response headers; tool calls are only read from Anthropic, Converse-shaped (Nova) and
/// Chat Completions (OpenAI) bodies.
fn bedrock_invoke_json(body: &[u8], headers: &HeaderMap) -> AiCall {
    let mut call = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|response| {
            anthropic_object(&response)
                .or_else(|| bedrock_converse_object(&response))
                .or_else(|| chat_completions_object(&response))
        })
        .unwrap_or_default();
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
    };
    let set = |field: &mut u64, name: &str| {
        if let Some(value) = header(name) {
            *field = value;
        }
    };
    set(&mut call.input_tokens, "x-amzn-bedrock-input-token-count");
    set(&mut call.output_tokens, "x-amzn-bedrock-output-token-count");
    set(
        &mut call.cache_read_tokens,
        "x-amzn-bedrock-cache-read-input-token-count",
    );
    set(
        &mut call.cache_write_tokens,
        "x-amzn-bedrock-cache-write-input-token-count",
    );
    call
}

/// Each `chunk` event carries a base64 chunk in the model's own format. Bedrock adds the token
/// counts of every model to the last chunk; tool calls are only read from Anthropic chunks.
fn bedrock_invoke_stream(body: &[u8]) -> Option<AiCall> {
    let mut call = AiCall::default();
    let mut seen_chunk = false;
    let chunks = event_stream(body)
        .filter(|(event_type, _)| event_type == "chunk")
        .filter_map(|(_, payload)| {
            let bytes = BASE64.decode(str_at(&payload, "/bytes")?).ok()?;
            serde_json::from_slice::<Value>(&bytes).ok()
        });
    for chunk in chunks {
        seen_chunk = true;
        anthropic_event(&mut call, &chunk);
        if let Some(metrics) = chunk.get("amazon-bedrock-invocationMetrics") {
            call.input_tokens = u64_at(metrics, "/inputTokenCount");
            call.output_tokens = u64_at(metrics, "/outputTokenCount");
            call.cache_read_tokens = u64_at(metrics, "/cacheReadInputTokenCount");
            call.cache_write_tokens = u64_at(metrics, "/cacheWriteInputTokenCount");
        }
    }
    seen_chunk.then_some(call)
}

fn gemini_json(body: &[u8]) -> Option<AiCall> {
    match serde_json::from_slice(body).ok()? {
        Value::Array(chunks) => gemini_chunks(chunks.into_iter()),
        object @ Value::Object(_) => gemini_chunks(std::iter::once(object)),
        _ => None,
    }
}

fn gemini_chunks(chunks: impl Iterator<Item = Value>) -> Option<AiCall> {
    let mut call = AiCall::default();
    let mut seen_chunk = false;
    for chunk in chunks {
        if chunk.get("candidates").is_none() && chunk.get("usageMetadata").is_none() {
            continue;
        }
        seen_chunk = true;
        set_model(&mut call, &chunk, "/modelVersion");
        if let Some(usage) = chunk.get("usageMetadata") {
            call.input_tokens =
                u64_at(usage, "/promptTokenCount") + u64_at(usage, "/toolUsePromptTokenCount");
            call.output_tokens =
                u64_at(usage, "/candidatesTokenCount") + u64_at(usage, "/thoughtsTokenCount");
            call.cache_read_tokens = u64_at(usage, "/cachedContentTokenCount");
        }
        for candidate in items(&chunk, "/candidates") {
            for part in items(candidate, "/content/parts") {
                if let Some(name) = str_at(part, "/functionCall/name") {
                    call.tools_called.push(name.to_owned());
                }
            }
        }
    }
    seen_chunk.then_some(call)
}
