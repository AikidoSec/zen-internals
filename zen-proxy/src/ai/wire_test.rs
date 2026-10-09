#[cfg(test)]
mod tests {
    use crate::ai::wire::{AiCall, Provider, WireFormat, decode, detect, hosts, parse};
    use aws_smithy_eventstream::frame::write_message_to;
    use aws_smithy_types::event_stream::{Header, HeaderValue as EventHeaderValue, Message};
    use rama::http::{HeaderMap, HeaderValue, header::CONTENT_TYPE};
    use std::io::Write;

    fn provider(host: &str) -> Provider {
        Provider::from_host(host).expect("known host")
    }

    fn openai() -> Provider {
        provider("api.openai.com")
    }

    fn azure() -> Provider {
        provider("my-resource.openai.azure.com")
    }

    fn anthropic() -> Provider {
        provider("api.anthropic.com")
    }

    fn gemini() -> Provider {
        provider("generativelanguage.googleapis.com")
    }

    fn groq() -> Provider {
        provider("api.groq.com")
    }

    fn mistral() -> Provider {
        provider("api.mistral.ai")
    }

    fn bedrock() -> Provider {
        provider("bedrock-runtime.us-east-1.amazonaws.com")
    }

    fn call(model: &str, tokens: [u64; 4], tools: &[&str], provider: Provider) -> AiCall {
        AiCall {
            provider: provider.name,
            model: model.to_owned(),
            input_tokens: tokens[0],
            output_tokens: tokens[1],
            cache_read_tokens: tokens[2],
            cache_write_tokens: tokens[3],
            tools_called: tools.iter().map(|tool| tool.to_string()).collect(),
        }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, HeaderValue::from_static(value));
        }
        headers
    }

    fn parse_str(provider: Provider, path: &str, response: &str, is_sse: bool) -> Option<AiCall> {
        let format = detect(provider, path).expect("known wire format");
        let response_headers = if is_sse {
            headers(&[(CONTENT_TYPE.as_str(), "text/event-stream")])
        } else {
            HeaderMap::new()
        };
        parse(
            provider,
            &format,
            None,
            response.as_bytes(),
            &response_headers,
        )
    }

    #[test]
    fn host_matching() {
        let known = |host| Provider::from_host(host).is_some();
        assert!(known("api.openai.com"));
        assert!(known("API.OpenAI.com"));
        assert!(known("my-resource.openai.azure.com"));
        assert!(known("my-resource.cognitiveservices.azure.com"));
        assert!(known("bedrock-runtime.eu-west-1.amazonaws.com"));
        assert!(known("bedrock-runtime-fips.us-east-1.amazonaws.com"));
        assert!(!known("openai.azure.com"));
        assert!(!known("evilopenai.azure.com"));
        assert!(!known("a.b.openai.azure.com"));
        assert!(!known(".openai.azure.com"));
        assert!(!known("api.openai.com.evil.com"));
        assert!(!known("bedrock-runtime.amazonaws.com"));
        assert!(!known("s3.us-east-1.amazonaws.com"));
        assert!(!known("example.com"));
        assert_eq!(azure().name, "azure");
        assert_eq!(provider("x.cognitiveservices.azure.com").name, "azure");
        assert_eq!(provider("api.together.xyz").name, "together_ai");
        assert_eq!(provider("api.minimax.io").name, "minimax");
        assert_eq!(bedrock().name, "bedrock");
        assert!(hosts().all(|pattern| !pattern.is_empty()));
    }

    #[test]
    fn detects_wire_formats() {
        use WireFormat::*;
        assert_eq!(
            detect(openai(), "/v1/chat/completions"),
            Some(ChatCompletions)
        );
        assert_eq!(
            detect(azure(), "/openai/deployments/gpt4/chat/completions"),
            Some(ChatCompletions)
        );
        assert_eq!(
            detect(groq(), "/openai/v1/chat/completions"),
            Some(ChatCompletions)
        );
        assert_eq!(
            detect(mistral(), "/v1/chat/completions"),
            Some(ChatCompletions)
        );
        assert_eq!(detect(openai(), "/v1/responses"), Some(Responses));
        assert_eq!(detect(azure(), "/openai/v1/responses"), Some(Responses));
        assert_eq!(detect(groq(), "/openai/v1/responses"), Some(Responses));
        assert_eq!(detect(anthropic(), "/v1/messages"), Some(AnthropicMessages));
        assert_eq!(
            detect(
                gemini(),
                "/v1beta/models/gemini-2.5-flash:streamGenerateContent"
            ),
            Some(Gemini {
                path_model: "gemini-2.5-flash".to_owned()
            })
        );
        assert!(detect(gemini(), "/v1/models/gemini-pro:generateContent").is_some());
        assert_eq!(
            detect(gemini(), "/v1beta/openai/chat/completions"),
            Some(ChatCompletions)
        );
        assert_eq!(detect(gemini(), "/v1beta/models/x:countTokens"), None);
        assert_eq!(detect(openai(), "/v1/embeddings"), None);
        assert_eq!(detect(anthropic(), "/v1/messages/count_tokens"), None);
        assert_eq!(
            detect(anthropic(), "/v1/chat/completions"),
            Some(ChatCompletions)
        );
        assert_eq!(
            detect(provider("api.minimax.io"), "/anthropic/v1/messages"),
            Some(AnthropicMessages)
        );
        assert_eq!(
            detect(provider("openrouter.ai"), "/api/v1/chat/completions"),
            Some(ChatCompletions)
        );
        assert_eq!(detect(gemini(), "/v1beta/responses"), None);
    }

    #[test]
    fn chat_completions_json_response() {
        let response = r#"{"id":"x","object":"chat.completion","model":"gpt-4o-mini-2024-07-18",
            "choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[
                {"id":"c1","type":"function","function":{"name":"get_weather","arguments":"{}"}},
                {"id":"c2","type":"function","function":{"name":"get_time","arguments":"{}"}}]}}],
            "usage":{"prompt_tokens":120,"completion_tokens":15,"total_tokens":135,
                "prompt_tokens_details":{"cached_tokens":64}}}"#;
        assert_eq!(
            parse_str(openai(), "/v1/chat/completions", response, false),
            Some(call(
                "gpt-4o-mini-2024-07-18",
                [120, 15, 64, 0],
                &["get_weather", "get_time"],
                openai()
            ))
        );
    }

    #[test]
    fn chat_completions_sse_response() {
        let response = concat!(
            "data: {\"id\":\"x\",\"model\":\"\",\"choices\":[],\"prompt_filter_results\":[]}\n\n",
            "data: {\"id\":\"x\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"\"}}]}}]}\n\n",
            "data: {\"id\":\"x\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n",
            "data: {\"id\":\"x\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"c2\",\"type\":\"function\",\"function\":{\"name\":\"search\",\"arguments\":\"{}\"}}]}}]}\n\n",
            "data: {\"id\":\"x\",\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":20,\"prompt_tokens_details\":{\"cached_tokens\":0}}}\n\n",
            "data: [DONE]\n\n"
        );
        assert_eq!(
            parse_str(
                azure(),
                "/openai/deployments/d/chat/completions",
                response,
                true
            ),
            Some(call(
                "gpt-4o",
                [50, 20, 0, 0],
                &["lookup", "search"],
                azure()
            ))
        );
    }

    #[test]
    fn chat_completions_json_custom_and_legacy_function_calls() {
        let response = r#"{"id":"x","object":"chat.completion","model":"gpt-5",
            "choices":[
                {"index":0,"message":{"role":"assistant","tool_calls":[
                    {"id":"c1","type":"custom","custom":{"name":"run_sql","input":"select 1"}}]}},
                {"index":1,"message":{"role":"assistant","function_call":{"name":"get_weather","arguments":"{}"}}}],
            "usage":{"prompt_tokens":2000,"completion_tokens":10,
                "prompt_tokens_details":{"cached_tokens":1024,"cache_write_tokens":512}}}"#;
        assert_eq!(
            parse_str(openai(), "/v1/chat/completions", response, false),
            Some(call(
                "gpt-5",
                [2000, 10, 1024, 512],
                &["run_sql", "get_weather"],
                openai()
            ))
        );
    }

    #[test]
    fn chat_completions_sse_legacy_function_call() {
        let response = concat!(
            "data: {\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"function_call\":{\"name\":\"get_weather\",\"arguments\":\"\"}}}]}\n\n",
            "data: {\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"function_call\":{\"arguments\":\"{}\"}}}]}\n\n",
            "data: {\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"function_call\"}]}\n\n",
            "data: {\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":30,\"completion_tokens\":7,\"prompt_tokens_details\":{\"cached_tokens\":0,\"cache_write_tokens\":0}}}\n\n",
            "data: [DONE]\n\n"
        );
        assert_eq!(
            parse_str(openai(), "/v1/chat/completions", response, true),
            Some(call("gpt-4o", [30, 7, 0, 0], &["get_weather"], openai()))
        );
    }

    #[test]
    fn chat_completions_sse_groq_usage() {
        let response = concat!(
            "data: {\"model\":\"llama-3.3-70b-versatile\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"model\":\"llama-3.3-70b-versatile\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"x_groq\":{\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":3}}}\n\n",
            "data: [DONE]\n\n"
        );
        assert_eq!(
            parse_str(groq(), "/openai/v1/chat/completions", response, true),
            Some(call("llama-3.3-70b-versatile", [9, 3, 0, 0], &[], groq()))
        );
    }

    #[test]
    fn responses_json_response() {
        let response = r#"{"id":"resp_1","object":"response","model":"gpt-4.1",
            "output":[{"type":"reasoning","summary":[]},
                {"type":"function_call","call_id":"c1","name":"get_weather","arguments":"{}"},
                {"type":"custom_tool_call","call_id":"c2","name":"run_sql","input":"select 1"},
                {"type":"mcp_call","id":"m1","server_label":"docs","name":"search","arguments":"{}"},
                {"type":"web_search_call","id":"w1","status":"completed"},
                {"type":"message","content":[{"type":"output_text","text":"hi"}]}],
            "usage":{"input_tokens":300,"output_tokens":40,"input_tokens_details":{"cached_tokens":256,"cache_write_tokens":32}}}"#;
        assert_eq!(
            parse_str(openai(), "/v1/responses", response, false),
            Some(call(
                "gpt-4.1",
                [300, 40, 256, 32],
                &["get_weather", "run_sql", "search"],
                openai()
            ))
        );
    }

    #[test]
    fn responses_sse_response() {
        let response = concat!(
            "event: response.created\n",
            "data: {\"type\":\"response.created\",\"response\":{\"model\":\"gpt-4.1\",\"output\":[],\"usage\":null}}\n\n",
            "event: response.output_item.added\n",
            "data: {\"type\":\"response.output_item.added\",\"item\":{\"type\":\"function_call\",\"name\":\"get_weather\"}}\n\n",
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-4.1\",\"output\":[{\"type\":\"function_call\",\"name\":\"get_weather\",\"arguments\":\"{}\"}],\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"input_tokens_details\":{\"cached_tokens\":0}}}}\n\n"
        );
        assert_eq!(
            parse_str(openai(), "/v1/responses", response, true),
            Some(call("gpt-4.1", [10, 5, 0, 0], &["get_weather"], openai()))
        );
        let max_tokens_hit = concat!(
            "data: {\"type\":\"response.created\",\"response\":{\"model\":\"o4-mini\",\"output\":[]}}\n\n",
            "data: {\"type\":\"response.incomplete\",\"response\":{\"model\":\"o4-mini\",\"status\":\"incomplete\",\"output\":[{\"type\":\"reasoning\",\"summary\":[]}],\"usage\":{\"input_tokens\":7,\"output_tokens\":100}}}\n\n"
        );
        assert_eq!(
            parse_str(openai(), "/v1/responses", max_tokens_hit, true),
            Some(call("o4-mini", [7, 100, 0, 0], &[], openai()))
        );
        let truncated = "data: {\"type\":\"response.created\",\"response\":{\"model\":\"gpt-4.1\",\"output\":[]}}\n\n";
        assert_eq!(parse_str(openai(), "/v1/responses", truncated, true), None);
    }

    #[test]
    fn anthropic_json_response() {
        let response = r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929",
            "content":[{"type":"text","text":"Let me check."},
                {"type":"tool_use","id":"toolu_1","name":"get_weather","input":{"city":"Ghent"}},
                {"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{"query":"x"}},
                {"type":"web_search_tool_result","tool_use_id":"srvtoolu_1","content":[]},
                {"type":"mcp_tool_use","id":"mcptoolu_1","name":"lookup","server_name":"docs","input":{}}],
            "stop_reason":"tool_use",
            "usage":{"input_tokens":12,"output_tokens":34,"cache_read_input_tokens":1000,"cache_creation_input_tokens":200}}"#;
        assert_eq!(
            parse_str(anthropic(), "/v1/messages", response, false),
            Some(call(
                "claude-sonnet-4-5-20250929",
                [12, 34, 1000, 200],
                &["get_weather", "web_search", "lookup"],
                anthropic()
            ))
        );
    }

    #[test]
    fn anthropic_sse_response() {
        let response = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-haiku-4-5\",\"content\":[],\"usage\":{\"input_tokens\":25,\"output_tokens\":1,\"cache_read_input_tokens\":500,\"cache_creation_input_tokens\":0}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"search_docs\",\"input\":{}}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":15}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"input_tokens\":26,\"output_tokens\":42,\"cache_creation_input_tokens\":7}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n"
        );
        assert_eq!(
            parse_str(anthropic(), "/v1/messages", response, true),
            Some(call(
                "claude-haiku-4-5",
                [26, 42, 500, 7],
                &["search_docs"],
                anthropic()
            ))
        );
    }

    #[test]
    fn gemini_json_response() {
        let response = r#"{"candidates":[{"content":{"role":"model","parts":[
                {"functionCall":{"name":"get_weather","args":{"city":"Ghent"}}}]},"finishReason":"STOP"}],
            "usageMetadata":{"promptTokenCount":70,"candidatesTokenCount":8,"cachedContentTokenCount":32,"totalTokenCount":78},
            "modelVersion":"gemini-2.5-flash-001"}"#;
        assert_eq!(
            parse_str(
                gemini(),
                "/v1beta/models/gemini-2.5-flash:generateContent",
                response,
                false
            ),
            Some(call(
                "gemini-2.5-flash-001",
                [70, 8, 32, 0],
                &["get_weather"],
                gemini()
            ))
        );
    }

    #[test]
    fn gemini_counts_thoughts_and_tool_use_prompt_tokens() {
        let response = r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]}}],
            "usageMetadata":{"promptTokenCount":70,"toolUsePromptTokenCount":30,"candidatesTokenCount":8,
                "thoughtsTokenCount":500,"totalTokenCount":608},
            "modelVersion":"gemini-2.5-pro"}"#;
        assert_eq!(
            parse_str(
                gemini(),
                "/v1beta/models/gemini-2.5-pro:generateContent",
                response,
                false
            ),
            Some(call("gemini-2.5-pro", [100, 508, 0, 0], &[], gemini()))
        );
    }

    #[test]
    fn gemini_sse_response() {
        let response = concat!(
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"a\",\"args\":{}}}]}}],\"usageMetadata\":{\"promptTokenCount\":5}}\r\n\r\n",
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"b\",\"args\":{}}}]}}],\"usageMetadata\":{\"promptTokenCount\":5,\"candidatesTokenCount\":9}}\r\n\r\n"
        );
        assert_eq!(
            parse_str(
                gemini(),
                "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
                response,
                true
            ),
            Some(call(
                "gemini-2.0-flash",
                [5, 9, 0, 0],
                &["a", "b"],
                gemini()
            ))
        );
    }

    #[test]
    fn gemini_json_array_response() {
        let response = r#"[{"candidates":[{"content":{"parts":[{"text":"Hel"}]}}],"modelVersion":"gemini-2.0-flash"},
            {"candidates":[{"content":{"parts":[{"text":"lo"}]}}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":2},"modelVersion":"gemini-2.0-flash"}]"#;
        assert_eq!(
            parse_str(
                gemini(),
                "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
                response,
                false
            ),
            Some(call("gemini-2.0-flash", [3, 2, 0, 0], &[], gemini()))
        );
    }

    fn event_stream(events: &[(&'static str, &'static str, String)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (message_type, event_type, payload) in events {
            let message = Message::new(payload.clone().into_bytes())
                .add_header(Header::new(
                    ":message-type",
                    EventHeaderValue::String((*message_type).into()),
                ))
                .add_header(Header::new(
                    ":event-type",
                    EventHeaderValue::String((*event_type).into()),
                ));
            write_message_to(&message, &mut body).unwrap();
        }
        body
    }

    fn parse_bedrock(path: &str, response: &[u8], response_headers: &HeaderMap) -> Option<AiCall> {
        let format = detect(bedrock(), path).expect("known wire format");
        parse(bedrock(), &format, None, response, response_headers)
    }

    #[test]
    fn detects_bedrock_wire_formats() {
        use WireFormat::*;
        let converse = |path_model: &str, stream| BedrockConverse {
            path_model: path_model.to_owned(),
            stream,
        };
        let invoke = |path_model: &str, stream| BedrockInvoke {
            path_model: path_model.to_owned(),
            stream,
        };
        let model = "anthropic.claude-sonnet-4-5-20250929-v1:0";
        assert_eq!(
            detect(
                bedrock(),
                "/model/anthropic.claude-sonnet-4-5-20250929-v1%3A0/converse"
            ),
            Some(converse(model, false))
        );
        assert_eq!(
            detect(bedrock(), &format!("/model/{model}/converse-stream")),
            Some(converse(model, true))
        );
        assert_eq!(
            detect(bedrock(), &format!("/model/{model}/invoke")),
            Some(invoke(model, false))
        );
        assert_eq!(
            detect(
                bedrock(),
                &format!("/model/{model}/invoke-with-response-stream")
            ),
            Some(invoke(model, true))
        );
        assert_eq!(
            detect(
                bedrock(),
                "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.anthropic.claude-sonnet-4-5-20250929-v1%3A0/converse"
            ),
            Some(converse(
                "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
                false
            ))
        );
        assert_eq!(
            detect(
                bedrock(),
                "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Aapplication-inference-profile%2Fabc123/converse"
            ),
            Some(converse("", false))
        );
        assert_eq!(
            detect(bedrock(), &format!("/model/{model}/count-tokens")),
            None
        );
        assert_eq!(detect(bedrock(), "/model//converse"), None);
        assert_eq!(detect(bedrock(), "/v1/chat/completions"), None);
    }

    #[test]
    fn bedrock_converse_json_response() {
        let response = br#"{
            "output":{"message":{"role":"assistant","content":[
                {"text":"Checking"},
                {"toolUse":{"toolUseId":"t1","name":"get_weather","input":{"city":"Ghent"}}}
            ]}},
            "stopReason":"tool_use",
            "usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15,"cacheReadInputTokens":3,"cacheWriteInputTokens":2}
        }"#;
        assert_eq!(
            parse_bedrock(
                "/model/amazon.nova-pro-v1%3A0/converse",
                response,
                &HeaderMap::new()
            ),
            Some(call(
                "amazon.nova-pro-v1:0",
                [10, 5, 3, 2],
                &["get_weather"],
                bedrock()
            ))
        );
        assert_eq!(
            parse_bedrock(
                "/model/amazon.nova-pro-v1%3A0/converse",
                br#"{"message":"x"}"#,
                &HeaderMap::new()
            ),
            None
        );
    }

    #[test]
    fn bedrock_converse_stream_response() {
        let body = event_stream(&[
            ("event", "messageStart", r#"{"role":"assistant","p":"abc"}"#.to_owned()),
            (
                "event",
                "contentBlockStart",
                r#"{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"t1","name":"search"}}}"#.to_owned(),
            ),
            ("event", "contentBlockDelta", r#"{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{}"}}}"#.to_owned()),
            ("event", "messageStop", r#"{"stopReason":"tool_use"}"#.to_owned()),
            (
                "event",
                "metadata",
                r#"{"usage":{"inputTokens":20,"outputTokens":7,"cacheReadInputTokens":4,"cacheWriteInputTokens":0},"metrics":{"latencyMs":1}}"#.to_owned(),
            ),
            ("exception", "throttlingException", r#"{"message":"slow down"}"#.to_owned()),
        ]);
        assert_eq!(
            parse_bedrock(
                "/model/amazon.nova-pro-v1%3A0/converse-stream",
                &body,
                &HeaderMap::new()
            ),
            Some(call(
                "amazon.nova-pro-v1:0",
                [20, 7, 4, 0],
                &["search"],
                bedrock()
            ))
        );
        assert_eq!(
            parse_bedrock(
                "/model/amazon.nova-pro-v1%3A0/converse-stream",
                b"not an event stream",
                &HeaderMap::new()
            ),
            None
        );
    }

    #[test]
    fn bedrock_invoke_json_response() {
        let response = br#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929",
            "content":[{"type":"tool_use","id":"t1","name":"get_weather","input":{}}],
            "usage":{"input_tokens":1,"output_tokens":1}}"#;
        let token_headers = headers(&[
            ("x-amzn-bedrock-input-token-count", "12"),
            ("x-amzn-bedrock-output-token-count", "34"),
            ("x-amzn-bedrock-cache-read-input-token-count", "56"),
            ("x-amzn-bedrock-cache-write-input-token-count", "78"),
        ]);
        assert_eq!(
            parse_bedrock(
                "/model/anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke",
                response,
                &token_headers
            ),
            Some(call(
                "anthropic.claude-sonnet-4-5-20250929-v1:0",
                [12, 34, 56, 78],
                &["get_weather"],
                bedrock()
            ))
        );
        // The ARN names no model, the Anthropic body does
        assert_eq!(
            parse_bedrock(
                "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Aprovisioned-model%2Fabc/invoke",
                response,
                &HeaderMap::new()
            ),
            Some(call(
                "claude-sonnet-4-5-20250929",
                [1, 1, 0, 0],
                &["get_weather"],
                bedrock()
            ))
        );
        // Llama's body has no usage or tools Zen reads, the headers still count the call
        assert_eq!(
            parse_bedrock(
                "/model/meta.llama3-1-70b-instruct-v1%3A0/invoke",
                br#"{"generation":"Hi","prompt_token_count":12,"generation_token_count":34}"#,
                &token_headers
            ),
            Some(call(
                "meta.llama3-1-70b-instruct-v1:0",
                [12, 34, 56, 78],
                &[],
                bedrock()
            ))
        );
    }

    #[test]
    fn bedrock_invoke_stream_response() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let chunk = |json: &str| format!(r#"{{"bytes":"{}","p":"abc"}}"#, STANDARD.encode(json));
        let body = event_stream(&[
            (
                "event",
                "chunk",
                chunk(
                    r#"{"type":"message_start","message":{"model":"claude-sonnet-4-5-20250929","usage":{"input_tokens":20,"output_tokens":1}}}"#,
                ),
            ),
            (
                "event",
                "chunk",
                chunk(
                    r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"search","input":{}}}"#,
                ),
            ),
            (
                "event",
                "chunk",
                chunk(
                    r#"{"type":"message_stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":20,"outputTokenCount":7,"invocationLatency":1,"firstByteLatency":1,"cacheReadInputTokenCount":5,"cacheWriteInputTokenCount":6}}"#,
                ),
            ),
        ]);
        assert_eq!(
            parse_bedrock(
                "/model/anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke-with-response-stream",
                &body,
                &HeaderMap::new()
            ),
            Some(call(
                "anthropic.claude-sonnet-4-5-20250929-v1:0",
                [20, 7, 5, 6],
                &["search"],
                bedrock()
            ))
        );
    }

    #[test]
    fn falls_back_to_request_model() {
        let format = detect(mistral(), "/v1/chat/completions").unwrap();
        let response = br#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2}}"#;
        let request = br#"{"model":"mistral-small-latest","messages":[]}"#;
        assert_eq!(
            parse(
                mistral(),
                &format,
                Some(request),
                response,
                &HeaderMap::new()
            ),
            Some(call("mistral-small-latest", [1, 2, 0, 0], &[], mistral()))
        );
    }

    #[test]
    fn rejects_unrecognised_bodies() {
        assert_eq!(
            parse_str(openai(), "/v1/chat/completions", "not json", false),
            None
        );
        assert_eq!(
            parse_str(
                openai(),
                "/v1/chat/completions",
                r#"{"error":{"message":"x"}}"#,
                false
            ),
            None
        );
        assert_eq!(
            parse_str(anthropic(), "/v1/messages", "data: [DONE]\n\n", true),
            None
        );
    }

    #[test]
    fn decodes_gzip_response() {
        let response = br#"{"type":"message","model":"claude-opus-4-1","content":[],"usage":{"input_tokens":3,"output_tokens":4}}"#;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(response).unwrap();
        let compressed = encoder.finish().unwrap();

        let decoded = decode(Some("gzip"), &compressed, 1024).unwrap();
        let format = detect(anthropic(), "/v1/messages").unwrap();
        assert_eq!(
            parse(anthropic(), &format, None, &decoded, &HeaderMap::new()),
            Some(call("claude-opus-4-1", [3, 4, 0, 0], &[], anthropic()))
        );
        assert_eq!(decode(Some("gzip"), &compressed, 10), None);
        assert_eq!(decode(Some("zstd"), &compressed, 1024), None);
        assert_eq!(decode(None, b"abc", 1024).as_deref(), Some(&b"abc"[..]));
    }

    #[test]
    fn decodes_brotli_response() {
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
            writer.write_all(b"hello brotli").unwrap();
        }
        assert_eq!(
            decode(Some("br"), &compressed, 1024).as_deref(),
            Some(&b"hello brotli"[..])
        );
    }
}
