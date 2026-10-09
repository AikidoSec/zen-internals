pub mod wire;
pub mod wire_test;

use rama::{
    Layer, Service,
    bytes::Bytes,
    http::{
        HeaderMap, Method, Request, Response,
        body::{CaptureHandle, CaptureLimit, CaptureOutcome},
        header::{CONTENT_ENCODING, CONTENT_LENGTH},
    },
    net::AuthorityInputExt as _,
};

use crate::output::{self, Line};
use wire::{Provider, WireFormat};

const MAX_INSPECTED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// The request is only read for the model fallback and is held until the response ends, which
/// can take minutes for streams; large prompts just lose the fallback.
const MAX_INSPECTED_REQUEST_BYTES: usize = 64 * 1024;

/// Observes LLM calls passing through the MITM relay and reports them as `ai_call` lines.
/// Traffic is forwarded unchanged; inspection works on copies once both bodies completed.
#[derive(Debug, Clone, Default)]
pub struct InspectLayer;

impl<S> Layer<S> for InspectLayer {
    type Service = Inspect<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Inspect { inner }
    }
}

#[derive(Debug, Clone)]
pub struct Inspect<S> {
    inner: S,
}

impl<S> Service<Request> for Inspect<S>
where
    S: Service<Request, Output = Response>,
{
    type Output = Response;
    type Error = S::Error;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let Some((provider, format)) = recognise(&req) else {
            return self.inner.serve(req).await;
        };

        let (parts, body) = req.into_parts();
        let request_length = content_length(&parts.headers);
        let (body, request_capture) =
            body.capture_buffered(CaptureLimit::max_bytes(MAX_INSPECTED_REQUEST_BYTES));
        let res = self.inner.serve(Request::from_parts(parts, body)).await?;
        if !res.status().is_success() {
            return Ok(res);
        }

        let content_encoding = res
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let response_length = content_length(res.headers());

        let (parts, body) = res.into_parts();
        let response_headers = parts.headers.clone();
        let (body, response_capture) =
            body.capture_buffered(CaptureLimit::max_bytes(MAX_INSPECTED_RESPONSE_BYTES));
        tokio::spawn(async move {
            let Some(response_body) = completed(response_capture, response_length).await else {
                return;
            };
            let Some(response_body) = wire::decode(
                content_encoding.as_deref(),
                &response_body,
                MAX_INSPECTED_RESPONSE_BYTES,
            ) else {
                return;
            };
            let request_body = completed(request_capture, request_length).await;
            if let Some(call) = wire::parse(
                provider,
                &format,
                request_body.as_deref(),
                &response_body,
                &response_headers,
            ) {
                output::send(&Line::AiCall(&call));
            }
        });
        Ok(Response::from_parts(parts, body))
    }
}

fn recognise(req: &Request) -> Option<(Provider, WireFormat)> {
    if req.method() != Method::POST {
        return None;
    }
    let provider = Provider::from_host(&req.authority()?.host.to_string())?;
    let format = wire::detect(provider, &req.uri().path_or_root())?;
    Some((provider, format))
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

/// Returns the captured body only when it was received completely and within the cap.
/// HTTP/1 stops polling a body once its `Content-Length` is reached, so the capture then
/// reports `Aborted` even though nothing is missing.
async fn completed(capture: CaptureHandle, content_length: Option<u64>) -> Option<Bytes> {
    let captured = capture.wait().await.ok()?;
    let complete = match captured.outcome() {
        CaptureOutcome::Complete => true,
        CaptureOutcome::Aborted => content_length == Some(captured.total_bytes()),
        CaptureOutcome::Error => false,
    };
    (complete && !captured.is_truncated()).then(|| captured.into_parts().0)
}
