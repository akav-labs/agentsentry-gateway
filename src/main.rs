//! AgentSentry Gateway — a transparent, OpenAI-compatible security gateway.
//!
//! Point your agent at it with a single env var:
//!     OPENAI_BASE_URL=http://localhost:9003/v1
//!
//! Every request is scanned before it leaves your network: leaked secrets/PII
//! (DLP), jailbreaks, prompt injection, and MITRE ATLAS techniques. Violations
//! are blocked with a 403; clean traffic is forwarded to the real upstream
//! unchanged. No database, no account, no telemetry — it runs entirely local.

mod atlas_engine;
mod dlp_engine;
mod fingerprint;

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get},
    Json, Router,
};
use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, Encoder, IntCounterVec, TextEncoder};
use serde_json::{json, Value};
use std::sync::Arc;

const BANNER: &str = r#"
   ___                    _   ____             _
  / _ \                  | | / ___|           | |
 / /_\ \ __ _  ___ _ __  | |_\ `--.  ___ _ __ | |_ _ __ _   _
 |  _  |/ _` |/ _ \ '_ \ | __|`--. \/ _ \ '_ \| __| '__| | | |
 | | | | (_| |  __/ | | || |_/\__/ /  __/ | | | |_| |  | |_| |
 \_| |_/\__, |\___|_| |_| \__\____/ \___|_| |_|\__|_|   \__, |
         __/ |                                           __/ |
        |___/     G A T E W A Y   ·   by Akav Labs      |___/

  Transparent LLM security gateway  ·  https://akav.io  ·  Apache-2.0
"#;

static REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!("agentsentry_requests_total", "Requests by decision", &["decision"]).unwrap()
});
static BLOCKS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!("agentsentry_blocked_total", "Blocked requests by top rule", &["rule"]).unwrap()
});

#[derive(Clone)]
struct AppConfig {
    /// Real LLM API this gateway forwards clean traffic to (e.g. https://api.openai.com).
    upstream_base_url: String,
    /// If set, the gateway injects this key upstream (clients need none). If empty,
    /// the caller's own Authorization header is passed through (bring-your-own-key).
    upstream_api_key: String,
    /// When true, MITRE ATLAS technique matches also block (default: log only, like
    /// the reference deployment — ATLAS is broad and better as detection than a gate).
    atlas_block: bool,
}

#[derive(Clone)]
struct AppState {
    dlp: Arc<dlp_engine::DlpEngine>,
    atlas: Arc<atlas_engine::AtlasEngine>,
    http: reqwest::Client,
    cfg: AppConfig,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| default.to_string())
}

#[tokio::main]
async fn main() {
    eprintln!("{BANNER}");
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .json()
        .init();

    let cfg = AppConfig {
        upstream_base_url: env_or("UPSTREAM_BASE_URL", "https://api.openai.com").trim_end_matches('/').to_string(),
        upstream_api_key: env_or("UPSTREAM_API_KEY", ""),
        atlas_block: env_or("ATLAS_BLOCK", "false") == "true",
    };
    let listen = env_or("LISTEN_ADDR", "0.0.0.0:9003");

    let dlp = Arc::new(dlp_engine::DlpEngine::new());
    let atlas = Arc::new(atlas_engine::AtlasEngine::new());
    tracing::info!(
        dlp_rules = dlp.rule_count(),
        atlas_rules = atlas.rule_count(),
        upstream = %cfg.upstream_base_url,
        gateway_key = !cfg.upstream_api_key.is_empty(),
        atlas_block = cfg.atlas_block,
        "AgentSentry Gateway starting"
    );

    let state = AppState {
        dlp,
        atlas,
        http: reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(1500))
            .build()
            .expect("http client"),
        cfg,
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics))
        // Any method: chat/completions & friends are POST (scanned), but real
        // OpenAI clients also GET /v1/models etc. — those pass straight through
        // (no body to scan) instead of 405-ing.
        .route("/v1/*path", any(proxy))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&listen).await
        .unwrap_or_else(|e| panic!("cannot bind {listen}: {e}"));
    tracing::info!("listening on {listen}  (point clients at http://{listen}/v1)");
    axum::serve(listener, app).await.unwrap();
}

async fn metrics() -> impl IntoResponse {
    let mut buf = Vec::new();
    let enc = TextEncoder::new();
    enc.encode(&prometheus::gather(), &mut buf).ok();
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], buf)
}

/// Pull scannable text out of an OpenAI-style request body: chat `messages`
/// (string or multimodal `text` parts), a bare `prompt`, or `input`.
fn prompt_text(body: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(msgs) = body["messages"].as_array() {
        for m in msgs {
            match &m["content"] {
                Value::String(s) => parts.push(s.clone()),
                Value::Array(items) => {
                    for it in items {
                        if let Some(t) = it["text"].as_str() { parts.push(t.to_string()); }
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(p) = body["prompt"].as_str() { parts.push(p.to_string()); }
    if let Some(p) = body["input"].as_str() { parts.push(p.to_string()); }
    parts.join(" ")
}

async fn proxy(State(s): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let fp = serde_json::from_slice::<Value>(&body).ok()
        .map(|b| fingerprint::extract(&headers, &b));
    let agent = fp.as_ref().map(|f| f.hash.clone()).unwrap_or_else(|| "unknown".into());

    let body_val: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let text = prompt_text(&body_val);

    // Normalize Unicode homoglyph/fullwidth/zero-width evasion to ASCII for
    // matching only — the ORIGINAL bytes are forwarded upstream untouched.
    let scan_text = dlp_engine::normalize_for_detection(&text);
    let dlp_hits = s.dlp.scan(&scan_text);       // secrets/PII/jailbreak/injection/agentic → block
    let atlas_hits = s.atlas.scan(&scan_text);   // MITRE ATLAS techniques → log (or block if configured)

    let block = !dlp_hits.is_empty() || (s.cfg.atlas_block && !atlas_hits.is_empty());
    if block {
        let mut reasons = dlp_hits.clone();
        if s.cfg.atlas_block { reasons.extend(atlas_hits.clone()); }
        let top = reasons.first().cloned().unwrap_or_else(|| "blocked".into());
        REQUESTS.with_label_values(&["block"]).inc();
        BLOCKS.with_label_values(&[&top]).inc();
        tracing::warn!(agent = %agent, rules = ?reasons, "blocked");
        let mut resp = (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": { "message": "Request blocked by AgentSentry", "type": "agentsentry_blocked" },
                "agentsentry": { "blocked": true, "rules": reasons, "by": "Akav Labs", "learn_more": "https://akav.io" }
            })),
        ).into_response();
        resp.headers_mut().insert("x-powered-by", HeaderValue::from_static("AgentSentry Gateway (Akav Labs)"));
        return resp;
    }

    if !atlas_hits.is_empty() {
        tracing::info!(agent = %agent, techniques = ?atlas_hits, "atlas match (log-only)");
    }

    // Clean — forward to the real upstream.
    REQUESTS.with_label_values(&["allow"]).inc();
    let path_q = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/v1/chat/completions");
    let url = format!("{}{}", s.cfg.upstream_base_url, path_q);
    let streaming = body_val["stream"].as_bool().unwrap_or(false);

    let mut req = s.http.request(method, &url).body(body.clone());
    if let Some(ct_in) = headers.get("content-type") { req = req.header("content-type", ct_in); }
    // Auth: gateway key (sandbox mode) overrides; else pass the caller's own key.
    if !s.cfg.upstream_api_key.is_empty() {
        req = req.header("authorization", format!("Bearer {}", s.cfg.upstream_api_key));
    } else if let Some(a) = headers.get("authorization") {
        req = req.header("authorization", a);
    }
    if let Some(v) = headers.get("anthropic-version") { req = req.header("anthropic-version", v); }
    if let Some(v) = headers.get("x-api-key") { req = req.header("x-api-key", v); }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, upstream = %url, "upstream unreachable");
            return (StatusCode::BAD_GATEWAY, Json(json!({
                "error": { "message": format!("upstream unreachable: {e}"), "type": "upstream_error" }
            }))).into_response();
        }
    };

    let status = resp.status();
    let ct = resp.headers().get("content-type").cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));

    if streaming {
        // Pass the token stream straight through (request already scanned;
        // streaming-response scanning is on the roadmap).
        let mut out = Response::builder().status(status);
        out = out.header("content-type", ct);
        out = out.header("x-agentsentry", "clean");
        out = out.header("x-powered-by", "AgentSentry Gateway (Akav Labs)");
        return out.body(Body::from_stream(resp.bytes_stream()))
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response());
    }

    // Non-streaming: scan the response body too (catches jailbreak-success and
    // secrets echoed back), then return it. Response hits are logged, not dropped.
    let rbytes = resp.bytes().await.unwrap_or_default();
    let rtext = String::from_utf8_lossy(&rbytes);
    let resp_hits = s.dlp.scan_response(&rtext);
    let mut headers_out = HeaderMap::new();
    headers_out.insert(axum::http::header::CONTENT_TYPE, ct);
    headers_out.insert(HeaderName::from_static("x-powered-by"), HeaderValue::from_static("AgentSentry Gateway (Akav Labs)"));
    if resp_hits.is_empty() {
        headers_out.insert(HeaderName::from_static("x-agentsentry"), HeaderValue::from_static("clean"));
    } else {
        tracing::warn!(agent = %agent, rules = ?resp_hits, "response scan flagged");
        if let Ok(v) = HeaderValue::from_str(&resp_hits.join(",")) {
            headers_out.insert(HeaderName::from_static("x-agentsentry-response-flags"), v);
        }
    }
    (status, headers_out, rbytes).into_response()
}
