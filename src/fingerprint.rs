use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

#[allow(dead_code)]
pub struct Fingerprint {
    pub hash: String,
    pub display_name: Option<String>,
    pub framework: Option<String>,
    pub sdk_version: Option<String>,
    pub source_ip: Option<String>,
    pub api_key_prefix: Option<String>,
    pub provider: Option<String>,
    pub key_type: Option<String>,
    pub sdk_lang: Option<String>,
    pub sdk_os: Option<String>,
    pub sdk_arch: Option<String>,
    pub sdk_runtime: Option<String>,
    pub sdk_runtime_version: Option<String>,
    pub api_type: String,
    // Identity enrichment headers
    pub agent_host: Option<String>,
    pub agent_user: Option<String>,
    pub agent_tool: Option<String>,
}

pub fn extract(headers: &HeaderMap, _body: &serde_json::Value) -> Fingerprint {
    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let key = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").trim_start_matches("Bearer ").to_string();

    let api_key_prefix = if key.len() >= 8 { Some(format!("{}...", &key[..8])) } else { None };

    // Identity must be tied ONLY to the bearer key, never to the User-Agent or
    // any other client-controlled header. This hash is the primary key SOC
    // enforcement (block/quarantine) looks up by — if it included the UA, an
    // agent could evade a live block by sending a different UA string on its
    // next request (the same key would compute a brand-new fingerprint and
    // auto-register as an "unknown" agent, bypassing the block entirely).
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    let hash = format!("{:x}", h.finalize());
    let hash = hash[..16.min(hash.len())].to_string();

    let (framework, sdk_version, display_name) = detect_framework(&ua);
    let (provider, key_type) = identify_provider(&key);

    // x-stainless-* headers (OpenAI + Anthropic SDKs)
    let sdk_lang = get_header(headers, "x-stainless-lang");
    let sdk_os = get_header(headers, "x-stainless-os");
    let sdk_arch = get_header(headers, "x-stainless-arch");
    let sdk_runtime = get_header(headers, "x-stainless-runtime");
    let sdk_runtime_version = get_header(headers, "x-stainless-runtime-version");

    // Detect Anthropic native vs OpenAI-compatible
    let api_type = if headers.contains_key("x-api-key") && headers.contains_key("anthropic-version") {
        "anthropic-native".to_string()
    } else {
        "openai-compatible".to_string()
    };

    // Identity enrichment headers (sent by SDK auto-config or agent itself)
    let agent_host = get_header(headers, "x-agent-host");
    let agent_user = get_header(headers, "x-agent-user");
    let agent_tool = get_header(headers, "x-agent-tool")
        .or_else(|| get_header(headers, "x-agent-framework"));

    // Build enriched display name: "tool / host" or "user's host / tool" or fallback
    let display_name = match (&agent_tool, &agent_host, &agent_user) {
        (Some(tool), Some(host), _) => Some(format!("{} / {}", tool, host)),
        (Some(tool), None, Some(user)) => Some(format!("{} / {}", tool, user)),
        (Some(tool), None, None) => Some(format!("{} Agent", tool)),
        (None, Some(host), Some(user)) => Some(format!("{}'s {}", user, host)),
        (None, Some(host), None) => Some(host.clone()),
        _ => display_name,
    };

    // Also infer tool from User-Agent if not explicitly sent
    let agent_tool = agent_tool.or_else(|| {
        if ua.contains("claude-code") || ua.contains("ClaudeCode") { Some("claude-code".into()) }
        else if ua.contains("cursor") || ua.contains("Cursor") { Some("cursor".into()) }
        else if ua.contains("copilot") { Some("copilot".into()) }
        else if ua.contains("vscode") || ua.contains("VSCode") { Some("vscode".into()) }
        else { None }
    });

    Fingerprint {
        hash, display_name, framework, sdk_version, source_ip: None, api_key_prefix,
        provider, key_type, sdk_lang, sdk_os, sdk_arch, sdk_runtime, sdk_runtime_version, api_type,
        agent_host, agent_user, agent_tool,
    }
}

fn get_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

fn identify_provider(key: &str) -> (Option<String>, Option<String>) {
    if key.starts_with("sk-proj-") { return (Some("OpenAI".into()), Some("project-key".into())) }
    if key.starts_with("sk-ant-") { return (Some("Anthropic".into()), Some("api-key".into())) }
    if key.starts_with("sk-") { return (Some("OpenAI".into()), Some("legacy-key".into())) }
    if key.starts_with("hf_") { return (Some("HuggingFace".into()), Some("hub-token".into())) }
    if key.starts_with("AIza") { return (Some("Google".into()), Some("gemini-key".into())) }
    if key.starts_with("gsk_") { return (Some("Groq".into()), Some("api-key".into())) }
    if key.starts_with("dsk-") { return (Some("DeepSeek".into()), Some("api-key".into())) }
    if key.starts_with("xai-") { return (Some("xAI".into()), Some("grok-key".into())) }
    (None, None)
}

fn detect_framework(ua: &str) -> (Option<String>, Option<String>, Option<String>) {
    let u = ua.to_lowercase();
    if u.contains("langchain") { return (Some("langchain".into()), ver(ua, "langchain"), Some("LangChain Agent".into())) }
    if u.contains("crewai") { return (Some("crewai".into()), ver(ua, "crewai"), Some("CrewAI Agent".into())) }
    if u.contains("openai-python") || u.contains("openai/python") { return (Some("openai-sdk".into()), ver(ua, "openai"), Some("OpenAI SDK Agent".into())) }
    if u.contains("anthropic") { return (Some("anthropic-sdk".into()), None, Some("Anthropic SDK Agent".into())) }
    if u.contains("autogen") { return (Some("autogen".into()), None, Some("AutoGen Agent".into())) }
    if u.contains("llamaindex") { return (Some("llamaindex".into()), None, Some("LlamaIndex Agent".into())) }
    if u.contains("ollama") { return (Some("ollama".into()), None, Some("Ollama Client".into())) }
    (None, None, Some("Unknown Agent".into()))
}

fn ver(ua: &str, prefix: &str) -> Option<String> {
    let lower = ua.to_lowercase();
    let pos = lower.find(prefix)?;
    let after = ua[pos + prefix.len()..].trim_start_matches(&['/', ' ', '-'][..]);
    let v: String = after.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    if v.is_empty() { None } else { Some(v) }
}

// Helper for behavioral classification from token usage — exposed for consumers
// and tests; not called on the OSS binary's default request path.
#[allow(dead_code)]
pub fn classify_behavior(prompt_tokens: i32, completion_tokens: i32, method: &str) -> &'static str {
    if method == "embeddings" { return "embedding" }
    if completion_tokens == 0 { return "classification" }
    let ratio = prompt_tokens as f32 / completion_tokens.max(1) as f32;
    if ratio > 10.0 { return "rag-pipeline" }
    if ratio < 0.5 { return "code-generation" }
    "chat"
}
