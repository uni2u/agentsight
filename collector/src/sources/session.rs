// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::text::{short_session_id, truncate_text};
use crate::view::types::Snapshot;

#[derive(Debug, Clone)]
pub(crate) struct LocalSession {
    pub(crate) agent: String,
    pub(crate) display_id: String,
    pub(crate) path: PathBuf,
    pub(crate) updated: SystemTime,
    pub(crate) model: Option<String>,
    pub(crate) input_tokens: i64,
    pub(crate) output_tokens: i64,
    pub(crate) total_tokens: i64,
    pub(crate) models: BTreeMap<String, (i64, i64, i64)>,
    pub(crate) tools: BTreeMap<String, usize>,
    pub(crate) prompt_preview: Option<String>,
    pub(crate) duration_ms: u64,
    pub(crate) num_turns: u64,
    pub(crate) cost_usd: f64,
}

impl LocalSession {
    pub(crate) fn age_s(&self) -> Option<f64> {
        SystemTime::now()
            .duration_since(self.updated)
            .ok()
            .map(|duration| duration.as_secs_f64())
    }

    pub(crate) fn tools_total(&self) -> usize {
        self.tools.values().sum()
    }

    pub(crate) fn has_tokens(&self) -> bool {
        self.input_tokens > 0 || self.output_tokens > 0 || self.total_tokens > 0
    }

    pub(crate) fn to_json(&self) -> Value {
        serde_json::json!({
            "models": self.models,
            "tools": self.tools,
            "duration_ms": self.duration_ms,
            "num_turns": self.num_turns,
            "cost_usd": self.cost_usd,
            "path": self.path,
        })
    }
}

pub(crate) fn discover(limit: usize) -> Vec<LocalSession> {
    let mut candidates = Vec::new();
    for (agent, dir) in local_session_dirs() {
        walk_jsonl(&dir, &mut |path, meta| {
            candidates.push((
                meta.modified().unwrap_or(UNIX_EPOCH),
                agent,
                path.to_path_buf(),
            ));
        });
    }
    candidates.sort_by_key(|(updated, _, _)| std::cmp::Reverse(*updated));

    let mut sessions = Vec::new();
    let mut seen = HashSet::new();
    let target = limit.clamp(1, 25);
    let scan = target.saturating_mul(3).clamp(10, 75);
    for (updated, agent, path) in candidates.into_iter().take(scan) {
        let Some(session) = read_session_path_with_source(agent, &path, updated) else {
            continue;
        };
        if seen.insert(session.display_id.clone()) {
            sessions.push(session);
        }
        if sessions.len() >= target {
            break;
        }
    }
    sessions
}

pub(crate) fn latest() -> Option<LocalSession> {
    discover(25).into_iter().next()
}

pub(crate) fn sessions_from_path_strings<'a>(
    targets: impl IntoIterator<Item = &'a str>,
) -> Vec<LocalSession> {
    let mut seen = BTreeSet::new();
    targets
        .into_iter()
        .filter_map(session_log_path_from_str)
        .filter_map(|path| {
            let path = normalize_session_log_path(&path);
            seen.insert(path.clone()).then(|| {
                read_session_path_with_source(
                    local_session_source(&path)?,
                    &path,
                    path_updated(&path),
                )
            })?
        })
        .collect()
}

pub(crate) fn from_snapshot(snapshot: &Snapshot) -> Vec<LocalSession> {
    sessions_from_path_strings(
        snapshot
            .audit_events
            .iter()
            .filter(|row| row.audit_type == "file")
            .filter_map(|row| row.target.as_deref()),
    )
}

pub(crate) fn model_rows(sessions: &[LocalSession]) -> Vec<(String, i64, i64, i64, i64)> {
    let mut models = BTreeMap::<String, (i64, i64, i64, i64)>::new();
    for session in sessions {
        for (model, (input, output, total)) in &session.models {
            let entry = models.entry(model.clone()).or_default();
            entry.0 += input;
            entry.1 += output;
            entry.2 += total;
            entry.3 += 1;
        }
    }
    models
        .into_iter()
        .map(|(model, (input, output, total, calls))| (model, input, output, total, calls))
        .collect()
}

pub(crate) fn model_token_counts(sessions: &[LocalSession]) -> BTreeMap<String, i64> {
    let mut counts = BTreeMap::new();
    for session in sessions {
        for (model, (_, _, total)) in &session.models {
            *counts.entry(model.clone()).or_default() += *total;
        }
    }
    counts
}

pub(crate) fn dominant_model(sessions: &[LocalSession]) -> Option<String> {
    model_token_counts(sessions)
        .into_iter()
        .max_by_key(|(_, total)| *total)
        .map(|(model, _)| model)
}

pub(crate) fn total_tokens(sessions: &[LocalSession]) -> i64 {
    sessions
        .iter()
        .filter(|session| session.has_tokens())
        .map(|session| session.total_tokens)
        .sum()
}

pub(crate) fn tool_counts(sessions: &[LocalSession]) -> BTreeMap<String, usize> {
    let mut tools = BTreeMap::new();
    for session in sessions {
        for (tool, count) in &session.tools {
            *tools.entry(tool.clone()).or_default() += count;
        }
    }
    tools
}

pub(crate) fn prompt_char_counts(sessions: &[LocalSession]) -> Vec<u64> {
    sessions
        .iter()
        .filter_map(|session| session.prompt_preview.as_ref())
        .map(|prompt| prompt.chars().count() as u64)
        .collect()
}

pub(crate) fn matches_filter(
    session: &LocalSession,
    pid_filter: Option<u32>,
    text_filter: Option<&str>,
) -> bool {
    if pid_filter.is_some() {
        return true;
    }
    let Some(filter) = text_filter else {
        return true;
    };
    let filter = filter.to_ascii_lowercase();
    session.agent.to_ascii_lowercase().contains(&filter)
        || session
            .prompt_preview
            .as_ref()
            .is_some_and(|prompt| prompt.to_ascii_lowercase().contains(&filter))
        || session
            .model
            .as_ref()
            .is_some_and(|model| model.to_ascii_lowercase().contains(&filter))
        || session
            .path
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains(&filter)
}

pub(crate) fn count_local_sessions() -> Vec<(&'static str, PathBuf, usize, u64)> {
    local_session_dirs()
        .into_iter()
        .filter_map(|(name, dir)| {
            let (mut count, mut bytes) = (0usize, 0u64);
            walk_jsonl(&dir, &mut |_, meta| {
                count += 1;
                bytes += meta.len();
            });
            (count > 0).then_some((name, dir, count, bytes))
        })
        .collect()
}

pub(crate) fn session_log_path_from_str(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim().trim_end_matches(" (deleted)");
    if trimmed.is_empty() {
        return None;
    }
    let path = Path::new(trimmed);
    if !path.is_absolute() || path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
        return None;
    }
    local_session_source(path).map(|_| normalize_session_log_path(path))
}

pub(crate) fn normalize_session_log_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub(crate) fn local_session_source(path: &Path) -> Option<&'static str> {
    let path = path.to_string_lossy();
    if path.contains("/.claude/") {
        Some("claude")
    } else if path.contains("/.codex/") {
        Some("codex")
    } else {
        None
    }
}

fn read_session_path_with_source(
    agent: &str,
    path: &Path,
    updated: SystemTime,
) -> Option<LocalSession> {
    let content = fs::read_to_string(path).ok()?;
    parse_content(agent, path, updated, &content)
}

fn path_updated(path: &Path) -> SystemTime {
    path.metadata()
        .ok()
        .and_then(|meta| meta.modified().ok())
        .unwrap_or(UNIX_EPOCH)
}

pub(crate) fn parse_content(
    agent: &str,
    path: &Path,
    updated: SystemTime,
    content: &str,
) -> Option<LocalSession> {
    let mut session_id = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("session")
        .to_string();
    let mut model = None;
    let mut models = BTreeMap::<String, (i64, i64, i64)>::new();
    let mut claude_message_models = BTreeMap::<String, (i64, i64, i64)>::new();
    let mut claude_seen_usage = HashSet::new();
    let mut tools = BTreeMap::new();
    let mut prompt_preview = None;
    let mut duration_ms = 0;
    let mut num_turns = 0;
    let mut cost_usd = 0.0;
    let mut codex_model = String::new();

    for line in content.lines() {
        let Ok(obj) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(id) = local_session_id(&obj) {
            session_id = id;
        }
        let typ = obj
            .get("type")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        match (agent, typ) {
            ("claude", "result") => {
                duration_ms = json_u64(&obj, "duration_ms");
                num_turns = json_u64(&obj, "num_turns");
                cost_usd = obj
                    .get("total_cost_usd")
                    .and_then(|value| value.as_f64())
                    .unwrap_or(0.0);
                if let Some(model_usage) = obj.get("modelUsage").and_then(|value| value.as_object())
                {
                    for (name, usage) in model_usage {
                        model.get_or_insert_with(|| name.clone());
                        add_usage(
                            &mut models,
                            name,
                            json_i64(usage, "inputTokens"),
                            json_i64(usage, "outputTokens"),
                            json_i64(usage, "inputTokens")
                                + json_i64(usage, "outputTokens")
                                + json_i64(usage, "cacheReadInputTokens")
                                + json_i64(usage, "cacheCreationInputTokens"),
                        );
                    }
                }
            }
            ("claude", "assistant") => {
                if let Some(name) = obj
                    .pointer("/message/model")
                    .and_then(|value| value.as_str())
                {
                    model.get_or_insert_with(|| name.to_string());
                }
                if let Some(usage) = obj.pointer("/message/usage")
                    && claude_seen_usage.insert(claude_usage_key(&obj))
                {
                    let name = obj
                        .pointer("/message/model")
                        .and_then(|value| value.as_str())
                        .unwrap_or("unknown");
                    add_usage(
                        &mut claude_message_models,
                        name,
                        json_i64(usage, "input_tokens"),
                        json_i64(usage, "output_tokens"),
                        json_i64(usage, "input_tokens")
                            + json_i64(usage, "output_tokens")
                            + json_i64(usage, "cache_read_input_tokens")
                            + json_i64(usage, "cache_creation_input_tokens"),
                    );
                }
                if let Some(items) = obj
                    .pointer("/message/content")
                    .and_then(|value| value.as_array())
                {
                    for item in items {
                        if item.get("type").and_then(|value| value.as_str()) == Some("tool_use") {
                            let name = item
                                .get("name")
                                .and_then(|value| value.as_str())
                                .unwrap_or("?");
                            *tools.entry(name.to_string()).or_default() += 1;
                        }
                    }
                }
            }
            ("claude", "user") => {
                if let Some(text) =
                    local_message_preview(obj.pointer("/message/content").unwrap_or(&obj))
                {
                    prompt_preview = Some(text);
                }
            }
            ("codex", "turn_context") => {
                if let Some(name) = obj
                    .pointer("/payload/model")
                    .and_then(|value| value.as_str())
                {
                    codex_model = name.to_string();
                    model = Some(name.to_string());
                }
            }
            ("codex", "event_msg") => {
                if obj
                    .pointer("/payload/type")
                    .and_then(|value| value.as_str())
                    == Some("token_count")
                    && let Some(usage) = obj.pointer("/payload/info/total_token_usage")
                {
                    let name = if codex_model.is_empty() {
                        "unknown"
                    } else {
                        &codex_model
                    };
                    models.insert(
                        name.to_string(),
                        (
                            json_i64(usage, "input_tokens"),
                            json_i64(usage, "output_tokens"),
                            json_i64(usage, "total_tokens"),
                        ),
                    );
                }
            }
            ("codex", "response_item")
                if obj
                    .pointer("/payload/type")
                    .and_then(|value| value.as_str())
                    == Some("function_call") =>
            {
                let name = obj
                    .pointer("/payload/name")
                    .and_then(|value| value.as_str())
                    .unwrap_or("?");
                *tools.entry(name.to_string()).or_default() += 1;
            }
            ("codex", "message") | ("codex", "input") | ("codex", "user") => {
                if let Some(text) = local_message_preview(&obj) {
                    prompt_preview = Some(text);
                }
            }
            _ if prompt_preview.is_none() && typ.contains("user") => {
                if let Some(text) = local_message_preview(&obj) {
                    prompt_preview = Some(text);
                }
            }
            _ => {}
        }
    }

    if models.is_empty() {
        models = claude_message_models;
    }
    let input_tokens = models.values().map(|usage| usage.0).sum();
    let output_tokens = models.values().map(|usage| usage.1).sum();
    let total_tokens = models.values().map(|usage| usage.2).sum();
    if total_tokens == 0 && tools.is_empty() && prompt_preview.is_none() && model.is_none() {
        return None;
    }

    Some(LocalSession {
        agent: agent.to_string(),
        display_id: format!("{agent}:{}", short_session_id(&session_id)),
        path: normalize_session_log_path(path),
        updated,
        model,
        input_tokens,
        output_tokens,
        total_tokens,
        models,
        tools,
        prompt_preview,
        duration_ms,
        num_turns,
        cost_usd,
    })
}

fn local_session_dirs() -> Vec<(&'static str, PathBuf)> {
    let Some(home) = user_home_dir() else {
        return Vec::new();
    };
    [
        ("claude", home.join(".claude/projects")),
        ("codex", home.join(".codex/sessions")),
    ]
    .into_iter()
    .filter(|(_, path)| path.is_dir())
    .collect()
}

fn user_home_dir() -> Option<PathBuf> {
    std::env::var("SUDO_USER")
        .ok()
        .and_then(|user| {
            fs::read_to_string("/etc/passwd").ok().and_then(|passwd| {
                passwd
                    .lines()
                    .find(|line| line.starts_with(&format!("{user}:")))
                    .and_then(|line| line.split(':').nth(5))
                    .map(PathBuf::from)
            })
        })
        .or_else(dirs::home_dir)
}

fn walk_jsonl(dir: &Path, f: &mut dyn FnMut(&Path, &fs::Metadata)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_jsonl(&path, f);
        } else if path.extension().is_some_and(|ext| ext == "jsonl")
            && let Ok(meta) = path.metadata()
        {
            f(&path, &meta);
        }
    }
}

fn add_usage(
    models: &mut BTreeMap<String, (i64, i64, i64)>,
    model: &str,
    input: i64,
    output: i64,
    total: i64,
) {
    let entry = models.entry(model.to_string()).or_default();
    entry.0 += input;
    entry.1 += output;
    entry.2 += total;
}

fn local_session_id(obj: &Value) -> Option<String> {
    for key in ["sessionId", "session_id", "conversation_id"] {
        if let Some(value) = obj.get(key).and_then(|value| value.as_str())
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    for pointer in ["/payload/session_id", "/payload/sessionId"] {
        if let Some(value) = obj.pointer(pointer).and_then(|value| value.as_str())
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    None
}

fn claude_usage_key(obj: &Value) -> String {
    obj.get("requestId")
        .or_else(|| obj.pointer("/message/id"))
        .or_else(|| obj.get("uuid"))
        .and_then(|value| value.as_str())
        .unwrap_or("usage")
        .to_string()
}

fn local_message_preview(value: &Value) -> Option<String> {
    let mut parts = Vec::new();
    collect_local_text(value, &mut parts);
    let text = parts
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (!text.is_empty()).then(|| truncate_text(&text, 80))
}

fn collect_local_text(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_local_text(item, out);
            }
        }
        Value::Object(obj) => {
            if obj
                .get("type")
                .and_then(|value| value.as_str())
                .is_some_and(|typ| typ == "tool_use" || typ == "function_call")
            {
                return;
            }
            for key in ["text", "content", "message", "input", "prompt"] {
                if let Some(value) = obj.get(key) {
                    collect_local_text(value, out);
                }
            }
        }
        _ => {}
    }
}

fn json_i64(value: &Value, key: &str) -> i64 {
    value
        .get(key)
        .and_then(|value| value.as_i64().or_else(|| value.as_u64().map(|v| v as i64)))
        .unwrap_or_default()
}

fn json_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(|value| value.as_u64()).unwrap_or(0)
}
