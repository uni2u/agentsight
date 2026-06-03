// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::cli_output::{
    FileAccessSummary, SessionSummary, SummaryStats, print_adapter_run, print_adapters,
    print_audit_rows, print_capture_adapters, print_exported_snapshot, print_json,
    print_llm_prompts, print_local_audit, print_replay, print_session_summary, print_token_summary,
    prompt_text_chars,
};
use crate::framework::{
    adapters::{builtin_adapters, run_sql_adapters},
    core::Event,
    runners::RunnerError,
    storage::{GenericProjector, SnapshotOptions, SqliteStore},
};
use clap::Subcommand;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

#[derive(Subcommand)]
pub(crate) enum AdapterCommand {
    /// List built-in SQL adapters
    List {
        /// Emit JSON output
        #[arg(long)]
        json: bool,
    },
    /// Run SQL adapters on an existing SQLite database
    Run {
        /// SQLite database path
        #[arg(long)]
        db: String,
        /// SQL adapter to run: auto, anthropic, claude-code, openclaw, gemini-cli
        #[arg(long, default_value = "auto")]
        adapter: String,
    },
}

pub(crate) fn configured_db_path(cli_value: &Option<String>) -> Option<String> {
    cli_value
        .clone()
        .or_else(|| std::env::var("AGENTSIGHT_DB_PATH").ok())
}

pub(crate) fn run_replay(
    input: &str,
    db: &str,
    adapter: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let content = std::fs::read_to_string(input)?;
    let mut store = SqliteStore::open(db)?;
    let mut projector = GenericProjector::new();
    let mut inserted = 0usize;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: Event = serde_json::from_str(trimmed)
            .map_err(|e| format!("failed to parse JSONL line {}: {}", idx + 1, e))?;
        store.insert_event(&event, &mut projector)?;
        inserted += 1;
    }

    if let Some(adapter) = adapter {
        run_sql_adapters(&mut store, adapter)?;
        print_replay(db, inserted, Some(adapter));
    } else {
        print_replay(db, inserted, None);
    }
    Ok(())
}

pub(crate) fn run_token_query(
    db: &str,
    group_by: &str,
    json: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let store = SqliteStore::open(db)?;
    let rows = store.token_summary(group_by)?;
    if json {
        print_json(&rows)?;
    } else {
        print_token_summary(group_by, &rows);
    }
    Ok(())
}

pub(crate) fn run_audit_query(
    db: &str,
    audit_type: Option<&str>,
    limit: usize,
    json: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let store = SqliteStore::open(db)?;
    let rows = store.audit_rows(audit_type, limit)?;
    if json {
        print_json(&rows)?;
    } else {
        print_audit_rows(&rows);
    }
    Ok(())
}

pub(crate) fn run_prompts_query(
    db: &str,
    limit: usize,
    json: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let store = SqliteStore::open(db)?;
    let rows = store.llm_call_rows(limit)?;
    if json {
        print_json(&rows)?;
    } else {
        print_llm_prompts(&rows);
    }
    Ok(())
}

pub(crate) fn run_export(
    db: &str,
    output: &str,
    event_limit: usize,
    audit_limit: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let store = SqliteStore::open(db)?;
    let snapshot = store.export_snapshot(SnapshotOptions {
        event_limit,
        audit_limit,
    })?;
    let json = serde_json::to_vec_pretty(&snapshot)?;
    if output == "-" {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&json)?;
        stdout.write_all(b"\n")?;
    } else {
        std::fs::write(output, json)?;
        print_exported_snapshot(output);
    }
    Ok(())
}

pub(crate) fn run_adapters_command(
    parent_json: bool,
    command: &Option<AdapterCommand>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match command {
        Some(AdapterCommand::List { json }) => run_adapters_list(parent_json || *json),
        Some(AdapterCommand::Run { db, adapter }) => run_adapters_on_db(db, adapter),
        None => run_adapters_list(parent_json),
    }
}

pub(crate) fn run_capture_adapters(
    db_path: Option<&str>,
    adapter: Option<&str>,
) -> Result<(), RunnerError> {
    let Some(db_path) = db_path else {
        return Ok(());
    };
    let Some(adapter) = adapter else {
        return Ok(());
    };
    let mut store = SqliteStore::open(db_path).map_err(|e| {
        RunnerError::from(format!(
            "failed to open SQLite database '{}': {}",
            db_path, e
        ))
    })?;
    run_sql_adapters(&mut store, adapter).map_err(|e| {
        RunnerError::from(format!("failed to run SQL adapter '{}': {}", adapter, e))
    })?;
    print_capture_adapters(db_path, adapter);
    Ok(())
}

fn run_adapters_on_db(
    db: &str,
    adapter: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut store = SqliteStore::open(db)?;
    run_sql_adapters(&mut store, adapter)?;
    print_adapter_run(db, adapter);
    Ok(())
}

fn run_adapters_list(json: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let adapters = builtin_adapters();
    if json {
        let rows: Vec<_> = adapters
            .iter()
            .map(|a| {
                serde_json::json!({
                    "id": a.id,
                    "version": a.version,
                    "type": a.adapter_type,
                    "supports_detect": a.supports_detect(),
                    "sql_files": a.sql_files.iter().map(|(name, _)| *name).collect::<Vec<_>>()
                })
            })
            .collect();
        print_json(&rows)?;
    } else {
        print_adapters(&adapters);
    }
    Ok(())
}

impl SessionSummary {
    pub fn from_sqlite(db: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut store = SqliteStore::open(db)?;
        let snap = store.export_snapshot(SnapshotOptions {
            event_limit: 50_000,
            audit_limit: 50_000,
        })?;
        let s = &snap.summary;
        let duration_s = match (s.start_timestamp_ms, s.end_timestamp_ms) {
            (Some(start), Some(end)) if end > start => (end - start) as f64 / 1000.0,
            _ => 0.0,
        };
        let llm_rows = store.llm_call_rows(50_000)?;
        let first_llm_after_ms = s.start_timestamp_ms.and_then(|start| {
            llm_rows
                .iter()
                .map(|row| row.start_timestamp_ms)
                .min()
                .and_then(|ts| ts.checked_sub(start))
        });
        let mut prompt_chars = SummaryStats::default();
        let mut llm_latency_ms = SummaryStats::default();
        for row in &llm_rows {
            if let Some(chars) = prompt_text_chars(&row.request) {
                prompt_chars.add(chars as u64);
            }
            if let Some(delta) = row
                .end_timestamp_ms
                .and_then(|end| end.checked_sub(row.start_timestamp_ms))
            {
                llm_latency_ms.add(delta);
            }
        }
        let models = snap
            .token_summary
            .iter()
            .map(|r| {
                (
                    r.group.clone(),
                    r.input_tokens,
                    r.output_tokens,
                    r.total_tokens,
                    r.calls,
                )
            })
            .collect();
        let mut processes = BTreeMap::new();
        for row in &snap.audit_events {
            if row.action.as_deref() == Some("exec") {
                *processes
                    .entry(row.comm.clone().unwrap_or_default())
                    .or_default() += 1;
            }
        }
        let mut process_exits = BTreeMap::new();
        for row in &snap.audit_events {
            if row.action.as_deref() == Some("exit") {
                let status = row.status.as_deref().unwrap_or("observed").to_string();
                *process_exits.entry(status).or_default() += 1;
            }
        }
        let mut seen_files = BTreeSet::new();
        let mut files = Vec::new();
        let mut file_access = FileAccessSummary::default();
        let mut file_dirs = BTreeMap::new();
        for row in &snap.audit_events {
            if row.audit_type != "file" {
                continue;
            }
            file_access.events += 1;
            let action = row.action.as_deref().unwrap_or("observed").to_string();
            *file_access.actions.entry(action).or_default() += 1;
            if let Some(delta) = after_start(s.start_timestamp_ms, row.timestamp_ms) {
                file_access.first_after_ms = Some(
                    file_access
                        .first_after_ms
                        .map_or(delta, |current| current.min(delta)),
                );
                file_access.last_after_ms = Some(
                    file_access
                        .last_after_ms
                        .map_or(delta, |current| current.max(delta)),
                );
            }
            if let Some(target) = row.target.as_ref() {
                if seen_files.insert(target.clone()) {
                    files.push(target.clone());
                }
                *file_dirs.entry(file_directory(target)).or_default() += 1;
            }
        }
        file_access.directories = top_counts(file_dirs, 8);

        let mut endpoint_counts = BTreeMap::new();
        let mut network_events = 0usize;
        for event in &snap.events {
            if let Some(host) = event.host.as_ref() {
                network_events += 1;
                let endpoint = event
                    .path
                    .as_ref()
                    .filter(|path| !path.is_empty())
                    .map(|path| format!("{host}{path}"))
                    .unwrap_or_else(|| host.clone());
                *endpoint_counts.entry(endpoint).or_default() += 1;
            }
        }
        let endpoints = top_counts(endpoint_counts, 8)
            .into_iter()
            .map(|(endpoint, count)| format!("{endpoint}({count})"))
            .collect();
        let first_tool_timestamp_ms: Option<u64> = store
            .connection_mut()
            .query_row("SELECT MIN(timestamp_ms) FROM tool_calls", [], |row| {
                row.get::<_, Option<i64>>(0)
            })?
            .map(|v| v as u64);
        let first_tool_after_ms =
            first_tool_timestamp_ms.and_then(|ts| after_start(s.start_timestamp_ms, ts));
        let mut tool_calls = BTreeMap::new();
        let mut tool_duration_ms = SummaryStats::default();
        {
            let mut stmt = store.connection_mut().prepare(
                "SELECT COALESCE(tool_name, '?'), COUNT(*)
                 FROM tool_calls
                 GROUP BY COALESCE(tool_name, '?')
                 ORDER BY COUNT(*) DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
            })?;
            for row in rows {
                let (name, count) = row?;
                tool_calls.insert(name, count);
            }
        }
        {
            let mut stmt = store
                .connection_mut()
                .prepare("SELECT duration_ms FROM tool_calls WHERE duration_ms >= 0")?;
            let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
            for row in rows {
                tool_duration_ms.add(row? as u64);
            }
        }
        Ok(Self {
            source: "agentsight".into(),
            duration_s,
            first_llm_after_ms,
            first_tool_after_ms,
            prompt_chars,
            llm_latency_ms,
            models,
            processes,
            process_exits,
            tool_calls,
            tool_duration_ms,
            files,
            file_access,
            network_events,
            endpoints,
        })
    }

    pub fn from_local_jsonl(source: &str, _file: &str, data: &serde_json::Value) -> Self {
        let models = data
            .get("models")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .map(|(name, u)| {
                        let arr = u.as_array();
                        let get = |i: usize| {
                            arr.and_then(|a| a.get(i))
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0)
                        };
                        (name.clone(), get(0), get(1), get(2), 0i64)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let tool_calls = data
            .get("tools")
            .and_then(|v| v.as_object())
            .map(|t| {
                t.iter()
                    .map(|(n, c)| (n.clone(), c.as_u64().unwrap_or(0) as usize))
                    .collect()
            })
            .unwrap_or_default();
        let duration_s = json_u64(data, "duration_ms") as f64 / 1000.0;
        Self {
            source: source.into(),
            duration_s,
            first_llm_after_ms: None,
            first_tool_after_ms: None,
            prompt_chars: SummaryStats::default(),
            llm_latency_ms: SummaryStats::default(),
            models,
            processes: BTreeMap::new(),
            process_exits: BTreeMap::new(),
            tool_calls,
            tool_duration_ms: SummaryStats::default(),
            files: vec![],
            file_access: FileAccessSummary::default(),
            network_events: 0,
            endpoints: vec![],
        }
    }
}

fn after_start(start_timestamp_ms: Option<u64>, timestamp_ms: u64) -> Option<u64> {
    start_timestamp_ms.and_then(|start| timestamp_ms.checked_sub(start))
}

fn top_counts(counts: BTreeMap<String, usize>, limit: usize) -> Vec<(String, usize)> {
    let mut rows = counts.into_iter().collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(limit);
    rows
}

fn file_directory(path: &str) -> String {
    std::path::Path::new(path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string())
}

pub(crate) fn run_db_summary(
    db: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if db.is_none()
        && let Some((source, file, data)) = read_latest_local_session()
    {
        print_session_summary(&SessionSummary::from_local_jsonl(&source, &file, &data));
        return Ok(());
    }
    let db = db.ok_or("No session data found. Run `agentsight record` first, or pass --db.")?;
    print_session_summary(&SessionSummary::from_sqlite(db)?);
    Ok(())
}

pub(crate) fn run_local_audit(json: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (source, file, data) = read_latest_local_session()
        .ok_or("No session data found. Install Claude Code or Codex, or pass --db.")?;

    if json {
        print_json(&data)?;
        return Ok(());
    }

    print_local_audit(&source, &file, &data);

    Ok(())
}

// ---------------------------------------------------------------------------
// Local agent session reader (reads ~/.claude and ~/.codex JSONL directly)
// ---------------------------------------------------------------------------

fn local_session_dirs() -> Vec<(&'static str, std::path::PathBuf)> {
    let home = dirs::home_dir().unwrap_or_default();
    [
        ("claude", home.join(".claude/projects")),
        ("codex", home.join(".codex/sessions")),
    ]
    .into_iter()
    .filter(|(_, d)| d.is_dir())
    .collect()
}

fn walk_jsonl(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, &std::fs::Metadata)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_jsonl(&path, f);
        } else if path.extension().is_some_and(|e| e == "jsonl")
            && let Ok(meta) = path.metadata()
        {
            f(&path, &meta);
        }
    }
}

pub(crate) fn count_local_sessions() -> Vec<(&'static str, std::path::PathBuf, usize, u64)> {
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

fn read_latest_local_session() -> Option<(String, String, serde_json::Value)> {
    let mut candidates = Vec::new();
    for (name, dir) in local_session_dirs() {
        walk_jsonl(&dir, &mut |path, meta| {
            let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            candidates.push((mtime, name, path.to_path_buf()));
        });
    }
    candidates.sort_by_key(|(mtime, _, _)| std::cmp::Reverse(*mtime));
    for (_, name, path) in candidates {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let parsed = parse_local_session(name, &content);
        if !parsed.is_null() {
            return Some((name.into(), path.display().to_string(), parsed));
        }
    }
    None
}

fn json_u64(v: &serde_json::Value, key: &str) -> u64 {
    v.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn parse_local_session(source: &str, content: &str) -> serde_json::Value {
    let mut models: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    let mut tools: BTreeMap<String, usize> = BTreeMap::new();
    let mut duration_ms = 0u64;
    let mut num_turns = 0u64;
    let mut cost_usd = 0.0f64;
    let mut codex_model = String::new();

    for line in content.lines() {
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let typ = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match (source, typ) {
            ("claude", "result") => {
                duration_ms = json_u64(&obj, "duration_ms");
                num_turns = json_u64(&obj, "num_turns");
                cost_usd = obj
                    .get("total_cost_usd")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                if let Some(mu) = obj.get("modelUsage").and_then(|v| v.as_object()) {
                    for (m, u) in mu {
                        let inp = json_u64(u, "inputTokens");
                        let out = json_u64(u, "outputTokens");
                        let total = inp
                            + out
                            + json_u64(u, "cacheReadInputTokens")
                            + json_u64(u, "cacheCreationInputTokens");
                        models.insert(m.clone(), (inp, out, total));
                    }
                }
            }
            ("claude", "assistant") => {
                if let Some(items) = obj.pointer("/message/content").and_then(|v| v.as_array()) {
                    for item in items {
                        if item.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                            let n = item.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                            *tools.entry(n.into()).or_default() += 1;
                        }
                    }
                }
            }
            ("codex", "turn_context") => {
                if let Some(m) = obj.pointer("/payload/model").and_then(|v| v.as_str()) {
                    codex_model = m.into();
                }
            }
            ("codex", "event_msg") => {
                if obj.pointer("/payload/type").and_then(|v| v.as_str()) == Some("token_count")
                    && let Some(u) = obj.pointer("/payload/info/total_token_usage")
                {
                    let key = if codex_model.is_empty() {
                        "unknown"
                    } else {
                        &codex_model
                    };
                    models.insert(
                        key.into(),
                        (
                            json_u64(u, "input_tokens"),
                            json_u64(u, "output_tokens"),
                            json_u64(u, "total_tokens"),
                        ),
                    );
                }
            }
            ("codex", "response_item")
                if obj.pointer("/payload/type").and_then(|v| v.as_str())
                    == Some("function_call") =>
            {
                let n = obj
                    .pointer("/payload/name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                *tools.entry(n.into()).or_default() += 1;
            }
            _ => {}
        }
    }

    if models.is_empty() && tools.is_empty() && duration_ms == 0 && num_turns == 0 {
        return serde_json::Value::Null;
    }
    serde_json::json!({ "models": models, "tools": tools, "duration_ms": duration_ms, "num_turns": num_turns, "cost_usd": cost_usd })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sqlite_summary_reports_timeline_prompt_and_access_scope() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("summary.db");
        let mut store = SqliteStore::open(&db).unwrap();
        let mut projector = GenericProjector::new();

        for event in [
            Event::new_with_timestamp(
                1_000,
                "process".to_string(),
                42,
                "claude".to_string(),
                json!({"event": "EXEC", "filename": "/usr/bin/claude"}),
            ),
            Event::new_with_timestamp(
                1_200,
                "http_parser".to_string(),
                42,
                "claude".to_string(),
                json!({
                    "tid": 7,
                    "message_type": "request",
                    "method": "POST",
                    "path": "/v1/messages",
                    "headers": {"host": "api.anthropic.com"},
                    "body": "{\"model\":\"claude-sonnet-4\",\"messages\":[{\"role\":\"user\",\"content\":\"hello summary\"}]}"
                }),
            ),
            Event::new_with_timestamp(
                1_700,
                "http_parser".to_string(),
                42,
                "claude".to_string(),
                json!({
                    "tid": 7,
                    "message_type": "response",
                    "path": "/v1/messages",
                    "headers": {"host": "api.anthropic.com"},
                    "status_code": 200,
                    "body": "{\"model\":\"claude-sonnet-4\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}"
                }),
            ),
            Event::new_with_timestamp(
                1_800,
                "process".to_string(),
                42,
                "claude".to_string(),
                json!({"event": "FILE_WRITE", "path": "/tmp/agentsight-summary/a.txt"}),
            ),
            Event::new_with_timestamp(
                1_900,
                "process".to_string(),
                42,
                "claude".to_string(),
                json!({"event": "FILE_WRITE", "path": "/tmp/agentsight-summary/sub/b.txt"}),
            ),
        ] {
            store.insert_event(&event, &mut projector).unwrap();
        }

        store
            .connection_mut()
            .execute(
                "INSERT INTO tool_calls (
                    id, timestamp_ms, start_timestamp_ms, end_timestamp_ms,
                    duration_ms, tool_name, adapter_id
                 ) VALUES ('tool-1', 1500, 1500, 1650, 150, 'Bash', 'claude-code')",
                [],
            )
            .unwrap();

        let summary = SessionSummary::from_sqlite(db.to_str().unwrap()).unwrap();
        assert_eq!(summary.duration_s, 0.9);
        assert_eq!(summary.first_llm_after_ms, Some(200));
        assert_eq!(summary.first_tool_after_ms, Some(500));
        assert_eq!(summary.prompt_chars.count, 1);
        assert_eq!(summary.prompt_chars.total, 13);
        assert_eq!(summary.llm_latency_ms.count, 1);
        assert_eq!(summary.llm_latency_ms.total, 500);
        assert_eq!(summary.tool_calls.get("Bash"), Some(&1));
        assert_eq!(summary.tool_duration_ms.count, 1);
        assert_eq!(summary.tool_duration_ms.total, 150);
        assert_eq!(summary.file_access.events, 2);
        assert_eq!(summary.file_access.actions.get("write"), Some(&2));
        assert_eq!(summary.files.len(), 2);
        assert_eq!(summary.network_events, 2);
        assert!(
            summary
                .endpoints
                .contains(&"api.anthropic.com/v1/messages(2)".to_string())
        );
    }
}
