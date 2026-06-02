// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::framework::{
    adapters::{builtin_adapters, run_sql_adapters},
    core::Event,
    runners::RunnerError,
    storage::{GenericProjector, SnapshotOptions, SqliteStore},
};
use clap::Subcommand;
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
        println!(
            "Replayed {} events into {} and ran adapter '{}'",
            inserted, db, adapter
        );
    } else {
        println!(
            "Replayed {} events into {} without SQL adapters",
            inserted, db
        );
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
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        println!("Token usage grouped by {}", group_by);
        println!(
            "{:<32} {:>12} {:>12} {:>12} {:>12} {:>12} {:>8}",
            "group", "input", "output", "cache_new", "cache_read", "total", "calls"
        );
        for row in rows {
            println!(
                "{:<32} {:>12} {:>12} {:>12} {:>12} {:>12} {:>8}",
                truncate(&row.group, 32),
                row.input_tokens,
                row.output_tokens,
                row.cache_creation_tokens,
                row.cache_read_tokens,
                row.total_tokens,
                row.calls
            );
        }
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
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        println!("Audit events");
        println!(
            "{:<15} {:<10} {:<8} {:<16} {:<10} {:<28} summary",
            "timestamp_ms", "type", "pid", "comm", "status", "target"
        );
        for row in rows {
            println!(
                "{:<15} {:<10} {:<8} {:<16} {:<10} {:<28} {}",
                row.timestamp_ms,
                row.audit_type,
                row.pid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                truncate(row.comm.as_deref().unwrap_or("-"), 16),
                row.status.as_deref().unwrap_or("-"),
                truncate(row.target.as_deref().unwrap_or("-"), 28),
                row.summary.as_deref().unwrap_or("")
            );
        }
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
        println!("Exported snapshot to {}", output);
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
    println!("✓ SQL adapters projected: {} ({})", adapter, db_path);
    Ok(())
}

fn run_adapters_on_db(
    db: &str,
    adapter: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut store = SqliteStore::open(db)?;
    run_sql_adapters(&mut store, adapter)?;
    println!("Ran SQL adapter '{}' on {}", adapter, db);
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
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        println!("{:<16} {:<10} {:<8} detect", "id", "version", "type");
        for adapter in adapters {
            println!(
                "{:<16} {:<10} {:<8} {}",
                adapter.id,
                adapter.version,
                adapter.adapter_type,
                if adapter.supports_detect() {
                    "yes"
                } else {
                    "no"
                }
            );
        }
    }
    Ok(())
}

// Unified summary data — produced from SQLite, Claude JSONL, or Codex JSONL.
pub(crate) struct SessionSummary {
    pub source: String,
    pub duration_s: f64,
    pub models: Vec<(String, i64, i64, i64, i64)>, // (name, input, output, total, calls)
    pub processes: BTreeMap<String, usize>,
    pub tool_calls: BTreeMap<String, usize>,
    pub files: Vec<String>,
    pub endpoints: Vec<String>,
    pub db_path: Option<String>,
}

impl SessionSummary {
    pub fn from_sqlite(db: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut store = SqliteStore::open(db)?;
        let snap = store.export_snapshot(SnapshotOptions { event_limit: 50_000, audit_limit: 50_000 })?;
        let s = &snap.summary;
        let duration_s = match (s.start_timestamp_ms, s.end_timestamp_ms) {
            (Some(start), Some(end)) if end > start => (end - start) as f64 / 1000.0,
            _ => 0.0,
        };
        let models = snap.token_summary.iter()
            .map(|r| (r.group.clone(), r.input_tokens, r.output_tokens, r.total_tokens, r.calls))
            .collect();
        let mut processes = BTreeMap::new();
        for row in &snap.audit_events {
            if row.action.as_deref() == Some("exec") {
                *processes.entry(row.comm.clone().unwrap_or_default()).or_default() += 1;
            }
        }
        let mut files = Vec::new();
        for row in &snap.audit_events {
            if row.audit_type == "file" && row.target.as_ref().is_some_and(|t| !files.contains(t)) {
                files.push(row.target.clone().unwrap());
            }
        }
        let endpoints: Vec<String> = snap.events.iter()
            .filter_map(|e| e.host.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter().collect();
        let mut tool_calls = BTreeMap::new();
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
        Ok(Self { source: "agentsight".into(), duration_s, models, processes, tool_calls, files, endpoints, db_path: Some(db.into()) })
    }

    pub fn from_local_jsonl(source: &str, file: &str, data: &serde_json::Value) -> Self {
        let models = data.get("models").and_then(|v| v.as_object()).map(|m| {
            m.iter().map(|(name, u)| {
                let arr = u.as_array();
                let get = |i: usize| arr.and_then(|a| a.get(i)).and_then(|v| v.as_i64()).unwrap_or(0);
                (name.clone(), get(0), get(1), get(2), 0i64)
            }).collect()
        }).unwrap_or_default();
        let tool_calls = data.get("tools").and_then(|v| v.as_object()).map(|t| {
            t.iter().map(|(n, c)| (n.clone(), c.as_u64().unwrap_or(0) as usize)).collect()
        }).unwrap_or_default();
        let duration_s = json_u64(data, "duration_ms") as f64 / 1000.0;
        Self { source: source.into(), duration_s, models, processes: BTreeMap::new(), tool_calls, files: vec![], endpoints: vec![], db_path: Some(file.into()) }
    }

    pub fn print(&self) {
        // Header
        let total_tokens: i64 = self.models.iter().map(|m| m.3).sum();
        let total_calls: i64 = self.models.iter().map(|m| m.4).sum();
        print!("{} session", self.source);
        if self.duration_s > 0.0 { print!(" · {:.0}s", self.duration_s); }
        if total_calls > 0 { print!(" · {} API calls", total_calls); }
        println!(" · {} tokens", total_tokens);
        println!();

        for (name, inp, out, total, calls) in &self.models {
            if *calls > 0 {
                println!("  {} — {} calls, {} tokens (in: {}, out: {})", name, calls, total, inp, out);
            } else {
                println!("  {} — {} tokens (in: {}, out: {})", name, total, inp, out);
            }
        }

        if !self.processes.is_empty() {
            let mut sorted: Vec<_> = self.processes.iter().collect();
            sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
            let exec_count: usize = sorted.iter().map(|(_, c)| *c).sum();
            let top: Vec<String> = sorted.iter().take(8).map(|(n, c)| format!("{}({})", n, c)).collect();
            println!("\n{} processes spawned: {}", exec_count, top.join(", "));
        }

        if !self.tool_calls.is_empty() {
            let mut sorted: Vec<_> = self.tool_calls.iter().collect();
            sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
            let total: usize = sorted.iter().map(|(_, c)| *c).sum();
            let top: Vec<String> = sorted.iter().take(8).map(|(n, c)| format!("{}({})", n, c)).collect();
            println!("\n{} tool calls: {}", total, top.join(", "));
        }

        if !self.files.is_empty() {
            let display: Vec<&str> = self.files.iter().take(5).map(|s| s.as_str()).collect();
            let suffix = if self.files.len() > 5 { format!(", ... (+{} more)", self.files.len() - 5) } else { String::new() };
            println!("{} files accessed: {}{}", self.files.len(), display.join(", "), suffix);
        }

        if !self.endpoints.is_empty() {
            println!("Network: {}", self.endpoints.join(", "));
        }

        if let Some(ref path) = self.db_path {
            println!("\n  Source: {}", path);
        }
    }
}

pub(crate) fn run_db_summary(
    db: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if db.is_none() && let Some((source, file, data)) = read_latest_local_session() {
        SessionSummary::from_local_jsonl(&source, &file, &data).print();
        return Ok(());
    }
    let db = db.ok_or("No session data found. Run `agentsight exec` first, or pass --db.")?;
    SessionSummary::from_sqlite(db)?.print();
    Ok(())
}

pub(crate) fn run_local_audit(json: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (source, file, data) = read_latest_local_session()
        .ok_or("No session data found. Install Claude Code or Codex, or pass --db.")?;

    let tools = data.get("tools").and_then(|v| v.as_object());
    let models = data.get("models").and_then(|v| v.as_object());

    if json {
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    println!("Local {} session: {}", source, file);
    println!();

    if let Some(models) = models {
        for (name, usage) in models {
            if let Some(arr) = usage.as_array() {
                let (inp, out, total) = (
                    arr.first().and_then(|v| v.as_u64()).unwrap_or(0),
                    arr.get(1).and_then(|v| v.as_u64()).unwrap_or(0),
                    arr.get(2).and_then(|v| v.as_u64()).unwrap_or(0),
                );
                println!("  {} — {} tokens (in: {}, out: {})", name, total, inp, out);
            }
        }
        println!();
    }

    if let Some(tools) = tools {
        println!("Tool calls:");
        let mut sorted: Vec<_> = tools.iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1.as_u64()));
        for (name, count) in &sorted {
            println!("  {:<30} {}", name, count);
        }
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    if max <= 3 {
        return ".".repeat(max);
    }
    let mut out: String = s.chars().take(max - 3).collect();
    out.push_str("...");
    out
}

// ---------------------------------------------------------------------------
// Local agent session reader (reads ~/.claude and ~/.codex JSONL directly)
// ---------------------------------------------------------------------------

use std::collections::BTreeMap;

fn local_session_dirs() -> Vec<(&'static str, std::path::PathBuf)> {
    let home = dirs::home_dir().unwrap_or_default();
    [("claude", home.join(".claude/projects")), ("codex", home.join(".codex/sessions"))]
        .into_iter()
        .filter(|(_, d)| d.is_dir())
        .collect()
}

fn walk_jsonl(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, &std::fs::Metadata)) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_jsonl(&path, f);
        } else if path.extension().is_some_and(|e| e == "jsonl")
            && let Ok(meta) = path.metadata() {
            f(&path, &meta);
        }
    }
}

pub(crate) fn count_local_sessions() -> Vec<(&'static str, std::path::PathBuf, usize, u64)> {
    local_session_dirs().into_iter().filter_map(|(name, dir)| {
        let (mut count, mut bytes) = (0usize, 0u64);
        walk_jsonl(&dir, &mut |_, meta| { count += 1; bytes += meta.len(); });
        (count > 0).then_some((name, dir, count, bytes))
    }).collect()
}

fn read_latest_local_session() -> Option<(String, String, serde_json::Value)> {
    for (name, dir) in local_session_dirs() {
        let mut best: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
        walk_jsonl(&dir, &mut |path, meta| {
            let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            if best.as_ref().is_none_or(|(t, _)| mtime > *t) {
                best = Some((mtime, path.to_path_buf()));
            }
        });
        let path = best?.1;
        let content = std::fs::read_to_string(&path).ok()?;
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
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let typ = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match (source, typ) {
            ("claude", "result") => {
                duration_ms = json_u64(&obj, "duration_ms");
                num_turns = json_u64(&obj, "num_turns");
                cost_usd = obj.get("total_cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
                if let Some(mu) = obj.get("modelUsage").and_then(|v| v.as_object()) {
                    for (m, u) in mu {
                        let inp = json_u64(u, "inputTokens");
                        let out = json_u64(u, "outputTokens");
                        let total = inp + out + json_u64(u, "cacheReadInputTokens") + json_u64(u, "cacheCreationInputTokens");
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
                    let key = if codex_model.is_empty() { "unknown" } else { &codex_model };
                    models.insert(key.into(), (json_u64(u, "input_tokens"), json_u64(u, "output_tokens"), json_u64(u, "total_tokens")));
                }
            }
            ("codex", "response_item")
                if obj.pointer("/payload/type").and_then(|v| v.as_str()) == Some("function_call") => {
                let n = obj.pointer("/payload/name").and_then(|v| v.as_str()).unwrap_or("?");
                *tools.entry(n.into()).or_default() += 1;
            }
            _ => {}
        }
    }

    if models.is_empty() { return serde_json::Value::Null; }
    serde_json::json!({ "models": models, "tools": tools, "duration_ms": duration_ms, "num_turns": num_turns, "cost_usd": cost_usd })
}
