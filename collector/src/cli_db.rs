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
use crate::local_sessions::{self, LocalSession};
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
        let local_sessions = local_sessions::from_snapshot(&snap);
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
        if !local_sessions.is_empty() {
            prompt_chars = local_prompt_chars(&local_sessions).unwrap_or(prompt_chars);
        }
        let local_model_rows = local_models(&local_sessions);
        let models = if local_sessions.iter().any(LocalSession::has_tokens) {
            local_model_rows
        } else {
            db_models(&snap)
        };
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
        let mut tool_calls = local_tools(&local_sessions);
        let mut tool_duration_ms = SummaryStats::default();
        if tool_calls.is_empty() {
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

    pub fn from_local_session(session: &LocalSession) -> Self {
        let prompt_chars = session
            .prompt_preview
            .as_ref()
            .map(|prompt| {
                let mut stats = SummaryStats::default();
                stats.add(prompt.chars().count() as u64);
                stats
            })
            .unwrap_or_default();
        Self {
            source: session.agent.clone(),
            duration_s: session.duration_ms as f64 / 1000.0,
            first_llm_after_ms: None,
            first_tool_after_ms: None,
            prompt_chars,
            llm_latency_ms: SummaryStats::default(),
            models: local_models(std::slice::from_ref(session)),
            processes: BTreeMap::new(),
            process_exits: BTreeMap::new(),
            tool_calls: session.tools.clone(),
            tool_duration_ms: SummaryStats::default(),
            files: vec![],
            file_access: FileAccessSummary::default(),
            network_events: 0,
            endpoints: vec![],
        }
    }
}

fn local_models(sessions: &[LocalSession]) -> Vec<(String, i64, i64, i64, i64)> {
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

fn local_tools(sessions: &[LocalSession]) -> BTreeMap<String, usize> {
    let mut tools = BTreeMap::new();
    for session in sessions {
        for (tool, count) in &session.tools {
            *tools.entry(tool.clone()).or_default() += count;
        }
    }
    tools
}

fn local_prompt_chars(sessions: &[LocalSession]) -> Option<SummaryStats> {
    let mut stats = SummaryStats::default();
    for prompt in sessions
        .iter()
        .filter_map(|session| session.prompt_preview.as_ref())
    {
        stats.add(prompt.chars().count() as u64);
    }
    (stats.count > 0).then_some(stats)
}

fn db_models(
    snap: &crate::framework::storage::sqlite::Snapshot,
) -> Vec<(String, i64, i64, i64, i64)> {
    let mut models = snap
        .token_summary
        .iter()
        .filter(|row| row.input_tokens != 0 || row.output_tokens != 0 || row.total_tokens != 0)
        .map(|row| {
            (
                row.group.clone(),
                (
                    row.input_tokens,
                    row.output_tokens,
                    row.total_tokens,
                    row.calls,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for session in &snap.sessions {
        if session.input_tokens == 0 && session.output_tokens == 0 && session.total_tokens == 0 {
            continue;
        }
        let model = session
            .model
            .as_ref()
            .filter(|model| !model.is_empty())
            .cloned()
            .unwrap_or_else(|| session.agent_type.clone());
        models.entry(model).or_insert((
            session.input_tokens,
            session.output_tokens,
            session.total_tokens,
            1,
        ));
    }

    models
        .into_iter()
        .map(|(model, (input, output, total, calls))| (model, input, output, total, calls))
        .collect()
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
        && let Some(session) = local_sessions::latest()
    {
        print_session_summary(&SessionSummary::from_local_session(&session));
        return Ok(());
    }
    let db = db.ok_or("No session data found. Run `agentsight record` first, or pass --db.")?;
    print_session_summary(&SessionSummary::from_sqlite(db)?);
    Ok(())
}

pub(crate) fn run_local_audit(json: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let session = local_sessions::latest()
        .ok_or("No session data found. Install Claude Code or Codex, or pass --db.")?;
    let data = session.to_json();

    if json {
        print_json(&data)?;
        return Ok(());
    }

    print_local_audit(&session.agent, &session.path.display().to_string(), &data);

    Ok(())
}

pub(crate) fn count_local_sessions() -> Vec<(&'static str, std::path::PathBuf, usize, u64)> {
    local_sessions::count_local_sessions()
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

    #[test]
    fn sqlite_summary_uses_agent_session_tokens_when_token_usage_is_empty() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("session-tokens.db");
        let mut store = SqliteStore::open(&db).unwrap();

        store
            .connection_mut()
            .execute(
                "INSERT INTO agent_sessions (
                    id, agent_type, agent_name, start_timestamp_ms, end_timestamp_ms,
                    status, model, input_tokens, output_tokens, total_tokens,
                    adapter_id, confidence, attributes_json
                 ) VALUES (
                    'session-1', 'claude-code', 'claude', 1000, 2000,
                    'completed', 'claude-opus-4-6', 3, 10, 27667,
                    'claude-code', 0.9, '{}'
                 )",
                [],
            )
            .unwrap();

        let summary = SessionSummary::from_sqlite(db.to_str().unwrap()).unwrap();
        assert_eq!(
            summary.models,
            vec![("claude-opus-4-6".to_string(), 3, 10, 27667, 1)]
        );
    }

    #[test]
    fn sqlite_summary_reads_touched_local_claude_log_without_projection() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("local-log.db");
        let session_dir = temp.path().join(".claude/projects/test");
        std::fs::create_dir_all(&session_dir).unwrap();
        let session_path = session_dir.join("session-1.jsonl");
        std::fs::write(
            &session_path,
            concat!(
                "{\"type\":\"assistant\",\"requestId\":\"req_1\",\"message\":{\"model\":\"claude-opus-4-6\",\"content\":[{\"type\":\"tool_use\",\"name\":\"Bash\"}],\"usage\":{\"input_tokens\":3,\"cache_creation_input_tokens\":5,\"cache_read_input_tokens\":7,\"output_tokens\":11}}}\n",
                "{\"type\":\"result\",\"duration_ms\":1200,\"usage\":{\"input_tokens\":3,\"cache_creation_input_tokens\":5,\"cache_read_input_tokens\":7,\"output_tokens\":11},\"modelUsage\":{\"claude-opus-4-6\":{\"inputTokens\":3,\"outputTokens\":11,\"cacheCreationInputTokens\":5,\"cacheReadInputTokens\":7}}}\n",
            ),
        )
        .unwrap();

        let mut store = SqliteStore::open(&db).unwrap();
        let session_path_string = session_path.to_string_lossy().to_string();
        store
            .connection_mut()
            .execute(
                "INSERT INTO audit_events (
                    id, timestamp_ms, audit_type, pid, comm, action, target, status, details_json
                 ) VALUES ('audit-1', 1000, 'file', 42, 'claude', 'write', ?1, 'observed', '{}')",
                [session_path_string.as_str()],
            )
            .unwrap();

        let summary = SessionSummary::from_sqlite(db.to_str().unwrap()).unwrap();
        assert_eq!(
            summary.models,
            vec![("claude-opus-4-6".to_string(), 3, 11, 26, 1)]
        );
        assert_eq!(summary.tool_calls.get("Bash"), Some(&1));

        let token_rows: i64 = store
            .connection_mut()
            .query_row("SELECT COUNT(*) FROM token_usage", [], |row| row.get(0))
            .unwrap();
        assert_eq!(token_rows, 0);
        let session_rows: i64 = store
            .connection_mut()
            .query_row("SELECT COUNT(*) FROM agent_sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(session_rows, 0);
    }

    #[test]
    fn sqlite_summary_uses_db_tokens_when_touched_local_log_has_no_usage() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("local-log-no-usage.db");
        let session_dir = temp.path().join(".claude/projects/test");
        std::fs::create_dir_all(&session_dir).unwrap();
        let session_path = session_dir.join("session-1.jsonl");
        std::fs::write(
            &session_path,
            "{\"type\":\"user\",\"message\":{\"content\":\"local prompt only\"}}\n",
        )
        .unwrap();

        let mut store = SqliteStore::open(&db).unwrap();
        let session_path_string = session_path.to_string_lossy().to_string();
        store
            .connection_mut()
            .execute(
                "INSERT INTO audit_events (
                    id, timestamp_ms, audit_type, pid, comm, action, target, status, details_json
                 ) VALUES ('audit-1', 1000, 'file', 42, 'claude', 'write', ?1, 'observed', '{}')",
                [session_path_string.as_str()],
            )
            .unwrap();
        store
            .connection_mut()
            .execute(
                "INSERT INTO token_usage (
                    id, timestamp_ms, model, input_tokens, output_tokens, total_tokens, source
                 ) VALUES ('token-1', 1200, 'ssl-model', 8, 5, 13, 'response_usage')",
                [],
            )
            .unwrap();

        let summary = SessionSummary::from_sqlite(db.to_str().unwrap()).unwrap();
        assert_eq!(summary.models, vec![("ssl-model".to_string(), 8, 5, 13, 1)]);
        assert_eq!(summary.prompt_chars.total, 17);
    }

    #[test]
    fn local_claude_summary_reads_active_message_usage() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(".claude/projects/test/session.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let session = local_sessions::parse_content(
            "claude",
            &path,
            std::time::UNIX_EPOCH,
            concat!(
                "{\"type\":\"assistant\",\"requestId\":\"req_1\",\"message\":{\"model\":\"claude-opus-4-6\",\"content\":[{\"type\":\"tool_use\",\"name\":\"Bash\"}],\"usage\":{\"input_tokens\":3,\"cache_creation_input_tokens\":5,\"cache_read_input_tokens\":7,\"output_tokens\":11}}}\n",
                "{\"type\":\"assistant\",\"requestId\":\"req_1\",\"message\":{\"model\":\"claude-opus-4-6\",\"content\":[{\"type\":\"text\",\"text\":\"done\"}],\"usage\":{\"input_tokens\":3,\"cache_creation_input_tokens\":5,\"cache_read_input_tokens\":7,\"output_tokens\":11}}}\n",
            ),
        )
        .unwrap();
        assert_eq!(session.models["claude-opus-4-6"], (3, 11, 26));
        assert_eq!(session.tools.get("Bash"), Some(&1));
    }
}
