// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

use crate::framework::adapters::sql_adapter::SqlAdapter;
use crate::framework::storage::sqlite::{AuditRow, LlmCallRow, TokenSummary};

#[derive(Debug, Default, Serialize)]
pub(crate) struct ResourcePeaks {
    pub(crate) max_cpu_percent: f64,
    pub(crate) max_rss_mb: u64,
    pub(crate) samples: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct StatOutput {
    pub(crate) db: String,
    pub(crate) duration_s: f64,
    pub(crate) raw_events: i64,
    pub(crate) canonical_events: i64,
    pub(crate) llm_calls: i64,
    pub(crate) input_tokens: i64,
    pub(crate) output_tokens: i64,
    pub(crate) total_tokens: i64,
    pub(crate) process_execs: usize,
    pub(crate) process_exits: usize,
    pub(crate) process_exit_success: usize,
    pub(crate) process_exit_failure: usize,
    pub(crate) file_events: usize,
    pub(crate) unique_files: usize,
    pub(crate) network_hosts: usize,
    pub(crate) http_errors: usize,
    pub(crate) tool_calls: i64,
    pub(crate) resources: ResourcePeaks,
}

pub(crate) type TopSection = (&'static str, &'static str, Vec<(String, i64)>);

#[derive(Debug, Clone)]
pub(crate) struct AgentTopRow {
    pub(crate) agent: String,
    pub(crate) pid: Option<u32>,
    pub(crate) cpu_percent: f64,
    pub(crate) rss_mb: u64,
    pub(crate) processes: usize,
    pub(crate) tokens: Option<i64>,
    pub(crate) execs: usize,
    pub(crate) failures: usize,
    pub(crate) files: usize,
    pub(crate) network: usize,
    pub(crate) unattributed: usize,
    pub(crate) trace: String,
    pub(crate) command: String,
}

pub(crate) struct AgentTopOutput<'a> {
    pub(crate) mode: &'a str,
    pub(crate) db: Option<&'a str>,
    pub(crate) duration_s: f64,
    pub(crate) canonical_events: i64,
    pub(crate) llm_calls: i64,
    pub(crate) total_tokens: i64,
    pub(crate) rows: Vec<AgentTopRow>,
    pub(crate) sections: Vec<TopSection>,
    pub(crate) failures: Vec<String>,
    pub(crate) notes: Vec<String>,
}

pub(crate) struct SessionSummary {
    pub(crate) source: String,
    pub(crate) duration_s: f64,
    pub(crate) models: Vec<(String, i64, i64, i64, i64)>,
    pub(crate) processes: BTreeMap<String, usize>,
    pub(crate) process_exits: BTreeMap<String, usize>,
    pub(crate) tool_calls: BTreeMap<String, usize>,
    pub(crate) files: Vec<String>,
    pub(crate) endpoints: Vec<String>,
}

pub(crate) fn print_json<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub(crate) fn clear_screen() {
    print!("\x1b[2J\x1b[H");
}

pub(crate) fn print_replay(db: &str, inserted: usize, adapter: Option<&str>) {
    match adapter {
        Some(adapter) => {
            println!("Replayed {inserted} events into {db} and ran adapter '{adapter}'")
        }
        None => println!("Replayed {inserted} events into {db} without SQL adapters"),
    }
}

pub(crate) fn print_exported_snapshot(output: &str) {
    println!("Exported snapshot to {output}");
}

pub(crate) fn print_capture_adapters(db_path: &str, adapter: &str) {
    println!("✓ SQL adapters projected: {adapter} ({db_path})");
}

pub(crate) fn print_adapter_run(db: &str, adapter: &str) {
    println!("Ran SQL adapter '{adapter}' on {db}");
}

pub(crate) fn print_adapters(adapters: &[SqlAdapter]) {
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

pub(crate) fn print_token_summary(group_by: &str, rows: &[TokenSummary]) {
    println!("Token usage grouped by {group_by}");
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

pub(crate) fn print_audit_rows(rows: &[AuditRow]) {
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

pub(crate) fn print_llm_prompts(rows: &[LlmCallRow]) {
    println!("LLM prompts");
    println!(
        "{:<15} {:<16} {:<28} {:>8} prompt",
        "timestamp_ms", "comm", "model", "tokens"
    );
    for row in rows {
        println!(
            "{:<15} {:<16} {:<28} {:>8} {}",
            row.start_timestamp_ms,
            truncate(row.comm.as_deref().unwrap_or("-"), 16),
            truncate(row.model.as_deref().unwrap_or("-"), 28),
            row.total_tokens,
            prompt_preview(&row.request, 96)
        );
    }
}

pub(crate) fn print_stat(stat: &StatOutput) {
    println!("AgentSight stat");
    field("db", &stat.db);
    field("elapsed time", format!("{:.3} s", stat.duration_s));
    field("raw events", stat.raw_events);
    field("canonical events", stat.canonical_events);
    field("LLM calls", stat.llm_calls);
    field(
        "tokens",
        format!(
            "{} total (in: {}, out: {})",
            stat.total_tokens, stat.input_tokens, stat.output_tokens
        ),
    );
    field("tool calls", stat.tool_calls);
    field("process execs", stat.process_execs);
    field(
        "process exits",
        format!(
            "{} (success: {}, failure: {})",
            stat.process_exits, stat.process_exit_success, stat.process_exit_failure
        ),
    );
    field(
        "file events",
        format!("{} (unique files: {})", stat.file_events, stat.unique_files),
    );
    field("network hosts", stat.network_hosts);
    field("HTTP/LLM errors", stat.http_errors);
    if stat.resources.samples > 0 {
        field("max CPU", format!("{:.2}%", stat.resources.max_cpu_percent));
        field("max RSS", format!("{} MB", stat.resources.max_rss_mb));
    }
}

pub(crate) fn print_agent_top(top: &AgentTopOutput<'_>) {
    let generated_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let db = top.db.map(|db| format!(" · {db}")).unwrap_or_default();
    println!(
        "AgentSight top - {} agents   {}   {}{db}   {:.0}s   events: {}   LLM: {}   tokens: {}",
        top.rows.len(),
        top.mode,
        generated_at,
        top.duration_s,
        top.canonical_events,
        top.llm_calls,
        format_count(top.total_tokens)
    );
    println!();
    println!(
        "{:<14} {:>7} {:>6} {:>7} {:>5} {:>8} {:>6} {:>5} {:>5} {:>4} {:>6} {:<10} COMMAND",
        "AGENT",
        "PID",
        "CPU%",
        "RSS",
        "PROCS",
        "TOKENS",
        "EXECS",
        "FAIL",
        "FILES",
        "NET",
        "UNATTR",
        "TRACE"
    );
    for row in &top.rows {
        println!(
            "{:<14} {:>7} {:>6.1} {:>7} {:>5} {:>8} {:>6} {:>5} {:>5} {:>4} {:>6} {:<10} {}",
            truncate(&row.agent, 14),
            row.pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_string()),
            row.cpu_percent,
            format_mb(row.rss_mb),
            row.processes,
            row.tokens
                .map(format_count)
                .unwrap_or_else(|| "-".to_string()),
            row.execs,
            row.failures,
            row.files,
            row.network,
            row.unattributed,
            truncate(&row.trace, 10),
            truncate(&row.command, 80),
        );
    }
    if top.rows.is_empty() {
        println!(
            "{:<14} {:>7} {:>6} {:>7} {:>5} {:>8} {:>6} {:>5} {:>5} {:>4} {:>6} {:<10} -",
            "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-"
        );
    }
    println!();

    for note in &top.notes {
        println!("note: {note}");
    }
    if !top.notes.is_empty() {
        println!();
    }

    if !top.sections.is_empty() {
        println!("Hot activity");
        for section in &top.sections {
            print_ranked(section);
        }
    }
    if !top.failures.is_empty() {
        println!("Recent Failures");
        for failure in &top.failures {
            println!("  {failure}");
        }
        println!();
    }
}

pub(crate) fn print_session_summary(summary: &SessionSummary) {
    let total_tokens: i64 = summary.models.iter().map(|m| m.3).sum();
    let total_calls: i64 = summary.models.iter().map(|m| m.4).sum();
    let has_tokens = summary
        .models
        .iter()
        .any(|(_, input, output, total, _)| *input > 0 || *output > 0 || *total > 0);

    print!("{} session", summary.source);
    if summary.duration_s > 0.0 {
        print!(" · {:.0}s", summary.duration_s);
    }
    if total_calls > 0 {
        print!(" · {total_calls} API calls");
    }
    if has_tokens {
        print!(" · {total_tokens} tokens");
    }
    println!("\n");

    for (name, inp, out, total, calls) in &summary.models {
        if *inp == 0 && *out == 0 && *total == 0 {
            continue;
        }
        if *calls > 0 {
            println!("  {name} — {calls} calls, {total} tokens (in: {inp}, out: {out})");
        } else {
            println!("  {name} — {total} tokens (in: {inp}, out: {out})");
        }
    }

    print_count_map("processes spawned", &summary.processes);
    print_process_exits(&summary.process_exits);
    print_count_map("tool calls", &summary.tool_calls);

    if !summary.files.is_empty() {
        let display: Vec<&str> = summary.files.iter().take(5).map(String::as_str).collect();
        let suffix = if summary.files.len() > 5 {
            format!(", ... (+{} more)", summary.files.len() - 5)
        } else {
            String::new()
        };
        println!(
            "{} files accessed: {}{}",
            summary.files.len(),
            display.join(", "),
            suffix
        );
    }
    if !summary.endpoints.is_empty() {
        println!("Network: {}", summary.endpoints.join(", "));
    }
}

pub(crate) fn print_local_audit(source: &str, file: &str, data: &Value) {
    println!("Local {source} session: {file}\n");

    if let Some(models) = data.get("models").and_then(|v| v.as_object()) {
        for (name, usage) in models {
            if let Some(arr) = usage.as_array() {
                let get = |i: usize| arr.get(i).and_then(|v| v.as_u64()).unwrap_or(0);
                println!(
                    "  {name} — {} tokens (in: {}, out: {})",
                    get(2),
                    get(0),
                    get(1)
                );
            }
        }
        println!();
    }

    if let Some(tools) = data.get("tools").and_then(|v| v.as_object()) {
        println!("Tool calls:");
        let mut sorted: Vec<_> = tools.iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1.as_u64()));
        for (name, count) in &sorted {
            println!("  {name:<30} {count}");
        }
    }
}

pub(crate) fn print_session_list(dir: &Path, entries: &[std::fs::DirEntry]) {
    if entries.is_empty() {
        println!("No session databases found in {}", dir.display());
        return;
    }
    println!("Session databases in {}:", dir.display());
    for entry in entries {
        let modified = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| {
                chrono::DateTime::<chrono::Local>::from(t)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
            })
            .unwrap_or_default();
        let size = entry.metadata().ok().map(|m| m.len()).unwrap_or(0);
        println!(
            "  {} ({} KB, {})",
            entry.path().display(),
            size / 1024,
            modified
        );
    }
}

pub(crate) fn print_discovery(
    rows: &[crate::cli_discover::DiscoveryRow],
    local: &[(&'static str, std::path::PathBuf, usize, u64)],
) {
    println!(
        "{:<14} {:<10} {:<10} {:<9} recommended",
        "id", "adapter", "command", "available"
    );
    for row in rows {
        println!(
            "{:<14} {:<10} {:<10} {:<9} {}",
            row.id,
            row.adapter,
            row.command,
            if row.available { "yes" } else { "no" },
            row.recommended_capture
        );
    }

    if !local.is_empty() {
        println!("\nLocal session data:");
        for (name, dir, count, bytes) in local {
            println!(
                "  {name:<10} {count} sessions, {:.0} MB  ({})",
                *bytes as f64 / 1_048_576.0,
                dir.display()
            );
        }
        println!("\n  Run `agentsight report` or `agentsight stat` to analyze the latest session.");
    }
}

fn field(label: &str, value: impl std::fmt::Display) {
    println!("  {:<20}{value}", format!("{label}:"));
}

fn print_count_map(label: &str, counts: &BTreeMap<String, usize>) {
    if counts.is_empty() {
        return;
    }
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
    let total: usize = sorted.iter().map(|(_, c)| *c).sum();
    let top = sorted
        .iter()
        .take(8)
        .map(|(name, count)| format!("{name}({count})"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("\n{total} {label}: {top}");
}

fn print_process_exits(counts: &BTreeMap<String, usize>) {
    if counts.is_empty() {
        return;
    }
    let ordered = ["failure", "success", "observed"];
    let mut parts = ordered
        .iter()
        .filter_map(|status| {
            counts
                .get(*status)
                .map(|count| format!("{status}({count})"))
        })
        .collect::<Vec<_>>();
    parts.extend(
        counts
            .iter()
            .filter(|(status, _)| !ordered.contains(&status.as_str()))
            .map(|(status, count)| format!("{status}({count})")),
    );
    println!(
        "{} process exits: {}",
        counts.values().sum::<usize>(),
        parts.join(", ")
    );
}

fn print_ranked((title, unit, rows): &TopSection) {
    if rows.is_empty() {
        return;
    }
    println!("{title}");
    for (name, value) in rows {
        println!("  {value:>8} {unit:<8} {}", truncate(name, 96));
    }
    println!();
}

fn format_count(value: i64) -> String {
    let abs = value.abs();
    if abs >= 1_000_000 {
        format!("{:.1}M", value as f64 / 1_000_000.0)
    } else if abs >= 1_000 {
        format!("{:.1}k", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
}

fn format_mb(value: u64) -> String {
    if value >= 1024 {
        format!("{:.1}G", value as f64 / 1024.0)
    } else {
        format!("{value}M")
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!(
            "{}...",
            s.chars().take(max.saturating_sub(3)).collect::<String>()
        )
    }
}

fn prompt_preview(value: &Value, max: usize) -> String {
    let text = extract_prompt_text(value).unwrap_or_else(|| value.to_string());
    truncate(&text.split_whitespace().collect::<Vec<_>>().join(" "), max)
}

fn extract_prompt_text(value: &Value) -> Option<String> {
    if let Some(prompt) = value.get("prompt").and_then(|v| v.as_str()) {
        return Some(prompt.to_string());
    }
    let mut parts = Vec::new();
    for key in ["messages", "contents"] {
        if let Some(items) = value.get(key).and_then(|v| v.as_array()) {
            for item in items {
                collect_content_text(item.get("content").unwrap_or(item), &mut parts);
            }
        }
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

fn collect_content_text(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items
            .iter()
            .for_each(|item| collect_content_text(item, out)),
        Value::Object(obj) => {
            for key in ["text", "content", "parts"] {
                if let Some(v) = obj.get(key) {
                    collect_content_text(v, out);
                }
            }
        }
        _ => {}
    }
}
