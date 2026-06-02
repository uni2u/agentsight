// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::framework::storage::{
    SnapshotOptions, SqliteStore,
    sqlite::{Snapshot, StorageResult},
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::time::Duration;

#[derive(Debug, Default, Serialize)]
struct ResourcePeaks {
    max_cpu_percent: f64,
    max_cpu_comm: Option<String>,
    max_cpu_pid: Option<u32>,
    max_rss_mb: u64,
    max_rss_comm: Option<String>,
    max_rss_pid: Option<u32>,
    samples: usize,
}

#[derive(Debug, Default, Serialize)]
struct ToolCounts {
    calls: i64,
    names: i64,
}

#[derive(Debug, Serialize)]
struct StatOutput {
    db: String,
    duration_s: f64,
    raw_events: i64,
    canonical_events: i64,
    llm_calls: i64,
    input_tokens: i64,
    output_tokens: i64,
    total_tokens: i64,
    process_execs: usize,
    process_exits: usize,
    process_exit_success: usize,
    process_exit_failure: usize,
    file_events: usize,
    unique_files: usize,
    network_hosts: usize,
    http_errors: usize,
    tool_calls: i64,
    tool_names: i64,
    resources: ResourcePeaks,
}

pub(crate) fn run_stat_query(
    db: &str,
    json: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stat = load_stat(db)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&stat)?);
    } else {
        print_stat(&stat);
    }
    Ok(())
}

pub(crate) fn run_top_query(
    db: &str,
    interval_secs: u64,
    limit: usize,
    count: Option<u32>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let limit = limit.clamp(1, 50);
    let interval = Duration::from_secs(interval_secs.max(1));
    let mut iterations = 0u32;
    let clear_screen = count != Some(1);

    loop {
        let (snapshot, resources) = load_snapshot_and_resources(db)?;
        if clear_screen {
            print!("\x1b[2J\x1b[H");
        }
        print_top(db, &snapshot, &resources, limit);
        io::stdout().flush()?;

        iterations += 1;
        if count.is_some_and(|max| iterations >= max) || crate::shutdown_requested() {
            break;
        }
        std::thread::sleep(interval);
    }

    Ok(())
}

fn load_stat(db: &str) -> StorageResult<StatOutput> {
    let (snapshot, resources) = load_snapshot_and_resources(db)?;
    let tool_counts = load_tool_counts(db)?;
    let duration_s = duration_s(&snapshot);

    let mut process_execs = 0usize;
    let mut process_exits = 0usize;
    let mut process_exit_success = 0usize;
    let mut process_exit_failure = 0usize;
    let mut file_events = 0usize;
    let mut files = BTreeSet::new();

    for row in &snapshot.audit_events {
        match row.audit_type.as_str() {
            "process" if row.action.as_deref() == Some("exec") => process_execs += 1,
            "process" if row.action.as_deref() == Some("exit") => {
                process_exits += 1;
                match row.status.as_deref() {
                    Some("success") => process_exit_success += 1,
                    Some("failure") => process_exit_failure += 1,
                    _ => {}
                }
            }
            "file" => {
                file_events += 1;
                if let Some(target) = &row.target {
                    files.insert(target.clone());
                }
            }
            _ => {}
        }
    }

    let network_hosts = snapshot
        .events
        .iter()
        .filter_map(|event| event.host.clone())
        .collect::<BTreeSet<_>>()
        .len();
    let http_errors = snapshot
        .events
        .iter()
        .filter(|event| {
            event.kind == "llm.error" || event.status_code.map(|code| code >= 400).unwrap_or(false)
        })
        .count();

    Ok(StatOutput {
        db: db.to_string(),
        duration_s,
        raw_events: snapshot.summary.raw_events,
        canonical_events: snapshot.summary.canonical_events,
        llm_calls: snapshot.summary.llm_calls,
        input_tokens: snapshot.summary.input_tokens,
        output_tokens: snapshot.summary.output_tokens,
        total_tokens: snapshot.summary.total_tokens,
        process_execs,
        process_exits,
        process_exit_success,
        process_exit_failure,
        file_events,
        unique_files: files.len(),
        network_hosts,
        http_errors,
        tool_calls: tool_counts.calls,
        tool_names: tool_counts.names,
        resources,
    })
}

fn print_stat(stat: &StatOutput) {
    println!("AgentSight stat");
    println!("  db:                  {}", stat.db);
    println!("  elapsed time:        {:.3} s", stat.duration_s);
    println!("  raw events:          {}", stat.raw_events);
    println!("  canonical events:    {}", stat.canonical_events);
    println!("  LLM calls:           {}", stat.llm_calls);
    println!(
        "  tokens:              {} total (in: {}, out: {})",
        stat.total_tokens, stat.input_tokens, stat.output_tokens
    );
    println!("  tool calls:          {}", stat.tool_calls);
    println!("  process execs:       {}", stat.process_execs);
    println!(
        "  process exits:       {} (success: {}, failure: {})",
        stat.process_exits, stat.process_exit_success, stat.process_exit_failure
    );
    println!(
        "  file events:         {} (unique files: {})",
        stat.file_events, stat.unique_files
    );
    println!("  network hosts:       {}", stat.network_hosts);
    println!("  HTTP/LLM errors:     {}", stat.http_errors);
    if stat.resources.samples > 0 {
        println!(
            "  max CPU:             {:.2}%{}",
            stat.resources.max_cpu_percent,
            subject_suffix(
                stat.resources.max_cpu_comm.as_deref(),
                stat.resources.max_cpu_pid
            )
        );
        println!(
            "  max RSS:             {} MB{}",
            stat.resources.max_rss_mb,
            subject_suffix(
                stat.resources.max_rss_comm.as_deref(),
                stat.resources.max_rss_pid
            )
        );
    }
}

fn print_top(db: &str, snapshot: &Snapshot, resources: &ResourcePeaks, limit: usize) {
    let generated_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    println!(
        "AgentSight top · {} · {} · {:.0}s · {} events · {} LLM calls · {} tokens",
        generated_at,
        db,
        duration_s(snapshot),
        snapshot.summary.canonical_events,
        snapshot.summary.llm_calls,
        snapshot.summary.total_tokens
    );
    println!();

    print_ranked("Processes", top_processes(snapshot, limit), "execs");
    print_ranked("Files", top_files(snapshot, limit), "events");
    print_ranked("Network", top_hosts(snapshot, limit), "events");
    print_ranked("Models", top_models(snapshot, limit), "tokens");

    if resources.samples > 0 {
        println!("Resources");
        println!(
            "  max CPU {:>8.2}%{}",
            resources.max_cpu_percent,
            subject_suffix(resources.max_cpu_comm.as_deref(), resources.max_cpu_pid)
        );
        println!(
            "  max RSS {:>8} MB{}",
            resources.max_rss_mb,
            subject_suffix(resources.max_rss_comm.as_deref(), resources.max_rss_pid)
        );
        println!();
    }

    let failures = recent_failures(snapshot, 5);
    if !failures.is_empty() {
        println!("Recent Failures");
        for failure in failures {
            println!("  {}", failure);
        }
        println!();
    }
}

fn print_ranked(title: &str, rows: Vec<(String, i64)>, unit: &str) {
    if rows.is_empty() {
        return;
    }
    println!("{}", title);
    for (name, value) in rows {
        println!("  {:>8} {:<8} {}", value, unit, truncate(&name, 96));
    }
    println!();
}

fn load_snapshot_and_resources(db: &str) -> StorageResult<(Snapshot, ResourcePeaks)> {
    let mut store = SqliteStore::open(db)?;
    let snapshot = store.export_snapshot(SnapshotOptions {
        event_limit: 50_000,
        audit_limit: 50_000,
    })?;
    let resources = load_resource_peaks(&mut store)?;
    Ok((snapshot, resources))
}

fn load_tool_counts(db: &str) -> StorageResult<ToolCounts> {
    let mut store = SqliteStore::open(db)?;
    let (calls, names): (i64, i64) = store.connection_mut().query_row(
        "SELECT COUNT(*), COUNT(DISTINCT COALESCE(tool_name, '?')) FROM tool_calls",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(ToolCounts { calls, names })
}

fn load_resource_peaks(store: &mut SqliteStore) -> StorageResult<ResourcePeaks> {
    let mut peaks = ResourcePeaks::default();
    let mut stmt = store
        .connection_mut()
        .prepare("SELECT raw_json FROM raw_events WHERE source = 'system'")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    for row in rows {
        let raw_json = row?;
        let Ok(raw) = serde_json::from_str::<Value>(&raw_json) else {
            continue;
        };
        let data = raw.get("data").unwrap_or(&raw);
        let comm = raw
            .get("comm")
            .and_then(|v| v.as_str())
            .or_else(|| data.get("comm").and_then(|v| v.as_str()))
            .map(str::to_string);
        let pid = raw
            .get("pid")
            .and_then(|v| v.as_u64())
            .or_else(|| data.get("pid").and_then(|v| v.as_u64()))
            .map(|v| v as u32);

        if let Some(cpu) = number_or_string(data.get("cpu").and_then(|v| v.get("percent"))) {
            if cpu >= peaks.max_cpu_percent {
                peaks.max_cpu_percent = cpu;
                peaks.max_cpu_comm = comm.clone();
                peaks.max_cpu_pid = pid;
            }
        }
        if let Some(rss_mb) = number_or_string(data.get("memory").and_then(|v| v.get("rss_mb"))) {
            let rss_mb = rss_mb.max(0.0) as u64;
            if rss_mb >= peaks.max_rss_mb {
                peaks.max_rss_mb = rss_mb;
                peaks.max_rss_comm = comm;
                peaks.max_rss_pid = pid;
            }
        }
        peaks.samples += 1;
    }

    Ok(peaks)
}

fn top_processes(snapshot: &Snapshot, limit: usize) -> Vec<(String, i64)> {
    let mut counts = BTreeMap::new();
    for row in &snapshot.audit_events {
        if row.audit_type == "process" && row.action.as_deref() == Some("exec") {
            let key = row
                .comm
                .clone()
                .or_else(|| row.target.clone())
                .unwrap_or_else(|| "unknown".to_string());
            *counts.entry(key).or_insert(0) += 1;
        }
    }
    sorted_counts(counts, limit)
}

fn top_files(snapshot: &Snapshot, limit: usize) -> Vec<(String, i64)> {
    let mut counts = BTreeMap::new();
    for row in &snapshot.audit_events {
        if row.audit_type == "file"
            && let Some(target) = &row.target
        {
            *counts.entry(target.clone()).or_insert(0) += 1;
        }
    }
    sorted_counts(counts, limit)
}

fn top_hosts(snapshot: &Snapshot, limit: usize) -> Vec<(String, i64)> {
    let mut counts = BTreeMap::new();
    for event in &snapshot.events {
        if let Some(host) = &event.host {
            *counts.entry(host.clone()).or_insert(0) += 1;
        }
    }
    sorted_counts(counts, limit)
}

fn top_models(snapshot: &Snapshot, limit: usize) -> Vec<(String, i64)> {
    let counts = snapshot
        .token_summary
        .iter()
        .map(|row| (row.group.clone(), row.total_tokens))
        .collect();
    sorted_counts(counts, limit)
}

fn recent_failures(snapshot: &Snapshot, limit: usize) -> Vec<String> {
    snapshot
        .audit_events
        .iter()
        .rev()
        .filter(|row| row.status.as_deref() == Some("failure"))
        .take(limit)
        .map(|row| {
            row.summary
                .clone()
                .or_else(|| row.target.clone())
                .unwrap_or_else(|| "failure".to_string())
        })
        .collect()
}

fn sorted_counts(counts: BTreeMap<String, i64>, limit: usize) -> Vec<(String, i64)> {
    let mut rows: Vec<_> = counts.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(limit);
    rows
}

fn duration_s(snapshot: &Snapshot) -> f64 {
    match (
        snapshot.summary.start_timestamp_ms,
        snapshot.summary.end_timestamp_ms,
    ) {
        (Some(start), Some(end)) if end > start => (end - start) as f64 / 1000.0,
        _ => 0.0,
    }
}

fn number_or_string(value: Option<&Value>) -> Option<f64> {
    value.and_then(|v| {
        v.as_f64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
    })
}

fn subject_suffix(comm: Option<&str>, pid: Option<u32>) -> String {
    match (comm, pid) {
        (Some(comm), Some(pid)) if !comm.is_empty() => format!(" ({}, pid {})", comm, pid),
        (Some(comm), _) if !comm.is_empty() => format!(" ({})", comm),
        (_, Some(pid)) => format!(" (pid {})", pid),
        _ => String::new(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}
