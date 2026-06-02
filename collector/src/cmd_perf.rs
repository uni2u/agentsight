// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::cli_output::{
    ResourcePeaks, StatOutput, TopSection, clear_screen, print_json, print_stat, print_top,
};
use crate::framework::storage::{
    SnapshotOptions, SqliteStore,
    sqlite::{Snapshot, StorageResult},
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::time::Duration;

pub(crate) fn run_stat_query(
    db: &str,
    json: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stat = load_stat(db)?;
    if json {
        print_json(&stat)?;
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
    let should_clear_screen = count != Some(1);

    loop {
        let (snapshot, resources) = load_snapshot_and_resources(db)?;
        if should_clear_screen {
            clear_screen();
        }
        print_top(
            db,
            duration_s(&snapshot),
            snapshot.summary.canonical_events,
            snapshot.summary.llm_calls,
            snapshot.summary.total_tokens,
            &resources,
            &top_sections(&snapshot, limit),
            &recent_failures(&snapshot, 5),
        );
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
    let tool_calls = load_tool_calls(db)?;

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
        duration_s: duration_s(&snapshot),
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
        tool_calls,
        resources,
    })
}

fn top_sections(snapshot: &Snapshot, limit: usize) -> [TopSection; 4] {
    let audit = &snapshot.audit_events;
    [
        (
            "Processes",
            "execs",
            top_counts(
                audit
                    .iter()
                    .filter(|row| {
                        row.audit_type == "process" && row.action.as_deref() == Some("exec")
                    })
                    .map(|row| {
                        row.comm
                            .clone()
                            .or_else(|| row.target.clone())
                            .unwrap_or_else(|| "unknown".to_string())
                    }),
                limit,
            ),
        ),
        (
            "Files",
            "events",
            top_counts(
                audit
                    .iter()
                    .filter(|row| row.audit_type == "file")
                    .filter_map(|row| row.target.clone()),
                limit,
            ),
        ),
        (
            "Network",
            "events",
            top_counts(
                snapshot
                    .events
                    .iter()
                    .filter_map(|event| event.host.clone()),
                limit,
            ),
        ),
        (
            "Models",
            "tokens",
            sorted_counts(
                snapshot
                    .token_summary
                    .iter()
                    .map(|row| (row.group.clone(), row.total_tokens))
                    .collect(),
                limit,
            ),
        ),
    ]
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

fn load_tool_calls(db: &str) -> StorageResult<i64> {
    let mut store = SqliteStore::open(db)?;
    Ok(store
        .connection_mut()
        .query_row("SELECT COUNT(*) FROM tool_calls", [], |row| row.get(0))?)
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

        if let Some(cpu) = number_or_string(data.get("cpu").and_then(|v| v.get("percent")))
            && cpu >= peaks.max_cpu_percent
        {
            peaks.max_cpu_percent = cpu;
        }
        if let Some(rss_mb) = number_or_string(data.get("memory").and_then(|v| v.get("rss_mb"))) {
            let rss_mb = rss_mb.max(0.0) as u64;
            if rss_mb >= peaks.max_rss_mb {
                peaks.max_rss_mb = rss_mb;
            }
        }
        peaks.samples += 1;
    }

    Ok(peaks)
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

fn top_counts(rows: impl Iterator<Item = String>, limit: usize) -> Vec<(String, i64)> {
    let mut counts = BTreeMap::new();
    for row in rows {
        *counts.entry(row).or_insert(0) += 1;
    }
    sorted_counts(counts, limit)
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
