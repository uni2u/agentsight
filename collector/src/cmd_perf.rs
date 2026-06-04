// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::output::{
    AgentTopOutput, AgentTopRow, ResourcePeaks, StatOutput, TopOptions, TopSection, clear_screen,
    print_agent_top, print_json, print_stat,
};
use crate::sources::proc as procfs;
use crate::sources::sqlite::load_view as load_sqlite_view;
use crate::text::short_session_id;
use crate::view::types::{SessionRow, Snapshot, SnapshotOptions, ViewResult};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, Write};
use std::time::Duration;

mod live;
pub(crate) use live::{run_live_top_query, run_live_top_tui};

#[cfg(test)]
use crate::sources::session as local_sessions;

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
    options: &TopOptions,
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
        let mut top = build_session_top(db, &snapshot, &resources, limit, options);
        sort_agent_rows(&mut top.rows, &options.sort);
        top.rows.truncate(limit);
        print_agent_top(&top);
        io::stdout().flush()?;

        iterations += 1;
        if count.is_some_and(|max| iterations >= max) || crate::shutdown_requested() {
            break;
        }
        std::thread::sleep(interval);
    }

    Ok(())
}

fn load_stat(db: &str) -> ViewResult<StatOutput> {
    let view = load_sqlite_view(db)?;
    let snapshot = view.export_snapshot(SnapshotOptions {
        audit_limit: 50_000,
    });
    let resources = resource_peaks_from_samples(view.resource_samples());
    let tool_calls = view.tool_call_count();
    let (input_tokens, output_tokens, total_tokens) = snapshot.materialized_token_totals();

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
        .network_targets
        .iter()
        .map(|target| target.host.clone())
        .collect::<BTreeSet<_>>()
        .len();
    let http_errors = snapshot
        .network_targets
        .iter()
        .map(|target| target.error_count.max(0) as usize)
        .sum();

    Ok(StatOutput {
        db: db.to_string(),
        duration_s: duration_s(&snapshot),
        view_events: snapshot.summary.view_events,
        llm_calls: snapshot.summary.llm_calls,
        input_tokens,
        output_tokens,
        total_tokens,
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

fn build_session_top<'a>(
    db: &'a str,
    snapshot: &Snapshot,
    resources: &ResourcePeaks,
    limit: usize,
    options: &TopOptions,
) -> AgentTopOutput<'a> {
    let rows = session_agent_rows(snapshot, resources, options);
    let sections = top_sections(snapshot, limit, &options.view);
    let mut notes =
        vec!["static session view; run without --db for live /proc agent process top".to_string()];
    if options.pid.is_some() || options.comm.is_some() {
        notes.push("filter applied before process-family aggregation".to_string());
    }
    AgentTopOutput {
        mode: "static session",
        db: Some(db),
        duration_s: duration_s(snapshot),
        view_events: snapshot.summary.view_events,
        llm_calls: snapshot.summary.llm_calls,
        total_tokens: snapshot.summary.total_tokens,
        rows,
        sections,
        failures: recent_failures(snapshot, 5),
        notes,
    }
}

fn top_sections(snapshot: &Snapshot, limit: usize, view: &str) -> Vec<TopSection> {
    let audit = &snapshot.audit_events;
    let model_counts = snapshot
        .token_summary
        .iter()
        .map(|row| (row.group.clone(), row.total_tokens))
        .collect();
    let all = vec![
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
            sorted_counts(network_target_counts(snapshot), limit),
        ),
        ("Models", "tokens", sorted_counts(model_counts, limit)),
    ];
    all.into_iter()
        .filter(|(title, _, _)| show_section(view, title))
        .collect()
}

fn show_section(view: &str, title: &str) -> bool {
    let view = view.to_ascii_lowercase();
    match view.as_str() {
        "all" => true,
        "process" | "processes" | "proc" => title == "Processes",
        "file" | "files" | "fs" => title == "Files",
        "network" | "net" => title == "Network",
        "model" | "models" | "tokens" => title == "Models",
        _ => true,
    }
}

#[derive(Debug, Default, Clone)]
struct ProcessMeta {
    pid: u32,
    ppid: Option<u32>,
    comm: String,
    command: String,
}

fn session_agent_rows(
    snapshot: &Snapshot,
    resources: &ResourcePeaks,
    options: &TopOptions,
) -> Vec<AgentTopRow> {
    let top_model = dominant_model(snapshot);
    let db_age_s = snapshot_age_s(snapshot);
    let mut processes = BTreeMap::<u32, ProcessMeta>::new();
    for row in &snapshot.audit_events {
        let Some(pid) = row.pid else { continue };
        let entry = processes.entry(pid).or_insert_with(|| ProcessMeta {
            pid,
            ppid: details_ppid(&row.details),
            comm: row.comm.clone().unwrap_or_else(|| "unknown".to_string()),
            command: process_command(row.audit_type.as_str(), &row.details, row.target.as_deref())
                .unwrap_or_else(|| row.comm.clone().unwrap_or_else(|| "unknown".to_string())),
        });
        if entry.ppid.is_none() {
            entry.ppid = details_ppid(&row.details);
        }
        if let Some(comm) = &row.comm
            && entry.comm == "unknown"
        {
            entry.comm = comm.clone();
        }
        if let Some(command) =
            process_command(row.audit_type.as_str(), &row.details, row.target.as_deref())
            && (entry.command == "unknown"
                || entry.command == entry.comm
                || entry.command.starts_with("exec "))
        {
            entry.command = command;
        }
    }

    let roots = session_roots(&processes, options);
    let mut rows = Vec::new();
    let hosts_by_pid = hosts_by_pid(snapshot);
    let tokens_by_pid = session_tokens_by_pid(snapshot);
    let mut assigned_global_tokens = false;

    for root_pid in roots {
        let family = process_family(root_pid, &processes);
        if family.is_empty() {
            continue;
        }
        let family_set: HashSet<u32> = family.iter().copied().collect();
        let mut execs = 0usize;
        let mut failures = 0usize;
        let mut files = BTreeSet::new();
        for row in &snapshot.audit_events {
            let Some(pid) = row.pid else { continue };
            if !family_set.contains(&pid) {
                continue;
            }
            match row.audit_type.as_str() {
                "process" if row.action.as_deref() == Some("exec") => execs += 1,
                "process" if row.action.as_deref() == Some("exit") => {
                    if row.status.as_deref() == Some("failure") {
                        failures += 1;
                    }
                }
                "file" => {
                    if let Some(target) = &row.target {
                        files.insert(target.clone());
                    }
                }
                _ => {}
            }
        }

        let network = family
            .iter()
            .filter_map(|pid| hosts_by_pid.get(pid))
            .flatten()
            .collect::<BTreeSet<_>>()
            .len();
        let family_tokens = family
            .iter()
            .filter_map(|pid| tokens_by_pid.get(pid))
            .sum::<i64>();
        let tokens = if family_tokens > 0 {
            Some(family_tokens)
        } else if tokens_by_pid.is_empty()
            && !assigned_global_tokens
            && snapshot.summary.total_tokens > 0
        {
            assigned_global_tokens = true;
            Some(snapshot.summary.total_tokens)
        } else {
            None
        };
        let root = processes.get(&root_pid);
        let agent = root
            .map(|p| procfs::agent_name_from_command(&p.comm, &p.command))
            .unwrap_or_else(|| "agent".to_string());
        rows.push(AgentTopRow {
            session: format!("db:{root_pid}"),
            agent,
            pid: Some(root_pid),
            model: top_model.clone(),
            age_s: db_age_s,
            cpu_percent: if rows.is_empty() {
                resources.max_cpu_percent
            } else {
                0.0
            },
            rss_mb: if rows.is_empty() {
                resources.max_rss_mb
            } else {
                0
            },
            processes: family.len(),
            tokens,
            tools: 0,
            execs,
            failures,
            files: files.len(),
            network,
            unattributed: 0,
            trace: "db".to_string(),
            command: root
                .map(|p| p.command.clone())
                .unwrap_or_else(|| "unknown".to_string()),
        });
    }

    if rows.is_empty() && (!snapshot.sessions.is_empty() || !snapshot.agents.is_empty()) {
        for session in &snapshot.sessions {
            if !options.matches(session.pid, session.comm.as_deref(), None) {
                continue;
            }
            rows.push(AgentTopRow {
                session: short_session_id(&session.id),
                agent: session
                    .agent_name
                    .clone()
                    .unwrap_or_else(|| session.agent_type.clone()),
                pid: session.pid,
                model: session.model.clone().or_else(|| top_model.clone()),
                age_s: session_age_s(session, snapshot),
                cpu_percent: resources.max_cpu_percent,
                rss_mb: resources.max_rss_mb,
                processes: 1,
                tokens: (session.total_tokens > 0).then_some(session.total_tokens),
                tools: 0,
                execs: 0,
                failures: 0,
                files: 0,
                network: 0,
                unattributed: 0,
                trace: "db".to_string(),
                command: session
                    .comm
                    .clone()
                    .unwrap_or_else(|| session.agent_type.clone()),
            });
        }
    }

    rows
}

fn session_roots(processes: &BTreeMap<u32, ProcessMeta>, options: &TopOptions) -> Vec<u32> {
    if let Some(pid) = options.pid {
        return processes
            .contains_key(&pid)
            .then_some(vec![pid])
            .unwrap_or_default();
    }
    let mut roots = Vec::new();
    for process in processes.values() {
        if !options.matches(
            Some(process.pid),
            Some(&process.comm),
            Some(&process.command),
        ) {
            continue;
        }
        let parent_known = process
            .ppid
            .and_then(|ppid| processes.get(&ppid))
            .is_some_and(|parent| {
                options.matches(Some(parent.pid), Some(&parent.comm), Some(&parent.command))
            });
        if !parent_known {
            roots.push(process.pid);
        }
    }
    if roots.is_empty() && options.comm.is_none() {
        roots = processes
            .values()
            .filter(|process| {
                process
                    .ppid
                    .is_none_or(|ppid| !processes.contains_key(&ppid))
            })
            .map(|process| process.pid)
            .collect();
    }
    roots.sort_unstable();
    roots
}

fn process_family(root: u32, processes: &BTreeMap<u32, ProcessMeta>) -> Vec<u32> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(pid) = stack.pop() {
        if out.contains(&pid) {
            continue;
        }
        out.push(pid);
        for process in processes.values() {
            if process.ppid == Some(pid) {
                stack.push(process.pid);
            }
        }
    }
    out
}

fn details_ppid(details: &Value) -> Option<u32> {
    details
        .get("ppid")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
}

fn details_command(details: &Value) -> Option<String> {
    details
        .get("full_command")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            details.get("argv").and_then(|v| v.as_array()).map(|argv| {
                argv.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
        })
        .filter(|s| !s.is_empty())
}

fn process_command(audit_type: &str, details: &Value, target: Option<&str>) -> Option<String> {
    if audit_type != "process" {
        return None;
    }
    details_command(details).or_else(|| target.map(str::to_string))
}

fn hosts_by_pid(snapshot: &Snapshot) -> BTreeMap<u32, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for target in &snapshot.network_targets {
        if let Some(pid) = target.pid {
            out.entry(pid)
                .or_insert_with(BTreeSet::new)
                .insert(target.host.clone());
        }
    }
    out
}

fn network_target_counts(snapshot: &Snapshot) -> BTreeMap<String, i64> {
    let mut counts = BTreeMap::new();
    for target in &snapshot.network_targets {
        *counts.entry(target.host.clone()).or_default() += target.count.max(0);
    }
    counts
}

fn session_tokens_by_pid(snapshot: &Snapshot) -> BTreeMap<u32, i64> {
    let mut out = BTreeMap::new();
    for session in &snapshot.sessions {
        if let Some(pid) = session.pid
            && session.total_tokens > 0
        {
            *out.entry(pid).or_insert(0) += session.total_tokens;
        }
    }
    out
}

fn sort_agent_rows(rows: &mut [AgentTopRow], sort: &str) {
    let sort = sort.to_ascii_lowercase();
    rows.sort_by(|a, b| {
        let primary = match sort.as_str() {
            "rss" | "mem" | "memory" => b.rss_mb.cmp(&a.rss_mb),
            "tokens" | "token" => b
                .tokens
                .unwrap_or_default()
                .cmp(&a.tokens.unwrap_or_default()),
            "exec" | "execs" => b.execs.cmp(&a.execs),
            "fail" | "fails" | "failure" | "failures" => b.failures.cmp(&a.failures),
            "file" | "files" => b.files.cmp(&a.files),
            "net" | "network" => b.network.cmp(&a.network),
            "agent" | "name" | "command" => a.agent.cmp(&b.agent),
            _ => b
                .cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal),
        };
        primary
            .then_with(|| {
                b.cpu_percent
                    .partial_cmp(&a.cpu_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| b.rss_mb.cmp(&a.rss_mb))
            .then_with(|| a.agent.cmp(&b.agent))
            .then_with(|| a.pid.cmp(&b.pid))
    });
}

fn load_snapshot_and_resources(db: &str) -> ViewResult<(Snapshot, ResourcePeaks)> {
    let view = load_sqlite_view(db)?;
    let snapshot = view.export_snapshot(SnapshotOptions {
        audit_limit: 50_000,
    });
    let resources = resource_peaks_from_samples(view.resource_samples());
    Ok((snapshot, resources))
}

fn resource_peaks_from_samples(samples: Vec<(Option<f64>, Option<i64>)>) -> ResourcePeaks {
    let mut peaks = ResourcePeaks::default();
    for (cpu, rss_mb) in samples {
        if let Some(cpu) = cpu
            && cpu >= peaks.max_cpu_percent
        {
            peaks.max_cpu_percent = cpu;
        }
        if let Some(rss_mb) = rss_mb.map(|v| v.max(0) as u64)
            && rss_mb >= peaks.max_rss_mb
        {
            peaks.max_rss_mb = rss_mb;
        }
        peaks.samples += 1;
    }

    peaks
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

fn snapshot_age_s(snapshot: &Snapshot) -> Option<f64> {
    let duration = duration_s(snapshot);
    (duration > 0.0).then_some(duration)
}

fn session_age_s(session: &SessionRow, snapshot: &Snapshot) -> Option<f64> {
    let end = session
        .end_timestamp_ms
        .or(snapshot.summary.end_timestamp_ms)
        .unwrap_or(session.start_timestamp_ms);
    (end > session.start_timestamp_ms).then(|| (end - session.start_timestamp_ms) as f64 / 1000.0)
}

fn dominant_model(snapshot: &Snapshot) -> Option<String> {
    snapshot
        .token_summary
        .iter()
        .find(|row| row.group != "unknown" && row.total_tokens > 0)
        .map(|row| row.group.clone())
        .or_else(|| {
            snapshot
                .sessions
                .iter()
                .find_map(|session| session.model.clone())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::types::AuditEventRow;

    #[test]
    fn stat_tokens_fall_back_to_agent_sessions() {
        let mut snapshot = Snapshot::empty("sqlite");
        snapshot.summary.llm_calls = 1;
        snapshot.summary.sessions = 1;
        snapshot.sessions = vec![SessionRow {
            id: "session-1".to_string(),
            agent_type: "claude-code".to_string(),
            agent_name: Some("claude".to_string()),
            pid: None,
            comm: None,
            start_timestamp_ms: 1_000,
            end_timestamp_ms: Some(2_000),
            status: "completed".to_string(),
            model: Some("claude-opus-4-6".to_string()),
            input_tokens: 3,
            output_tokens: 10,
            total_tokens: 27667,
            view_source: "claude-code".to_string(),
            confidence: Some(0.9),
            attributes: serde_json::json!({}),
        }];

        assert_eq!(snapshot.materialized_token_totals(), (3, 10, 27667));
    }

    #[test]
    fn stat_tokens_ignore_touched_local_log_without_usage() {
        let (_temp, path) = local_sessions::create_temp_session_path("claude");
        std::fs::write(
            &path,
            "{\"type\":\"user\",\"message\":{\"content\":\"local prompt only\"}}\n",
        )
        .unwrap();

        let mut snapshot = Snapshot::empty("sqlite");
        snapshot.summary.llm_calls = 1;
        snapshot.summary.token_usage_rows = 1;
        snapshot.summary.audit_events = 1;
        snapshot.summary.input_tokens = 8;
        snapshot.summary.output_tokens = 5;
        snapshot.summary.total_tokens = 13;
        snapshot.audit_events = vec![AuditEventRow {
            id: "audit-1".to_string(),
            timestamp_ms: 1_000,
            audit_type: "file".to_string(),
            pid: Some(42),
            comm: Some("claude".to_string()),
            subject: None,
            action: Some("write".to_string()),
            target: Some(path.to_string_lossy().to_string()),
            status: Some("observed".to_string()),
            summary: None,
            details: serde_json::json!({}),
        }];

        assert_eq!(snapshot.materialized_token_totals(), (8, 5, 13));
    }
}
