// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::cli_output::{
    AgentTopOutput, AgentTopRow, ResourcePeaks, StatOutput, TopSection, clear_screen,
    print_agent_top, print_json, print_stat,
};
use crate::framework::storage::{
    SnapshotOptions, SqliteStore,
    sqlite::{Snapshot, StorageResult},
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub(crate) struct TopOptions {
    pub(crate) pid: Option<u32>,
    pub(crate) comm: Option<String>,
    pub(crate) sort: String,
    pub(crate) view: String,
}

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

pub(crate) fn run_live_top_query(
    interval_secs: u64,
    limit: usize,
    count: Option<u32>,
    options: &TopOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let limit = limit.clamp(1, 100);
    let interval = Duration::from_secs(interval_secs.max(1));
    let mut iterations = 0u32;
    let should_clear_screen = count != Some(1);
    let mut previous: Option<LiveSample> = None;

    loop {
        let sample = LiveSample::collect()?;
        if should_clear_screen {
            clear_screen();
        }
        let mut top = build_live_top(&sample, previous.as_ref(), limit, options);
        sort_agent_rows(&mut top.rows, &options.sort);
        top.rows.truncate(limit);
        print_agent_top(&top);
        io::stdout().flush()?;

        previous = Some(sample);
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
        canonical_events: snapshot.summary.canonical_events,
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
            .map(|p| agent_name_from_command(&p.comm, &p.command))
            .unwrap_or_else(|| "agent".to_string());
        rows.push(AgentTopRow {
            agent,
            pid: Some(root_pid),
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
            if !matches_top_filter(session.pid, session.comm.as_deref(), None, options) {
                continue;
            }
            rows.push(AgentTopRow {
                agent: session
                    .agent_name
                    .clone()
                    .unwrap_or_else(|| session.agent_type.clone()),
                pid: session.pid,
                cpu_percent: resources.max_cpu_percent,
                rss_mb: resources.max_rss_mb,
                processes: 1,
                tokens: (session.total_tokens > 0).then_some(session.total_tokens),
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
        if !matches_top_filter(
            Some(process.pid),
            Some(&process.comm),
            Some(&process.command),
            options,
        ) {
            continue;
        }
        let parent_known = process
            .ppid
            .and_then(|ppid| processes.get(&ppid))
            .is_some_and(|parent| {
                matches_top_filter(
                    Some(parent.pid),
                    Some(&parent.comm),
                    Some(&parent.command),
                    options,
                )
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
    for event in &snapshot.events {
        if let (Some(pid), Some(host)) = (event.pid, event.host.as_ref()) {
            out.entry(pid)
                .or_insert_with(BTreeSet::new)
                .insert(host.clone());
        }
    }
    out
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

#[derive(Debug, Clone)]
struct ProcInfo {
    pid: u32,
    ppid: u32,
    comm: String,
    command: String,
    ticks: u64,
    starttime_ticks: u64,
    rss_mb: u64,
}

#[derive(Debug, Clone)]
struct LiveSample {
    at: Instant,
    uptime_s: f64,
    procs: BTreeMap<u32, ProcInfo>,
}

impl LiveSample {
    fn collect() -> io::Result<Self> {
        let page_size = page_size_bytes();
        let mut procs = BTreeMap::new();

        for entry in fs::read_dir("/proc")? {
            let Ok(entry) = entry else { continue };
            let file_name = entry.file_name();
            let Some(pid) = file_name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
                continue;
            };
            let Some(mut proc_info) = read_proc_info(pid, page_size) else {
                continue;
            };
            if proc_info.command.is_empty() {
                proc_info.command = proc_info.comm.clone();
            }
            procs.insert(pid, proc_info);
        }

        Ok(Self {
            at: Instant::now(),
            uptime_s: read_uptime_s().unwrap_or_default(),
            procs,
        })
    }
}

fn build_live_top<'a>(
    sample: &LiveSample,
    previous: Option<&LiveSample>,
    _limit: usize,
    options: &TopOptions,
) -> AgentTopOutput<'a> {
    let roots = live_roots(sample, options);
    let children = children_by_ppid(&sample.procs);
    let mut rows = Vec::new();

    for root_pid in roots {
        let family = live_process_family(root_pid, &children, &sample.procs);
        if family.is_empty() {
            continue;
        }
        let root = sample.procs.get(&root_pid);
        let cpu_percent = family
            .iter()
            .filter_map(|pid| sample.procs.get(pid))
            .map(|proc_info| process_cpu_percent(proc_info, previous, sample))
            .sum();
        let rss_mb = family
            .iter()
            .filter_map(|pid| sample.procs.get(pid).map(|proc_info| proc_info.rss_mb))
            .sum();
        let agent = root
            .map(|proc_info| agent_name_from_command(&proc_info.comm, &proc_info.command))
            .unwrap_or_else(|| "agent".to_string());

        rows.push(AgentTopRow {
            agent,
            pid: Some(root_pid),
            cpu_percent,
            rss_mb,
            processes: family.len(),
            tokens: None,
            execs: 0,
            failures: 0,
            files: 0,
            network: 0,
            unattributed: 0,
            trace: "proc".to_string(),
            command: root
                .map(|proc_info| proc_info.command.clone())
                .unwrap_or_else(|| "unknown".to_string()),
        });
    }

    let mut notes = vec![
        "live process view uses /proc; run agentsight record/stat for tokens, files, network, and failures"
            .to_string(),
    ];
    if rows.is_empty() {
        if options.pid.is_some() || options.comm.is_some() {
            notes.push(
                "no active process matched the filter; try another -p/-c value or inspect a saved session with --db"
                    .to_string(),
            );
        } else {
            notes.push(
                "no active known agent process found; use -c/-p for arbitrary commands or --db for saved sessions"
                    .to_string(),
            );
        }
    }

    AgentTopOutput {
        mode: "live /proc",
        db: None,
        duration_s: 0.0,
        canonical_events: 0,
        llm_calls: 0,
        total_tokens: 0,
        rows,
        sections: Vec::new(),
        failures: Vec::new(),
        notes,
    }
}

fn read_proc_info(pid: u32, page_size: u64) -> Option<ProcInfo> {
    let proc_dir = format!("/proc/{pid}");
    let stat = fs::read_to_string(format!("{proc_dir}/stat")).ok()?;
    let (comm, ppid, ticks, starttime_ticks) = parse_proc_stat(&stat)?;
    let command = read_cmdline(pid).unwrap_or_else(|| comm.clone());
    let rss_mb = read_rss_mb(pid, page_size).unwrap_or_default();
    Some(ProcInfo {
        pid,
        ppid,
        comm,
        command,
        ticks,
        starttime_ticks,
        rss_mb,
    })
}

fn parse_proc_stat(stat: &str) -> Option<(String, u32, u64, u64)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat[open + 1..close].to_string();
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    let ppid = fields.get(1)?.parse().ok()?;
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let starttime_ticks = fields.get(19)?.parse().ok()?;
    Some((comm, ppid, utime.saturating_add(stime), starttime_ticks))
}

fn read_cmdline(pid: u32) -> Option<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let command = bytes
        .split(|byte| *byte == 0)
        .filter_map(|part| std::str::from_utf8(part).ok())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!command.is_empty()).then_some(command)
}

fn read_rss_mb(pid: u32, page_size: u64) -> Option<u64> {
    let statm = fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    let rss_bytes = resident_pages.saturating_mul(page_size);
    if rss_bytes == 0 {
        Some(0)
    } else {
        Some(rss_bytes.div_ceil(1_048_576))
    }
}

fn read_uptime_s() -> Option<f64> {
    fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn page_size_bytes() -> u64 {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value > 0 { value as u64 } else { 4096 }
}

fn ticks_per_second() -> f64 {
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if value > 0 { value as f64 } else { 100.0 }
}

fn process_cpu_percent(
    proc_info: &ProcInfo,
    previous: Option<&LiveSample>,
    sample: &LiveSample,
) -> f64 {
    let ticks_per_second = ticks_per_second();
    if let Some(previous) = previous
        && let Some(prev_proc) = previous.procs.get(&proc_info.pid)
    {
        let delta_ticks = proc_info.ticks.saturating_sub(prev_proc.ticks);
        let delta_wall = sample.at.duration_since(previous.at).as_secs_f64();
        if delta_wall > 0.0 {
            return (delta_ticks as f64 / ticks_per_second) / delta_wall * 100.0;
        }
    }

    let process_start_s = proc_info.starttime_ticks as f64 / ticks_per_second;
    let elapsed_s = (sample.uptime_s - process_start_s).max(0.001);
    (proc_info.ticks as f64 / ticks_per_second) / elapsed_s * 100.0
}

fn live_roots(sample: &LiveSample, options: &TopOptions) -> Vec<u32> {
    if let Some(pid) = options.pid {
        return sample
            .procs
            .contains_key(&pid)
            .then_some(vec![pid])
            .unwrap_or_default();
    }

    let mut roots = Vec::new();
    for proc_info in sample.procs.values() {
        if !live_process_matches(proc_info, options) {
            continue;
        }
        if live_matching_ancestor(proc_info, sample, options) {
            continue;
        }
        roots.push(proc_info.pid);
    }
    roots.sort_unstable();
    roots
}

fn live_process_matches(proc_info: &ProcInfo, options: &TopOptions) -> bool {
    if options.comm.is_none() {
        return known_agent_label(&proc_info.comm, &proc_info.command).is_some();
    }
    matches_top_filter(
        Some(proc_info.pid),
        Some(&proc_info.comm),
        Some(&proc_info.command),
        options,
    )
}

fn live_matching_ancestor(proc_info: &ProcInfo, sample: &LiveSample, options: &TopOptions) -> bool {
    let current_label = known_agent_label(&proc_info.comm, &proc_info.command);
    let mut parent_pid = proc_info.ppid;
    let mut seen = HashSet::new();
    while parent_pid > 0 && seen.insert(parent_pid) {
        let Some(parent) = sample.procs.get(&parent_pid) else {
            break;
        };
        if options.comm.is_some() {
            if live_process_matches(parent, options) {
                return true;
            }
        } else if known_agent_label(&parent.comm, &parent.command) == current_label {
            return true;
        }
        parent_pid = parent.ppid;
    }
    false
}

fn children_by_ppid(procs: &BTreeMap<u32, ProcInfo>) -> HashMap<u32, Vec<u32>> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for proc_info in procs.values() {
        children
            .entry(proc_info.ppid)
            .or_default()
            .push(proc_info.pid);
    }
    children
}

fn live_process_family(
    root: u32,
    children: &HashMap<u32, Vec<u32>>,
    procs: &BTreeMap<u32, ProcInfo>,
) -> Vec<u32> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    let mut seen = HashSet::new();
    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) || !procs.contains_key(&pid) {
            continue;
        }
        out.push(pid);
        if let Some(child_pids) = children.get(&pid) {
            stack.extend(child_pids.iter().copied());
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

fn matches_top_filter(
    pid: Option<u32>,
    comm: Option<&str>,
    command: Option<&str>,
    options: &TopOptions,
) -> bool {
    if let Some(wanted_pid) = options.pid {
        return pid == Some(wanted_pid);
    }
    if let Some(wanted_comm) = &options.comm {
        let wanted_comm = wanted_comm.to_ascii_lowercase();
        return comm
            .map(|comm| comm.to_ascii_lowercase().contains(&wanted_comm))
            .unwrap_or(false)
            || command
                .map(|command| command.to_ascii_lowercase().contains(&wanted_comm))
                .unwrap_or(false);
    }
    true
}

fn agent_name_from_command(comm: &str, command: &str) -> String {
    known_agent_label(comm, command)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if !comm.is_empty() && comm != "unknown" {
                comm.to_string()
            } else {
                command
                    .split_whitespace()
                    .next()
                    .unwrap_or("agent")
                    .to_string()
            }
        })
}

fn known_agent_label(comm: &str, command: &str) -> Option<&'static str> {
    let needle = format!(
        "{} {}",
        comm.to_ascii_lowercase(),
        command.to_ascii_lowercase()
    );
    [
        ("claude", "claude"),
        ("codex", "codex"),
        ("gemini", "gemini"),
        ("opencode", "opencode"),
        ("openclaw", "openclaw"),
        ("aider", "aider"),
        ("goose", "goose"),
    ]
    .into_iter()
    .find_map(|(marker, label)| needle.contains(marker).then_some(label))
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
