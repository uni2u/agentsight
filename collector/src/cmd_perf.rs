// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::framework::binary_extractor::BinaryExtractor;
use crate::framework::core::Event;
use crate::framework::runners::{ProcessRunner, Runner};
use crate::output::{
    AgentTopOutput, AgentTopRow, ResourcePeaks, StatOutput, TopOptions, TopSection, clear_screen,
    draw_live_top_tui, next_view_key, print_agent_top, print_json, print_stat,
    print_top_sudo_prompt,
};
use crate::sources::proc::{self as procfs, ProcInfo, ProcSnapshot as LiveSample};
use crate::sources::session::{self as local_sessions, LocalSession};
use crate::sources::sqlite::SqliteSource;
use crate::text::short_session_id;
use crate::view::types::{SessionRow, Snapshot, SnapshotOptions, StorageResult};
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event as CrosstermEvent, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt;
use ratatui::{Terminal, backend::CrosstermBackend};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Default)]
struct CaptureCounters {
    execs: usize,
    failures: usize,
    files: usize,
    network: usize,
}

impl CaptureCounters {
    fn add(&mut self, other: CaptureCounters) {
        self.execs += other.execs;
        self.failures += other.failures;
        self.files += other.files;
        self.network += other.network;
    }

    fn is_empty(self) -> bool {
        self.execs == 0 && self.failures == 0 && self.files == 0 && self.network == 0
    }
}

#[derive(Debug, Clone, Default)]
struct LiveCaptureSnapshot {
    by_pid: HashMap<u32, CaptureCounters>,
    session_paths_by_pid: HashMap<u32, BTreeSet<PathBuf>>,
    events: u64,
    parse_errors: u64,
}

#[derive(Default)]
struct LiveCaptureState {
    by_pid: HashMap<u32, CaptureCounters>,
    session_paths_by_pid: HashMap<u32, BTreeSet<PathBuf>>,
    events: u64,
    parse_errors: u64,
}

const TRACE_EBPF_FILE: &str = "ebpf_file";
const TRACE_PROC_FD: &str = "proc_fd";
const TRACE_STICKY_BINDING: &str = "sticky";

#[derive(Default)]
struct LiveSessionBindings {
    by_pid: HashMap<u32, LiveSessionBinding>,
}

struct LiveSessionBinding {
    starttime_ticks: u64,
    session_path: PathBuf,
}

impl LiveSessionBindings {
    fn retain_live(&mut self, live_rows: &[AgentTopRow], sample: &LiveSample) {
        self.by_pid.retain(|pid, binding| {
            live_rows.iter().any(|row| row.pid == Some(*pid))
                && sample
                    .procs
                    .get(pid)
                    .is_some_and(|proc_info| proc_info.starttime_ticks == binding.starttime_ticks)
        });
    }

    fn link_trace(
        &mut self,
        session: &LocalSession,
        row: &AgentTopRow,
        sample: &LiveSample,
        path_evidence: &HashMap<u32, BTreeMap<PathBuf, &'static str>>,
    ) -> Option<&'static str> {
        let pid = row.pid?;
        let proc_info = sample.procs.get(&pid)?;
        let path = local_sessions::normalize_session_log_path(&session.path);

        if let Some(evidence) = path_evidence.get(&pid) {
            if let Some(trace) = evidence.get(&path).copied() {
                self.by_pid.insert(
                    pid,
                    LiveSessionBinding {
                        starttime_ticks: proc_info.starttime_ticks,
                        session_path: path,
                    },
                );
                return Some(trace);
            }
            self.by_pid.remove(&pid);
            return None;
        }

        self.by_pid
            .get(&pid)
            .filter(|binding| {
                binding.starttime_ticks == proc_info.starttime_ticks && binding.session_path == path
            })
            .map(|_| TRACE_STICKY_BINDING)
    }
}

struct LiveEbpfCapture {
    state: Arc<Mutex<LiveCaptureState>>,
    handle: tokio::task::JoinHandle<()>,
    start_note: Option<String>,
}

impl LiveEbpfCapture {
    fn snapshot(&self) -> LiveCaptureSnapshot {
        let Ok(state) = self.state.lock() else {
            return LiveCaptureSnapshot::default();
        };
        LiveCaptureSnapshot {
            by_pid: state.by_pid.clone(),
            session_paths_by_pid: state.session_paths_by_pid.clone(),
            events: state.events,
            parse_errors: state.parse_errors,
        }
    }

    fn stop(self) {
        self.handle.abort();
    }
}

#[derive(Default)]
struct LiveView {
    previous: Option<LiveSample>,
    bindings: LiveSessionBindings,
}

impl LiveView {
    fn refresh(
        &mut self,
        capture: Option<&LiveEbpfCapture>,
        limit: usize,
        options: &TopOptions,
    ) -> io::Result<AgentTopOutput<'static>> {
        let sample = LiveSample::collect()?;
        let capture_snapshot = capture.map(LiveEbpfCapture::snapshot);
        let mut top = self.build_top(&sample, capture_snapshot.as_ref(), limit, options);
        if let Some(note) = capture.and_then(|capture| capture.start_note.clone()) {
            top.notes.push(note);
        }
        self.previous = Some(sample);
        Ok(top)
    }

    fn build_top<'a>(
        &mut self,
        sample: &LiveSample,
        capture: Option<&LiveCaptureSnapshot>,
        limit: usize,
        options: &TopOptions,
    ) -> AgentTopOutput<'a> {
        let mut live_rows = live_process_rows(sample, self.previous.as_ref(), options);
        sort_agent_rows(&mut live_rows, "cpu");
        let local_sessions = discover_local_top_sessions(options, limit);
        let path_evidence = collect_live_session_path_evidence(&live_rows, sample, capture);
        self.bindings.retain_live(&live_rows, sample);
        let mut used_live_pids = HashSet::new();
        let mut rows = Vec::new();

        for session in local_sessions {
            let live_match = live_rows.iter().enumerate().find_map(|(idx, row)| {
                if row.pid.is_some_and(|pid| used_live_pids.contains(&pid))
                    || row.agent != session.agent
                    || !options.matches(row.pid, Some(&row.agent), Some(&row.command))
                {
                    return None;
                }
                self.bindings
                    .link_trace(&session, row, sample, &path_evidence)
                    .map(|trace| (idx, trace))
            });
            let live = live_match
                .and_then(|(idx, trace)| live_rows.get(idx).cloned().map(|row| (row, trace)));
            if let Some(pid) = live.as_ref().and_then(|(row, _)| row.pid) {
                used_live_pids.insert(pid);
            }
            let command = session
                .prompt_preview
                .clone()
                .or_else(|| live.as_ref().map(|(row, _)| row.command.clone()))
                .unwrap_or_else(|| session.path.display().to_string());
            let trace = if let Some((_, link_trace)) = &live {
                format!("local+proc+{link_trace}")
            } else {
                "local".to_string()
            };
            let age_s = live
                .as_ref()
                .and_then(|(row, _)| row.age_s)
                .or_else(|| session.age_s());
            let tools = session.tools_total();
            rows.push(AgentTopRow {
                session: session.display_id,
                agent: session.agent,
                pid: live.as_ref().and_then(|(row, _)| row.pid),
                model: session.model,
                age_s,
                cpu_percent: live
                    .as_ref()
                    .map(|(row, _)| row.cpu_percent)
                    .unwrap_or_default(),
                rss_mb: live.as_ref().map(|(row, _)| row.rss_mb).unwrap_or_default(),
                processes: live
                    .as_ref()
                    .map(|(row, _)| row.processes)
                    .unwrap_or_default(),
                tokens: (session.total_tokens > 0).then_some(session.total_tokens),
                tools,
                execs: 0,
                failures: 0,
                files: 0,
                network: 0,
                unattributed: 0,
                trace,
                command,
            });
        }

        rows.extend(live_rows.into_iter().filter(|row| {
            row.pid
                .map(|pid| !used_live_pids.contains(&pid))
                .unwrap_or(true)
        }));
        if let Some(capture) = capture {
            apply_live_capture(&mut rows, sample, capture);
        }

        let has_local = rows.iter().any(|row| row.trace.contains("local"));
        let has_proc = rows.iter().any(|row| row.trace.contains("proc"));
        let has_ebpf = rows.iter().any(|row| row.trace.contains("ebpf"));
        let has_session_file_link = rows.iter().any(|row| {
            row.trace.contains("ebpf_file")
                || row.trace.contains("proc_fd")
                || row.trace.contains("sticky")
        });
        let mut notes = Vec::new();
        if has_local {
            notes.push(
                "session tokens/tools come from local ~/.claude or ~/.codex logs".to_string(),
            );
        }
        if has_proc {
            notes.push("proc evidence uses /proc for CPU/RSS/process families".to_string());
        }
        if has_session_file_link {
            notes.push("local sessions bind to live pids after the process touches the matching JSONL log path; binding stays until pid exits or a new session path is observed".to_string());
        }
        if has_ebpf {
            notes.push(
                "ebpf evidence is live process capture; SSL/network/token details still require record/stat or local agent logs"
                    .to_string(),
            );
        }
        if let Some(capture) = capture
            && capture.parse_errors > 0
        {
            notes.push(format!(
                "ebpf process capture had {} parse errors",
                capture.parse_errors
            ));
        }
        if rows.is_empty() {
            if options.pid.is_some() || options.comm.is_some() {
                notes.push(
                    "no active process or local session matched the filter; try another -p/-c value or inspect a saved session with --db"
                        .to_string(),
                );
            } else {
                notes.push(
                    "no active known agent process or local Claude/Codex session found; use -c/-p, run an agent, or pass --db"
                        .to_string(),
                );
            }
        }

        AgentTopOutput {
            mode: "live sessions",
            db: None,
            duration_s: 0.0,
            view_events: 0,
            llm_calls: 0,
            total_tokens: rows.iter().filter_map(|row| row.tokens).sum(),
            rows,
            sections: Vec::new(),
            failures: Vec::new(),
            notes,
        }
    }
}

async fn start_live_ebpf_capture(
    binary_extractor: &BinaryExtractor,
    options: &TopOptions,
) -> Option<LiveEbpfCapture> {
    let start_note = match prepare_live_ebpf_privileges() {
        Ok(note) => note,
        Err(note) => {
            return Some(LiveEbpfCapture {
                state: Arc::new(Mutex::new(LiveCaptureState::default())),
                handle: tokio::spawn(async {}),
                start_note: Some(note),
            });
        }
    };

    let mut args = Vec::new();
    if let Some(pid) = options.pid {
        args.extend(["-p".to_string(), pid.to_string()]);
    } else if let Some(comm) = &options.comm {
        args.extend(["-c".to_string(), comm.clone()]);
    } else {
        args.extend(["-m".to_string(), "1".to_string()]);
    }
    args.push("--trace-fs".to_string());

    let seed_snapshot = match LiveSample::collect() {
        Ok(snapshot) => snapshot,
        Err(err) => {
            return Some(LiveEbpfCapture {
                state: Arc::new(Mutex::new(LiveCaptureState::default())),
                handle: tokio::spawn(async {}),
                start_note: Some(format!("live eBPF capture did not start: {err}")),
            });
        }
    };
    let seeds = if let Some(pid) = options.pid {
        seed_snapshot.seeds_for_pid_family(pid)
    } else if let Some(comm) = &options.comm {
        seed_snapshot.seeds_for_comm(comm)
    } else {
        seed_snapshot.seeds_for_all()
    };

    let mut runner = ProcessRunner::from_binary_extractor(binary_extractor.get_process_path())
        .with_args(args.iter().map(String::as_str))
        .with_seed_pids(&seeds);
    let state = Arc::new(Mutex::new(LiveCaptureState::default()));
    let state_for_task = Arc::clone(&state);

    let stream = match runner.run().await {
        Ok(stream) => stream,
        Err(err) => {
            return Some(LiveEbpfCapture {
                state,
                handle: tokio::spawn(async {}),
                start_note: Some(format!("live eBPF capture did not start: {err}")),
            });
        }
    };

    let handle = tokio::spawn(async move {
        consume_live_ebpf_stream(stream, state_for_task).await;
    });

    Some(LiveEbpfCapture {
        state,
        handle,
        start_note,
    })
}

fn prepare_live_ebpf_privileges() -> Result<Option<String>, String> {
    if unsafe { libc::geteuid() } == 0 {
        return Ok(Some("live eBPF process capture enabled".to_string()));
    }

    let cached = std::process::Command::new("sudo")
        .args(["-n", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if cached {
        return Ok(Some(
            "live eBPF process capture enabled via cached sudo".to_string(),
        ));
    }

    let interactive = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    if !interactive {
        return Err("live eBPF capture requires sudo; non-interactive top is showing /proc + local sessions only".to_string());
    }

    print_top_sudo_prompt();
    let ok = std::process::Command::new("sudo")
        .arg("-v")
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if ok {
        Ok(Some("live eBPF process capture enabled".to_string()))
    } else {
        Err("live eBPF capture did not start: sudo authentication failed".to_string())
    }
}

async fn consume_live_ebpf_stream(
    mut stream: crate::framework::runners::EventStream,
    state: Arc<Mutex<LiveCaptureState>>,
) {
    while let Some(event) = stream.next().await {
        record_live_ebpf_event(&state, &event);
    }
}

fn record_live_ebpf_event(state: &Arc<Mutex<LiveCaptureState>>, event: &Event) {
    let Ok(mut state) = state.lock() else {
        return;
    };
    state.events += 1;

    if event.source == "diagnostic" {
        if event.data.get("type").and_then(|value| value.as_str()) == Some("runner_parse_error") {
            state.parse_errors += 1;
        }
        return;
    }

    if let Some(path) = session_path_from_process_event(&event.data) {
        state
            .session_paths_by_pid
            .entry(event.pid)
            .or_default()
            .insert(path);
    }

    let Some(event_name) = event.data.get("event").and_then(|value| value.as_str()) else {
        return;
    };
    let kind = if event_name == "SUMMARY" {
        event
            .data
            .get("type")
            .and_then(|value| value.as_str())
            .unwrap_or(event_name)
    } else {
        event_name
    };
    let counters = state.by_pid.entry(event.pid).or_default();
    match kind {
        "EXEC" => counters.execs += 1,
        "EXIT" => {
            if event
                .data
                .get("exit_code")
                .and_then(|value| value.as_u64())
                .is_some_and(|code| code != 0)
            {
                counters.failures += 1;
            }
        }
        value if value.contains("FILE_") || value == "WRITE" => counters.files += 1,
        value if value.starts_with("NET_") => counters.network += 1,
        _ => {}
    }
}

fn session_path_from_process_event(data: &Value) -> Option<PathBuf> {
    let field = match data.get("event").and_then(|value| value.as_str())? {
        "FILE_OPEN" => "filepath",
        "SUMMARY"
            if data.get("type").and_then(|value| value.as_str()) == Some("WRITE")
                && data
                    .get("path_resolved")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false) =>
        {
            "detail"
        }
        _ => return None,
    };
    data.get(field)
        .and_then(|value| value.as_str())
        .and_then(local_sessions::session_log_path_from_str)
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

pub(crate) async fn run_live_top_query(
    binary_extractor: &BinaryExtractor,
    interval_secs: u64,
    limit: usize,
    count: Option<u32>,
    options: &TopOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let limit = limit.clamp(1, 100);
    let interval = Duration::from_secs(interval_secs.max(1));
    let mut iterations = 0u32;
    let should_clear_screen = count != Some(1);
    let mut live_view = LiveView::default();
    let capture = start_live_ebpf_capture(binary_extractor, options).await;

    loop {
        if should_clear_screen {
            clear_screen();
        }
        let mut top = live_view.refresh(capture.as_ref(), limit, options)?;
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

    if let Some(capture) = capture {
        capture.stop();
    }

    Ok(())
}

pub(crate) async fn run_live_top_tui(
    binary_extractor: &BinaryExtractor,
    interval_secs: u64,
    limit: usize,
    options: &TopOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let capture = start_live_ebpf_capture(binary_extractor, options).await;
    let result = run_live_top_tui_loop(interval_secs, limit, options, capture.as_ref());
    if let Some(capture) = capture {
        capture.stop();
    }
    result
}

struct LiveTopTerminalGuard;

impl LiveTopTerminalGuard {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, Hide)?;
        Ok(Self)
    }
}

impl Drop for LiveTopTerminalGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, Show, LeaveAlternateScreen);
    }
}

fn run_live_top_tui_loop(
    interval_secs: u64,
    limit: usize,
    options: &TopOptions,
    capture: Option<&LiveEbpfCapture>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut options = options.clone();
    let mut display_limit = limit.clamp(1, 100);
    let interval = Duration::from_secs(interval_secs.max(1));
    let _guard = LiveTopTerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut live_view = LiveView::default();
    let mut current_top: Option<AgentTopOutput<'static>> = None;
    let mut selected = 0usize;
    let mut paused = false;
    let mut show_help = false;
    let mut show_diagnostics = false;
    let mut last_refresh = Instant::now() - interval;
    let mut force_refresh = true;

    loop {
        if force_refresh
            || (!paused && (current_top.is_none() || last_refresh.elapsed() >= interval))
        {
            let mut top = live_view.refresh(capture, display_limit, &options)?;
            sort_agent_rows(&mut top.rows, &options.sort);
            top.rows.truncate(display_limit);
            clamp_selected(&mut selected, top.rows.len());
            current_top = Some(top);
            last_refresh = Instant::now();
            force_refresh = false;
        }

        let top = current_top
            .as_ref()
            .expect("live top TUI refreshes before first render");
        terminal.draw(|frame| {
            draw_live_top_tui(
                frame,
                top,
                selected,
                &options,
                paused,
                show_help,
                show_diagnostics,
                interval_secs,
                display_limit,
            );
        })?;

        if crate::shutdown_requested() {
            break;
        }

        let wait = if paused {
            Duration::from_millis(250)
        } else {
            interval
                .checked_sub(last_refresh.elapsed())
                .unwrap_or(Duration::ZERO)
                .min(Duration::from_millis(250))
        };
        if !event::poll(wait)? {
            continue;
        }
        let CrosstermEvent::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => break,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
            KeyCode::Char('?') => show_help = !show_help,
            KeyCode::Char('e') => show_diagnostics = !show_diagnostics,
            KeyCode::Char('p') => paused = !paused,
            KeyCode::Char('r') => force_refresh = true,
            KeyCode::Char('s') => {
                options.sort = next_sort_key(&options.sort);
                if let Some(top) = &mut current_top {
                    sort_agent_rows(&mut top.rows, &options.sort);
                    top.rows.truncate(display_limit);
                    clamp_selected(&mut selected, top.rows.len());
                }
            }
            KeyCode::Char('v') => options.view = next_view_key(&options.view),
            KeyCode::Char('+') | KeyCode::Char('=') => {
                display_limit = (display_limit + 1).min(100);
                force_refresh = true;
            }
            KeyCode::Char('-') => {
                display_limit = display_limit.saturating_sub(1).max(1);
                if let Some(top) = &mut current_top {
                    top.rows.truncate(display_limit);
                    clamp_selected(&mut selected, top.rows.len());
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(top) = &current_top
                    && selected + 1 < top.rows.len()
                {
                    selected += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                selected = selected.saturating_sub(1);
            }
            KeyCode::Home => selected = 0,
            KeyCode::End => {
                if let Some(top) = &current_top {
                    selected = top.rows.len().saturating_sub(1);
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn clamp_selected(selected: &mut usize, rows: usize) {
    if rows == 0 {
        *selected = 0;
    } else if *selected >= rows {
        *selected = rows - 1;
    }
}

fn normalize_sort_key(sort: &str) -> &'static str {
    match sort.to_ascii_lowercase().as_str() {
        "rss" | "mem" | "memory" => "rss",
        "tokens" | "token" => "tokens",
        "exec" | "execs" => "execs",
        "fail" | "fails" | "failure" | "failures" => "fail",
        "file" | "files" => "files",
        "net" | "network" => "net",
        "agent" | "name" | "command" => "agent",
        _ => "cpu",
    }
}

fn next_sort_key(current: &str) -> String {
    const SORTS: [&str; 8] = [
        "cpu", "rss", "tokens", "execs", "fail", "files", "net", "agent",
    ];
    let current = normalize_sort_key(current);
    let idx = SORTS
        .iter()
        .position(|value| *value == current)
        .unwrap_or(0);
    SORTS[(idx + 1) % SORTS.len()].to_string()
}

fn load_stat(db: &str) -> StorageResult<StatOutput> {
    let view = SqliteSource::open(db)?.into_view();
    let snapshot = view.export_snapshot(SnapshotOptions {
        audit_limit: 50_000,
    });
    let resources = resource_peaks_from_samples(view.resource_samples());
    let tool_calls = view.tool_call_count();
    let (input_tokens, output_tokens, total_tokens) = stat_token_totals(&snapshot);

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

fn stat_token_totals(snapshot: &Snapshot) -> (i64, i64, i64) {
    let local_sessions = local_sessions::from_snapshot(snapshot);
    if local_sessions.iter().any(LocalSession::has_tokens) {
        return (
            local_sessions
                .iter()
                .map(|session| session.input_tokens)
                .sum(),
            local_sessions
                .iter()
                .map(|session| session.output_tokens)
                .sum(),
            local_sessions
                .iter()
                .map(|session| session.total_tokens)
                .sum(),
        );
    }

    if snapshot.summary.total_tokens > 0
        || snapshot.summary.input_tokens > 0
        || snapshot.summary.output_tokens > 0
    {
        return (
            snapshot.summary.input_tokens,
            snapshot.summary.output_tokens,
            snapshot.summary.total_tokens,
        );
    }

    let input_tokens = snapshot.sessions.iter().map(|s| s.input_tokens).sum();
    let output_tokens = snapshot.sessions.iter().map(|s| s.output_tokens).sum();
    let total_tokens = snapshot.sessions.iter().map(|s| s.total_tokens).sum();
    (input_tokens, output_tokens, total_tokens)
}

fn build_session_top<'a>(
    db: &'a str,
    snapshot: &Snapshot,
    resources: &ResourcePeaks,
    limit: usize,
    options: &TopOptions,
) -> AgentTopOutput<'a> {
    let local_sessions = if options.pid.is_some() {
        Vec::new()
    } else {
        local_sessions::from_snapshot(snapshot)
            .into_iter()
            .filter(|session| {
                local_sessions::matches_filter(session, options.pid, options.comm.as_deref())
            })
            .collect()
    };
    let local_total_tokens = local_sessions::total_tokens(&local_sessions);
    let rows = session_agent_rows(snapshot, resources, options, &local_sessions);
    let sections = top_sections(snapshot, limit, &options.view, &local_sessions);
    let mut notes =
        vec!["static session view; run without --db for live /proc agent process top".to_string()];
    if !local_sessions.is_empty() {
        notes.push(
            "session tokens/tools come from touched local ~/.claude or ~/.codex logs".to_string(),
        );
    }
    if options.pid.is_some() || options.comm.is_some() {
        notes.push("filter applied before process-family aggregation".to_string());
    }
    AgentTopOutput {
        mode: "static session",
        db: Some(db),
        duration_s: duration_s(snapshot),
        view_events: snapshot.summary.view_events,
        llm_calls: snapshot.summary.llm_calls,
        total_tokens: if local_total_tokens > 0 {
            local_total_tokens
        } else {
            snapshot.summary.total_tokens
        },
        rows,
        sections,
        failures: recent_failures(snapshot, 5),
        notes,
    }
}

fn top_sections(
    snapshot: &Snapshot,
    limit: usize,
    view: &str,
    local_sessions: &[LocalSession],
) -> Vec<TopSection> {
    let audit = &snapshot.audit_events;
    let local_model_counts = local_sessions::model_token_counts(local_sessions);
    let model_counts = if local_model_counts.is_empty() {
        snapshot
            .token_summary
            .iter()
            .map(|row| (row.group.clone(), row.total_tokens))
            .collect()
    } else {
        local_model_counts
    };
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
    local_sessions: &[LocalSession],
) -> Vec<AgentTopRow> {
    let top_model =
        dominant_model(snapshot).or_else(|| local_sessions::dominant_model(local_sessions));
    let local_total_tokens = local_sessions::total_tokens(local_sessions);
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
        } else if local_total_tokens > 0 && !assigned_global_tokens {
            assigned_global_tokens = true;
            Some(local_total_tokens)
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

    if rows.is_empty() && !local_sessions.is_empty() {
        for session in local_sessions {
            if !options.matches(
                None,
                Some(&session.agent),
                session.prompt_preview.as_deref(),
            ) {
                continue;
            }
            rows.push(AgentTopRow {
                session: session.display_id.clone(),
                agent: session.agent.clone(),
                pid: None,
                model: session.model.clone().or_else(|| top_model.clone()),
                age_s: session.age_s(),
                cpu_percent: 0.0,
                rss_mb: 0,
                processes: 0,
                tokens: (session.total_tokens > 0).then_some(session.total_tokens),
                tools: session.tools_total(),
                execs: 0,
                failures: 0,
                files: 0,
                network: 0,
                unattributed: 0,
                trace: "local+db".to_string(),
                command: session
                    .prompt_preview
                    .clone()
                    .unwrap_or_else(|| session.path.display().to_string()),
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

fn collect_live_session_path_evidence(
    live_rows: &[AgentTopRow],
    sample: &LiveSample,
    capture: Option<&LiveCaptureSnapshot>,
) -> HashMap<u32, BTreeMap<PathBuf, &'static str>> {
    let children = sample.children_by_ppid();
    let mut out = HashMap::new();

    for row in live_rows {
        let Some(root_pid) = row.pid else {
            continue;
        };
        let family = procfs::process_family(root_pid, &children, &sample.procs);
        let mut evidence = BTreeMap::new();
        for pid in family {
            for path in scan_proc_fd_session_paths(pid) {
                evidence.entry(path).or_insert(TRACE_PROC_FD);
            }
            if let Some(capture) = capture
                && let Some(paths) = capture.session_paths_by_pid.get(&pid)
            {
                for path in paths {
                    evidence.insert(path.clone(), TRACE_EBPF_FILE);
                }
            }
        }
        if !evidence.is_empty() {
            out.insert(root_pid, evidence);
        }
    }

    out
}

fn scan_proc_fd_session_paths(pid: u32) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return out;
    };

    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        if let Some(path) = local_sessions::session_log_path_from_str(&target.to_string_lossy()) {
            out.insert(path);
        }
    }

    out
}

fn apply_live_capture(
    rows: &mut [AgentTopRow],
    sample: &LiveSample,
    capture: &LiveCaptureSnapshot,
) {
    if capture.events == 0 {
        return;
    }

    let children = sample.children_by_ppid();
    let mut attributed = HashSet::new();
    for row in rows.iter_mut() {
        let Some(root_pid) = row.pid else {
            continue;
        };
        let family = procfs::process_family(root_pid, &children, &sample.procs);
        let mut counters = CaptureCounters::default();
        for pid in family {
            if let Some(pid_counters) = capture.by_pid.get(&pid) {
                counters.add(*pid_counters);
                attributed.insert(pid);
            }
        }
        if counters.is_empty() {
            continue;
        }
        row.execs += counters.execs;
        row.failures += counters.failures;
        row.files += counters.files;
        row.network += counters.network;
        if !row.trace.contains("ebpf") {
            row.trace = format!("{}+ebpf", row.trace);
        }
    }

    let unattributed = capture
        .by_pid
        .iter()
        .filter(|(pid, counters)| !attributed.contains(pid) && !counters.is_empty())
        .count();
    if unattributed == 0 {
        return;
    }
    if let Some(row) = rows.iter_mut().find(|row| row.trace.contains("ebpf")) {
        row.unattributed += unattributed;
    }
}

fn live_process_rows(
    sample: &LiveSample,
    previous: Option<&LiveSample>,
    options: &TopOptions,
) -> Vec<AgentTopRow> {
    let roots = live_roots(sample, options);
    let children = sample.children_by_ppid();
    let mut rows = Vec::new();

    for root_pid in roots {
        let family = procfs::process_family(root_pid, &children, &sample.procs);
        if family.is_empty() {
            continue;
        }
        let root = sample.procs.get(&root_pid);
        let cpu_percent = family
            .iter()
            .filter_map(|pid| sample.procs.get(pid))
            .map(|proc_info| procfs::process_cpu_percent(proc_info, previous, sample))
            .sum();
        let rss_mb = family
            .iter()
            .filter_map(|pid| sample.procs.get(pid).map(|proc_info| proc_info.rss_mb))
            .sum();
        let agent = root
            .map(|proc_info| procfs::agent_name_from_command(&proc_info.comm, &proc_info.command))
            .unwrap_or_else(|| "agent".to_string());

        rows.push(AgentTopRow {
            session: format!("proc:{root_pid}"),
            agent,
            pid: Some(root_pid),
            model: None,
            age_s: root.map(|proc_info| procfs::process_age_s(proc_info, sample)),
            cpu_percent,
            rss_mb,
            processes: family.len(),
            tokens: None,
            tools: 0,
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

    rows
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
        return procfs::known_agent_label(&proc_info.comm, &proc_info.command).is_some();
    }
    options
        .comm
        .as_deref()
        .is_some_and(|comm| procfs::process_matches_comm(proc_info, comm))
}

fn live_matching_ancestor(proc_info: &ProcInfo, sample: &LiveSample, options: &TopOptions) -> bool {
    let current_label = procfs::known_agent_label(&proc_info.comm, &proc_info.command);
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
        } else if procfs::known_agent_label(&parent.comm, &parent.command) == current_label {
            return true;
        }
        parent_pid = parent.ppid;
    }
    false
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

fn discover_local_top_sessions(options: &TopOptions, limit: usize) -> Vec<LocalSession> {
    local_sessions::discover(limit)
        .into_iter()
        .filter(|session| {
            local_sessions::matches_filter(session, options.pid, options.comm.as_deref())
        })
        .collect()
}

fn load_snapshot_and_resources(db: &str) -> StorageResult<(Snapshot, ResourcePeaks)> {
    let view = SqliteSource::open(db)?.into_view();
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
    use crate::framework::core::Event;
    use crate::output::tui::{tui_diagnostic_lines, tui_status_line};
    use crate::view::types::{AuditEventRow, SnapshotSummary};
    use serde_json::json;
    use std::fs::File;

    fn create_temp_session_path(agent: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let base = match agent {
            "claude" => [".claude", "projects"],
            "codex" => [".codex", "sessions"],
            _ => unreachable!("test agent"),
        };
        let path = temp
            .path()
            .join(base[0])
            .join(base[1])
            .join("session.jsonl");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{}\n").unwrap();
        (temp, path)
    }

    fn test_live_sample(pid: u32, starttime_ticks: u64) -> LiveSample {
        LiveSample {
            at: Instant::now(),
            uptime_s: 100.0,
            procs: BTreeMap::from([(
                pid,
                ProcInfo {
                    pid,
                    ppid: 0,
                    session_id: pid,
                    comm: "claude".to_string(),
                    command: "claude".to_string(),
                    ticks: 0,
                    starttime_ticks,
                    rss_kb: 0,
                    rss_mb: 0,
                    vsz_kb: 0,
                    threads: 1,
                },
            )]),
        }
    }

    #[test]
    fn record_live_ebpf_event_tracks_only_resolved_session_paths() {
        let (_claude_temp, claude_path) = create_temp_session_path("claude");
        let (_codex_temp, codex_path) = create_temp_session_path("codex");
        let state = Arc::new(Mutex::new(LiveCaptureState::default()));

        for (pid, comm, data) in [
            (
                42,
                "claude",
                json!({
                    "timestamp": 1,
                    "event": "FILE_OPEN",
                    "comm": "claude",
                    "pid": 42,
                    "filepath": claude_path,
                    "flags": 1
                }),
            ),
            (
                7,
                "codex",
                json!({
                    "timestamp": 1,
                    "event": "SUMMARY",
                    "comm": "codex",
                    "pid": 7,
                    "type": "WRITE",
                    "detail": codex_path,
                    "path_resolved": true,
                    "count": 3
                }),
            ),
            (
                9,
                "codex",
                json!({
                "timestamp": 1,
                "event": "SUMMARY",
                "comm": "codex",
                "pid": 9,
                "type": "WRITE",
                "detail": "fd=3",
                "path_resolved": false,
                "count": 1
                }),
            ),
        ] {
            record_live_ebpf_event(
                &state,
                &Event::new_with_timestamp(1, "process".to_string(), pid, comm.to_string(), data),
            );
        }

        let snapshot = state.lock().unwrap();
        assert_eq!(snapshot.by_pid.get(&42).unwrap().files, 1);
        assert_eq!(snapshot.by_pid.get(&7).unwrap().files, 1);
        assert_eq!(snapshot.by_pid.get(&9).unwrap().files, 1);
        assert!(
            snapshot.session_paths_by_pid[&42]
                .contains(&local_sessions::normalize_session_log_path(&claude_path))
        );
        assert!(
            snapshot.session_paths_by_pid[&7]
                .contains(&local_sessions::normalize_session_log_path(&codex_path))
        );
        assert!(!snapshot.session_paths_by_pid.contains_key(&9));
    }

    #[test]
    fn proc_fd_scan_finds_open_session_jsonl() {
        let (_temp, path) = create_temp_session_path("claude");
        let _file = File::open(&path).unwrap();

        let paths = scan_proc_fd_session_paths(std::process::id());
        assert!(paths.contains(&local_sessions::normalize_session_log_path(&path)));
    }

    #[test]
    fn local_session_binding_sticks_after_initial_path_evidence() {
        let (_temp, path) = create_temp_session_path("claude");

        let session = local_sessions::parse_content(
            "claude",
            &path,
            std::time::UNIX_EPOCH,
            "{\"type\":\"result\",\"modelUsage\":{\"claude-opus\":{\"inputTokens\":1,\"outputTokens\":0}}}\n",
        )
        .unwrap();
        let row = AgentTopRow {
            session: "proc:1".to_string(),
            agent: "claude".to_string(),
            pid: Some(1),
            model: None,
            age_s: Some(30.0),
            cpu_percent: 0.0,
            rss_mb: 0,
            processes: 1,
            tokens: None,
            tools: 0,
            execs: 0,
            failures: 0,
            files: 0,
            network: 0,
            unattributed: 0,
            trace: "proc".to_string(),
            command: "claude".to_string(),
        };
        let sample = test_live_sample(1, 10);
        let mut bindings = LiveSessionBindings::default();

        assert_eq!(
            bindings.link_trace(&session, &row, &sample, &HashMap::new()),
            None
        );

        let mut evidence = BTreeMap::new();
        evidence.insert(
            local_sessions::normalize_session_log_path(&path),
            TRACE_PROC_FD,
        );
        let path_evidence = HashMap::from([(1, evidence)]);

        assert_eq!(
            bindings.link_trace(&session, &row, &sample, &path_evidence),
            Some(TRACE_PROC_FD)
        );
        assert_eq!(
            bindings.link_trace(&session, &row, &sample, &HashMap::new()),
            Some(TRACE_STICKY_BINDING)
        );
        assert_eq!(
            bindings.link_trace(&session, &row, &test_live_sample(1, 11), &HashMap::new()),
            None
        );
    }

    #[test]
    fn tui_status_compacts_source_notes() {
        let top = AgentTopOutput {
            mode: "live sessions",
            db: None,
            duration_s: 0.0,
            view_events: 0,
            llm_calls: 0,
            total_tokens: 15,
            rows: vec![AgentTopRow {
                session: "codex:test".to_string(),
                agent: "codex".to_string(),
                pid: Some(42),
                model: Some("gpt-smoke".to_string()),
                age_s: Some(1.0),
                cpu_percent: 0.0,
                rss_mb: 0,
                processes: 1,
                tokens: Some(15),
                tools: 1,
                execs: 0,
                failures: 0,
                files: 0,
                network: 0,
                unattributed: 0,
                trace: "local+proc+ebpf_file".to_string(),
                command: "codex".to_string(),
            }],
            sections: Vec::new(),
            failures: Vec::new(),
            notes: vec![
                "session tokens/tools come from local ~/.claude or ~/.codex logs".to_string(),
                "proc evidence uses /proc for CPU/RSS/process families".to_string(),
                "live eBPF capture did not start: sudo unavailable".to_string(),
            ],
        };

        assert_eq!(
            tui_status_line(&top),
            "local logs | /proc | eBPF | session path linked | tokens 15"
        );
        assert_eq!(
            tui_diagnostic_lines(&top, 1),
            vec!["live eBPF capture did not start: sudo unavailable".to_string()]
        );
    }

    #[test]
    fn stat_tokens_fall_back_to_agent_sessions() {
        let snapshot = Snapshot {
            schema_version: 1,
            generated_at: "now".to_string(),
            summary: SnapshotSummary {
                source: "sqlite".to_string(),
                view_events: 0,
                llm_calls: 1,
                token_usage_rows: 0,
                audit_events: 0,
                sessions: 1,
                input_tokens: 0,
                output_tokens: 0,
                total_tokens: 0,
                start_timestamp_ms: None,
                end_timestamp_ms: None,
                audit_limit: 0,
            },
            token_summary: Vec::new(),
            network_targets: Vec::new(),
            audit_events: Vec::new(),
            sessions: vec![SessionRow {
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
            }],
            agents: Vec::new(),
        };

        assert_eq!(stat_token_totals(&snapshot), (3, 10, 27667));
    }

    #[test]
    fn stat_tokens_ignore_touched_local_log_without_usage() {
        let (_temp, path) = create_temp_session_path("claude");
        std::fs::write(
            &path,
            "{\"type\":\"user\",\"message\":{\"content\":\"local prompt only\"}}\n",
        )
        .unwrap();

        let snapshot = Snapshot {
            schema_version: 1,
            generated_at: "now".to_string(),
            summary: SnapshotSummary {
                source: "sqlite".to_string(),
                view_events: 0,
                llm_calls: 1,
                token_usage_rows: 1,
                audit_events: 1,
                sessions: 0,
                input_tokens: 8,
                output_tokens: 5,
                total_tokens: 13,
                start_timestamp_ms: None,
                end_timestamp_ms: None,
                audit_limit: 0,
            },
            token_summary: Vec::new(),
            network_targets: Vec::new(),
            audit_events: vec![AuditEventRow {
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
            }],
            sessions: Vec::new(),
            agents: Vec::new(),
        };

        assert_eq!(stat_token_totals(&snapshot), (8, 5, 13));
    }
}
