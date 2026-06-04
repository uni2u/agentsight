// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use super::sort_agent_rows;
use crate::framework::analyzers::TimestampNormalizer;
use crate::framework::binary_extractor::BinaryExtractor;
use crate::framework::core::Event;
use crate::framework::runners::{ProcessRunner, Runner};
use crate::output::{
    AgentTopOutput, AgentTopRow, TopOptions, clear_screen, draw_live_top_tui, next_view_key,
    print_agent_top, print_top_sudo_prompt,
};
use crate::sources::proc::{self as procfs, ProcInfo, ProcSnapshot as LiveSample};
use crate::sources::session as local_sessions;
use crate::view::MaterializedView;
use crate::view::types::{AuditCounters, SessionRow, Snapshot, SnapshotOptions};
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
use std::path::{Path, PathBuf};
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

#[derive(Debug, Clone)]
struct LiveCaptureSnapshot {
    by_pid: HashMap<u32, CaptureCounters>,
    session_paths_by_pid: HashMap<u32, BTreeSet<PathBuf>>,
    snapshot: Snapshot,
    parse_errors: u64,
}

impl Default for LiveCaptureSnapshot {
    fn default() -> Self {
        Self {
            by_pid: HashMap::new(),
            session_paths_by_pid: HashMap::new(),
            snapshot: Snapshot::empty("live_capture"),
            parse_errors: 0,
        }
    }
}

struct LiveCaptureState {
    session_paths_by_pid: HashMap<u32, BTreeSet<PathBuf>>,
    view: MaterializedView,
    parse_errors: u64,
}

impl Default for LiveCaptureState {
    fn default() -> Self {
        Self {
            session_paths_by_pid: HashMap::new(),
            view: MaterializedView::new(),
            parse_errors: 0,
        }
    }
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
        session_path: &Path,
        row: &AgentTopRow,
        sample: &LiveSample,
        path_evidence: &HashMap<u32, BTreeMap<PathBuf, &'static str>>,
    ) -> Option<&'static str> {
        let pid = row.pid?;
        let proc_info = sample.procs.get(&pid)?;
        let path = local_sessions::normalize_session_log_path(session_path);

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
        let snapshot = state.view.export_snapshot(SnapshotOptions {
            audit_limit: 10_000,
        });
        LiveCaptureSnapshot {
            by_pid: capture_counters_by_pid(&snapshot),
            session_paths_by_pid: state.session_paths_by_pid.clone(),
            snapshot,
            parse_errors: state.parse_errors,
        }
    }

    fn stop(self) {
        self.handle.abort();
    }
}

struct LiveView {
    previous: Option<LiveSample>,
    bindings: LiveSessionBindings,
    session_cache: local_sessions::SessionCache,
    fd_cache: HashMap<(u32, u64), BTreeSet<PathBuf>>,
}

impl Default for LiveView {
    fn default() -> Self {
        Self {
            previous: None,
            bindings: LiveSessionBindings::default(),
            session_cache: local_sessions::SessionCache::new(),
            fd_cache: HashMap::new(),
        }
    }
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
        let session_snapshot = self.session_cache.snapshot(options, limit);
        let mut top = self.build_top(
            &sample,
            capture_snapshot.as_ref(),
            &session_snapshot,
            options,
        );
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
        session_snapshot: &Snapshot,
        options: &TopOptions,
    ) -> AgentTopOutput<'a> {
        let children = sample.children_by_ppid();
        let mut live_rows = live_process_rows(sample, self.previous.as_ref(), options, &children);
        sort_agent_rows(&mut live_rows, "cpu");
        let path_evidence = collect_live_session_path_evidence(
            &live_rows,
            sample,
            capture,
            &children,
            &mut self.fd_cache,
        );
        self.bindings.retain_live(&live_rows, sample);
        let mut used_live_pids = HashSet::new();
        let mut rows = Vec::new();

        for session in &session_snapshot.sessions {
            let session_path = session_attr(session, "path").map(PathBuf::from);
            let live_match = live_rows.iter().enumerate().find_map(|(idx, row)| {
                if row.pid.is_some_and(|pid| used_live_pids.contains(&pid))
                    || row.agent != session.agent_type
                    || !options.matches(row.pid, Some(&row.agent), Some(&row.command))
                {
                    return None;
                }
                let path = session_path.as_deref()?;
                self.bindings
                    .link_trace(path, row, sample, &path_evidence)
                    .map(|trace| (idx, trace))
            });
            let live = live_match
                .and_then(|(idx, trace)| live_rows.get(idx).cloned().map(|row| (row, trace)));
            if options.pid.is_some() && live.is_none() {
                continue;
            }
            if let Some(pid) = live.as_ref().and_then(|(row, _)| row.pid) {
                used_live_pids.insert(pid);
            }
            let command = session_attr(session, "prompt_preview")
                .map(ToString::to_string)
                .or_else(|| live.as_ref().map(|(row, _)| row.command.clone()))
                .or_else(|| session_path.as_ref().map(|path| path.display().to_string()))
                .unwrap_or_else(|| session.id.clone());
            let trace = if let Some((_, link_trace)) = &live {
                format!("agent-native+proc+{link_trace}")
            } else {
                "agent-native".to_string()
            };
            let age_s = live
                .as_ref()
                .and_then(|(row, _)| row.age_s)
                .or_else(|| session_age_s(session));
            rows.push(AgentTopRow {
                session: session_attr(session, "display_id")
                    .unwrap_or(session.id.as_str())
                    .to_string(),
                agent: session.agent_type.clone(),
                pid: live.as_ref().and_then(|(row, _)| row.pid),
                model: session.model.clone(),
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
                tools: session
                    .attributes
                    .get("tools_total")
                    .and_then(Value::as_u64)
                    .unwrap_or_default() as usize,
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
            apply_live_capture(&mut rows, sample, capture, &children);
        }

        let local_summary = &session_snapshot.summary;
        let local_total_tokens = local_summary.total_tokens;
        let capture_summary = capture.map(|capture| &capture.snapshot.summary);
        let capture_total_tokens = capture
            .map(|capture| capture.snapshot.summary.total_tokens)
            .unwrap_or_default();
        let has_agent_native = rows.iter().any(|row| row.trace.contains("agent-native"));
        let has_proc = rows.iter().any(|row| row.trace.contains("proc"));
        let has_ebpf = rows.iter().any(|row| row.trace.contains("ebpf"));
        let has_session_file_link = rows.iter().any(|row| {
            row.trace.contains("ebpf_file")
                || row.trace.contains("proc_fd")
                || row.trace.contains("sticky")
        });
        let mut notes = Vec::new();
        if has_agent_native {
            notes.push(
                "agent-native sessions are the primary token/tool source (~/.claude, ~/.codex)"
                    .to_string(),
            );
        }
        if has_proc {
            notes.push("proc evidence uses /proc for CPU/RSS/process families".to_string());
        }
        if has_session_file_link {
            notes.push("agent-native sessions bind to live pids after the process touches the matching session path; binding stays until pid exits or a new session path is observed".to_string());
        }
        if has_ebpf {
            notes.push(
                "ebpf evidence is live process capture; SSL/network details still require record/stat"
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
                    "no active process or agent-native session matched the filter; try another -p/-c value or inspect a saved session with --db"
                        .to_string(),
                );
            } else {
                notes.push(
                    "no active known agent process or agent-native Claude/Codex session found; use -c/-p, run an agent, or pass --db"
                        .to_string(),
                );
            }
        }

        AgentTopOutput {
            mode: "live sessions",
            db: None,
            duration_s: 0.0,
            view_events: local_summary.view_events
                + capture_summary
                    .map(|summary| summary.view_events)
                    .unwrap_or_default(),
            llm_calls: local_summary.llm_calls
                + capture_summary
                    .map(|summary| summary.llm_calls)
                    .unwrap_or_default(),
            total_tokens: local_total_tokens + capture_total_tokens,
            rows,
            sections: Vec::new(),
            failures: Vec::new(),
            notes,
        }
    }
}

fn session_age_s(session: &SessionRow) -> Option<f64> {
    let timestamp_ms = session
        .end_timestamp_ms
        .or(Some(session.start_timestamp_ms))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as u64;
    now_ms
        .checked_sub(timestamp_ms)
        .map(|age_ms| age_ms as f64 / 1000.0)
}

fn session_attr<'a>(session: &'a SessionRow, key: &str) -> Option<&'a str> {
    session
        .attributes
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
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
    runner = runner.add_analyzer(Box::new(TimestampNormalizer::new()));
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
        return Err("live eBPF capture requires sudo; non-interactive top is showing /proc + agent-native sessions only".to_string());
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
    if let Err(error) = state.view.ingest_event(event) {
        log::warn!("live eBPF capture failed to ingest view event: {}", error);
    }

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
}

fn capture_counters_by_pid(snapshot: &Snapshot) -> HashMap<u32, CaptureCounters> {
    AuditCounters::by_pid(&snapshot.audit_events)
        .into_iter()
        .map(|(pid, counters)| {
            (
                pid,
                CaptureCounters {
                    execs: counters.process_execs,
                    failures: counters.process_exit_failure,
                    files: counters.file_events,
                    network: counters.network_events,
                },
            )
        })
        .collect()
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

fn collect_live_session_path_evidence(
    live_rows: &[AgentTopRow],
    sample: &LiveSample,
    capture: Option<&LiveCaptureSnapshot>,
    children: &HashMap<u32, Vec<u32>>,
    fd_cache: &mut HashMap<(u32, u64), BTreeSet<PathBuf>>,
) -> HashMap<u32, BTreeMap<PathBuf, &'static str>> {
    let mut out = HashMap::new();
    let mut live_keys = HashSet::new();

    for row in live_rows {
        let Some(root_pid) = row.pid else {
            continue;
        };
        let family = procfs::process_family(root_pid, children, &sample.procs);
        let mut evidence = BTreeMap::new();
        for pid in family {
            let starttime = sample
                .procs
                .get(&pid)
                .map(|p| p.starttime_ticks)
                .unwrap_or(0);
            let key = (pid, starttime);
            live_keys.insert(key);
            let paths = fd_cache
                .entry(key)
                .or_insert_with(|| scan_proc_fd_session_paths(pid));
            for path in paths.iter() {
                evidence.entry(path.clone()).or_insert(TRACE_PROC_FD);
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

    fd_cache.retain(|key, _| live_keys.contains(key));
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
    children: &HashMap<u32, Vec<u32>>,
) {
    if capture.by_pid.is_empty() {
        return;
    }

    let mut attributed = HashSet::new();
    for row in rows.iter_mut() {
        let Some(root_pid) = row.pid else {
            continue;
        };
        let family = procfs::process_family(root_pid, children, &sample.procs);
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
    children: &HashMap<u32, Vec<u32>>,
) -> Vec<AgentTopRow> {
    let roots = live_roots(sample, options);
    let mut rows = Vec::new();

    for root_pid in roots {
        let family = procfs::process_family(root_pid, children, &sample.procs);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tui::{tui_diagnostic_lines, tui_status_line};
    use serde_json::json;
    use std::fs::File;

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
        let (_claude_temp, claude_path) = local_sessions::create_temp_session_path("claude");
        let (_codex_temp, codex_path) = local_sessions::create_temp_session_path("codex");
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
        let view_snapshot = snapshot.view.export_snapshot(SnapshotOptions {
            audit_limit: 10_000,
        });
        let counters = capture_counters_by_pid(&view_snapshot);
        assert_eq!(counters.get(&42).unwrap().files, 1);
        assert_eq!(counters.get(&7).unwrap().files, 1);
        assert_eq!(counters.get(&9).unwrap().files, 1);
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
        let (_temp, path) = local_sessions::create_temp_session_path("claude");
        let _file = File::open(&path).unwrap();

        let paths = scan_proc_fd_session_paths(std::process::id());
        assert!(paths.contains(&local_sessions::normalize_session_log_path(&path)));
    }

    #[test]
    fn local_session_binding_sticks_after_initial_path_evidence() {
        let (_temp, path) = local_sessions::create_temp_session_path("claude");
        let session_path = local_sessions::normalize_session_log_path(&path);
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
            bindings.link_trace(&session_path, &row, &sample, &HashMap::new()),
            None
        );

        let mut evidence = BTreeMap::new();
        evidence.insert(session_path.clone(), TRACE_PROC_FD);
        let path_evidence = HashMap::from([(1, evidence)]);

        assert_eq!(
            bindings.link_trace(&session_path, &row, &sample, &path_evidence),
            Some(TRACE_PROC_FD)
        );
        assert_eq!(
            bindings.link_trace(&session_path, &row, &sample, &HashMap::new()),
            Some(TRACE_STICKY_BINDING)
        );
        assert_eq!(
            bindings.link_trace(
                &session_path,
                &row,
                &test_live_sample(1, 11),
                &HashMap::new()
            ),
            None
        );
    }

    #[test]
    fn pid_filter_does_not_show_unbound_local_sessions() {
        let (_temp, path) = local_sessions::create_temp_session_path("claude");
        let session = local_sessions::parse_content(
            "claude",
            &path,
            std::time::UNIX_EPOCH,
            "{\"type\":\"result\",\"modelUsage\":{\"claude-opus\":{\"inputTokens\":3,\"outputTokens\":4}}}\n",
        )
        .unwrap();
        let local_sessions = vec![session];
        let session_snapshot = local_sessions::materialized_view(&local_sessions)
            .export_snapshot(SnapshotOptions { audit_limit: 10 });
        let options = TopOptions {
            pid: Some(1),
            comm: None,
            sort: "cpu".to_string(),
            view: "all".to_string(),
        };

        let mut live_view = LiveView::default();
        let top = live_view.build_top(&test_live_sample(1, 10), None, &session_snapshot, &options);

        assert_eq!(top.rows.len(), 1);
        assert_eq!(top.rows[0].pid, Some(1));
        assert_eq!(top.rows[0].trace, "proc");
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
                trace: "agent-native+proc+ebpf_file".to_string(),
                command: "codex".to_string(),
            }],
            sections: Vec::new(),
            failures: Vec::new(),
            notes: vec![
                "agent-native sessions are the primary token/tool source (~/.claude, ~/.codex)"
                    .to_string(),
                "proc evidence uses /proc for CPU/RSS/process families".to_string(),
                "live eBPF capture did not start: sudo unavailable".to_string(),
            ],
        };

        assert_eq!(
            tui_status_line(&top),
            "agent-native | /proc | eBPF | session path linked | tokens 15"
        );
        assert_eq!(
            tui_diagnostic_lines(&top, 1),
            vec!["live eBPF capture did not start: sudo unavailable".to_string()]
        );
    }
}
