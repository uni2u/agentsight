// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::cli_output::{
    AgentTopOutput, AgentTopRow, ResourcePeaks, StatOutput, TopSection, clear_screen,
    print_agent_top, print_json, print_stat,
};
use crate::framework::binary_extractor::BinaryExtractor;
use crate::framework::core::Event;
use crate::framework::runners::{ProcessRunner, Runner};
use crate::framework::storage::{
    SnapshotOptions, SqliteStore,
    sqlite::{SessionRow, Snapshot, StorageResult},
};
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event as CrosstermEvent, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt;
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone)]
pub(crate) struct TopOptions {
    pub(crate) pid: Option<u32>,
    pub(crate) comm: Option<String>,
    pub(crate) sort: String,
    pub(crate) view: String,
}

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
    events: u64,
    parse_errors: u64,
}

#[derive(Default)]
struct LiveCaptureState {
    by_pid: HashMap<u32, CaptureCounters>,
    events: u64,
    parse_errors: u64,
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
            events: state.events,
            parse_errors: state.parse_errors,
        }
    }

    fn start_note(&self) -> Option<String> {
        self.start_note.clone()
    }

    fn stop(self) {
        self.handle.abort();
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

    let mut runner = ProcessRunner::from_binary_extractor(binary_extractor.get_process_path())
        .with_args(args.iter().map(String::as_str));
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

    eprintln!("🔑 top live eBPF capture requires root. Requesting sudo access...");
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

    let Some(kind) = event.data.get("event").and_then(|value| value.as_str()) else {
        return;
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
    let mut previous: Option<LiveSample> = None;
    let capture = start_live_ebpf_capture(binary_extractor, options).await;

    loop {
        let sample = LiveSample::collect()?;
        if should_clear_screen {
            clear_screen();
        }
        let capture_snapshot = capture.as_ref().map(LiveEbpfCapture::snapshot);
        let mut top = build_live_top(
            &sample,
            previous.as_ref(),
            capture_snapshot.as_ref(),
            limit,
            options,
        );
        if let Some(capture) = &capture
            && let Some(note) = capture.start_note()
        {
            top.notes.push(note);
        }
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

    let mut previous: Option<LiveSample> = None;
    let mut current_top: Option<AgentTopOutput<'static>> = None;
    let mut selected = 0usize;
    let mut paused = false;
    let mut show_help = false;
    let mut last_refresh = Instant::now() - interval;
    let mut force_refresh = true;

    loop {
        if force_refresh
            || (!paused && (current_top.is_none() || last_refresh.elapsed() >= interval))
        {
            current_top = Some(refresh_live_top(
                &mut previous,
                capture,
                display_limit,
                &options,
                &mut selected,
            )?);
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

fn refresh_live_top(
    previous: &mut Option<LiveSample>,
    capture: Option<&LiveEbpfCapture>,
    limit: usize,
    options: &TopOptions,
    selected: &mut usize,
) -> io::Result<AgentTopOutput<'static>> {
    let sample = LiveSample::collect()?;
    let capture_snapshot = capture.map(LiveEbpfCapture::snapshot);
    let mut top: AgentTopOutput<'static> = build_live_top(
        &sample,
        previous.as_ref(),
        capture_snapshot.as_ref(),
        limit,
        options,
    );
    if let Some(capture) = capture
        && let Some(note) = capture.start_note()
    {
        top.notes.push(note);
    }
    sort_agent_rows(&mut top.rows, &options.sort);
    top.rows.truncate(limit);
    clamp_selected(selected, top.rows.len());
    *previous = Some(sample);
    Ok(top)
}

fn clamp_selected(selected: &mut usize, rows: usize) {
    if rows == 0 {
        *selected = 0;
    } else if *selected >= rows {
        *selected = rows - 1;
    }
}

fn draw_live_top_tui(
    frame: &mut Frame<'_>,
    top: &AgentTopOutput<'_>,
    selected: usize,
    options: &TopOptions,
    paused: bool,
    show_help: bool,
    interval_secs: u64,
    display_limit: usize,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(8),
            Constraint::Length(5),
        ])
        .split(frame.area());

    render_top_summary(
        frame,
        chunks[0],
        top,
        options,
        paused,
        interval_secs,
        display_limit,
    );
    render_session_table(frame, chunks[1], top, selected);
    render_session_detail(frame, chunks[2], top, selected, options);
    render_top_footer(frame, chunks[3], top);

    if show_help {
        render_top_help(frame);
    }
}

fn render_top_summary(
    frame: &mut Frame<'_>,
    area: Rect,
    top: &AgentTopOutput<'_>,
    options: &TopOptions,
    paused: bool,
    interval_secs: u64,
    display_limit: usize,
) {
    let state = if paused { "paused" } else { "running" };
    let filter = top_filter_label(options);
    let lines = vec![
        Line::from(vec![
            Span::styled(
                "AgentSight top",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  mode={}  state={}  refresh={}s  rows={}/{}",
                top.mode,
                state,
                interval_secs.max(1),
                top.rows.len(),
                display_limit
            )),
        ]),
        Line::from(vec![
            Span::styled("sort ", label_style()),
            Span::raw(options.sort.clone()),
            Span::raw("  "),
            Span::styled("view ", label_style()),
            Span::raw(options.view.clone()),
            Span::raw("  "),
            Span::styled("filter ", label_style()),
            Span::raw(filter),
            Span::raw("  "),
            Span::styled("session tokens ", label_style()),
            Span::raw(format_token_value(Some(top.total_tokens))),
        ]),
        Line::from(vec![
            Span::styled("evidence ", label_style()),
            Span::raw(evidence_summary(top)),
        ]),
    ];
    let block = Block::default().borders(Borders::ALL);
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_session_table(
    frame: &mut Frame<'_>,
    area: Rect,
    top: &AgentTopOutput<'_>,
    selected: usize,
) {
    let header = Row::new(vec![
        Cell::from("SESSION"),
        Cell::from("AGENT"),
        Cell::from("STATE"),
        Cell::from("AGE"),
        Cell::from("MODEL"),
        Cell::from("TOKENS"),
        Cell::from("HEALTH"),
        Cell::from("ACTIVITY"),
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .bottom_margin(1);

    let rows = top.rows.iter().map(|row| {
        Row::new(vec![
            Cell::from(truncate_text(&row.session, 16)),
            Cell::from(truncate_text(&row.agent, 8)),
            Cell::from(row.state_label()),
            Cell::from(row.age_label()),
            Cell::from(truncate_text(&row.model_label(), 14)),
            Cell::from(row.token_label()),
            Cell::from(row.health_label()),
            Cell::from(truncate_text(&tui_activity_label(row), 48)),
        ])
        .style(row_style(row))
    });

    let widths = [
        Constraint::Length(16),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Length(14),
        Constraint::Length(9),
        Constraint::Length(12),
        Constraint::Min(12),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().title("sessions").borders(Borders::ALL))
        .column_spacing(1)
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    let mut state = TableState::default();
    if !top.rows.is_empty() {
        state.select(Some(selected));
    }
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_session_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    top: &AgentTopOutput<'_>,
    selected: usize,
    options: &TopOptions,
) {
    let title = format!("selected session - {}", normalize_view_key(&options.view));
    let lines = if let Some(row) = top.rows.get(selected) {
        session_detail_lines(row, options)
    } else {
        vec![
            Line::from("No active agent session matched this view."),
            Line::from("Run an agent, pass -c/-p, or inspect a saved session with top --db."),
        ]
    };
    let block = Block::default().title(title).borders(Borders::ALL);
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn render_top_footer(frame: &mut Frame<'_>, area: Rect, top: &AgentTopOutput<'_>) {
    let mut lines = vec![Line::from(vec![
        Span::styled("keys ", label_style()),
        Span::raw(
            "q quit | up/down select | s sort | v view | p pause | r refresh | +/- rows | ? help",
        ),
    ])];
    for note in top.notes.iter().take(3) {
        lines.push(Line::from(note.clone()));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title("status").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_top_help(frame: &mut Frame<'_>) {
    let area = centered_rect(62, 52, frame.area());
    frame.render_widget(Clear, area);
    let lines = vec![
        Line::from(vec![Span::styled(
            "AgentSight top keys",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from("q or Esc       exit"),
        Line::from("up/down, k/j   select a session"),
        Line::from("s              cycle sort: cpu, rss, tokens, execs, fail, files, net, agent"),
        Line::from("v              cycle detail view: all, processes, files, network, models"),
        Line::from("p              pause or resume refresh"),
        Line::from("r              refresh now"),
        Line::from("+/-            change row limit"),
        Line::from("?              close this help"),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title("help").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn session_detail_lines(row: &AgentTopRow, options: &TopOptions) -> Vec<Line<'static>> {
    match normalize_view_key(&options.view).as_str() {
        "processes" => vec![
            detail_line("session", row.session.clone()),
            detail_line("agent", format!("{} ({})", row.agent, row.state_label())),
            detail_line(
                "root pid",
                row.pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            detail_line("age", row.age_label()),
            detail_line("processes", row.processes.to_string()),
            detail_line("cpu", format!("{:.1}%", row.cpu_percent)),
            detail_line("rss", format!("{} MB", row.rss_mb)),
            detail_line("command", row.command.clone()),
        ],
        "files" => vec![
            detail_line("session", row.session.clone()),
            detail_line("evidence", row.evidence_label()),
            detail_line("execs", row.execs.to_string()),
            detail_line("failures", row.failures.to_string()),
            detail_line("file events", row.files.to_string()),
            detail_line("unattributed ebpf pids", row.unattributed.to_string()),
            detail_line("trace", row.trace.clone()),
            detail_line("command", row.command.clone()),
        ],
        "network" => vec![
            detail_line("session", row.session.clone()),
            detail_line("evidence", row.evidence_label()),
            detail_line("network events", row.network.to_string()),
            detail_line("tokens", format_token_value(row.tokens)),
            detail_line("tools", row.tools.to_string()),
            detail_line("trace", row.trace.clone()),
            detail_line("command", row.command.clone()),
        ],
        "models" => vec![
            detail_line("session", row.session.clone()),
            detail_line("agent", row.agent.clone()),
            detail_line("model", row.model_label()),
            detail_line("tokens", row.token_label()),
            detail_line("tools", row.tools.to_string()),
            detail_line("prompt or command", row.command.clone()),
        ],
        _ => vec![
            detail_line("session", row.session.clone()),
            detail_line(
                "agent",
                format!(
                    "{}  state={}  pid={}",
                    row.agent,
                    row.state_label(),
                    row.pid
                        .map(|pid| pid.to_string())
                        .unwrap_or_else(|| "-".to_string())
                ),
            ),
            detail_line("model", row.model_label()),
            detail_line("age", row.age_label()),
            detail_line("evidence", row.evidence_label()),
            detail_line("session tokens", row.token_label()),
            detail_line(
                "resources",
                format!(
                    "cpu={:.1}% rss={} MB processes={}",
                    row.cpu_percent, row.rss_mb, row.processes
                ),
            ),
            detail_line(
                "activity",
                format!(
                    "processes={} tools={} execs={} failures={} files={} network={}",
                    row.processes, row.tools, row.execs, row.failures, row.files, row.network
                ),
            ),
            detail_line("unattributed ebpf pids", row.unattributed.to_string()),
            detail_line("trace", row.trace.clone()),
            detail_line("prompt or command", row.command.clone()),
        ],
    }
}

fn detail_line(label: &'static str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), label_style()),
        Span::raw(value),
    ])
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn label_style() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

fn tui_activity_label(row: &AgentTopRow) -> String {
    let mut parts = Vec::new();
    if row.processes > 0 {
        parts.push(format!("{} proc", format_compact_i64(row.processes as i64)));
    }
    if row.tools > 0 {
        parts.push(format!("{} tool", format_compact_i64(row.tools as i64)));
    }
    if row.execs > 0 {
        parts.push(format!("{} exec", format_compact_i64(row.execs as i64)));
    }
    if row.failures > 0 {
        parts.push(format!("{} fail", format_compact_i64(row.failures as i64)));
    }
    if row.files > 0 {
        parts.push(format!("{} file", format_compact_i64(row.files as i64)));
    }
    if row.network > 0 {
        parts.push(format!("{} net", format_compact_i64(row.network as i64)));
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(", ")
    }
}

fn row_style(row: &AgentTopRow) -> Style {
    if row.failures > 0 {
        Style::default().fg(Color::Red)
    } else if row.trace.contains("ebpf") {
        Style::default().fg(Color::Green)
    } else if row.trace.contains("local") {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    }
}

fn evidence_summary(top: &AgentTopOutput<'_>) -> String {
    let local = top
        .rows
        .iter()
        .filter(|row| row.trace.contains("local"))
        .count();
    let proc_rows = top
        .rows
        .iter()
        .filter(|row| row.trace.contains("proc"))
        .count();
    let ebpf = top
        .rows
        .iter()
        .filter(|row| row.trace.contains("ebpf"))
        .count();
    let mut parts = Vec::new();
    if local > 0 {
        parts.push(format!("local={local}"));
    }
    if proc_rows > 0 {
        parts.push(format!("proc={proc_rows}"));
    }
    if ebpf > 0 {
        parts.push(format!("ebpf={ebpf}"));
    }
    if parts.is_empty() {
        "none yet".to_string()
    } else {
        parts.join(" ")
    }
}

fn top_filter_label(options: &TopOptions) -> String {
    if let Some(pid) = options.pid {
        format!("pid={pid}")
    } else if let Some(comm) = &options.comm {
        format!("comm={comm}")
    } else {
        "known agents".to_string()
    }
}

fn normalize_view_key(view: &str) -> String {
    match view.to_ascii_lowercase().as_str() {
        "process" | "proc" => "processes".to_string(),
        "file" | "fs" => "files".to_string(),
        "net" => "network".to_string(),
        "model" | "tokens" => "models".to_string(),
        "processes" | "files" | "network" | "models" => view.to_ascii_lowercase(),
        _ => "all".to_string(),
    }
}

fn next_view_key(current: &str) -> String {
    const VIEWS: [&str; 5] = ["all", "processes", "files", "network", "models"];
    let current = normalize_view_key(current);
    let idx = VIEWS
        .iter()
        .position(|value| *value == current)
        .unwrap_or(0);
    VIEWS[(idx + 1) % VIEWS.len()].to_string()
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

fn format_token_value(value: Option<i64>) -> String {
    value
        .map(format_compact_i64)
        .unwrap_or_else(|| "-".to_string())
}

fn format_compact_i64(value: i64) -> String {
    let abs = value.abs();
    if abs >= 1_000_000 {
        format!("{:.1}m", value as f64 / 1_000_000.0)
    } else if abs >= 10_000 {
        format!("{:.1}k", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
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
            .map(|p| agent_name_from_command(&p.comm, &p.command))
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
            if !matches_top_filter(session.pid, session.comm.as_deref(), None, options) {
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
    capture: Option<&LiveCaptureSnapshot>,
    limit: usize,
    options: &TopOptions,
) -> AgentTopOutput<'a> {
    let mut live_rows = live_process_rows(sample, previous, options);
    sort_agent_rows(&mut live_rows, "cpu");
    let local_sessions = discover_local_top_sessions(options, limit);
    let mut used_live_pids = HashSet::new();
    let mut rows = Vec::new();

    for session in local_sessions {
        let live_idx = live_rows.iter().position(|row| {
            !row.pid.is_some_and(|pid| used_live_pids.contains(&pid))
                && row.agent == session.agent
                && local_session_can_attach_to_live(&session, row)
                && matches_top_filter(row.pid, Some(&row.agent), Some(&row.command), options)
        });
        let live = live_idx.and_then(|idx| live_rows.get(idx).cloned());
        if let Some(pid) = live.as_ref().and_then(|row| row.pid) {
            used_live_pids.insert(pid);
        }
        let command = session
            .prompt_preview
            .clone()
            .or_else(|| live.as_ref().map(|row| row.command.clone()))
            .unwrap_or_else(|| session.path.display().to_string());
        let trace = if live.is_some() {
            "local+proc"
        } else {
            "local"
        };
        rows.push(AgentTopRow {
            session: session.display_id,
            agent: session.agent,
            pid: live.as_ref().and_then(|row| row.pid),
            model: session.model,
            age_s: live.as_ref().and_then(|row| row.age_s).or(session.age_s),
            cpu_percent: live.as_ref().map(|row| row.cpu_percent).unwrap_or_default(),
            rss_mb: live.as_ref().map(|row| row.rss_mb).unwrap_or_default(),
            processes: live.as_ref().map(|row| row.processes).unwrap_or_default(),
            tokens: (session.total_tokens > 0).then_some(session.total_tokens),
            tools: session.tools,
            execs: 0,
            failures: 0,
            files: 0,
            network: 0,
            unattributed: 0,
            trace: trace.to_string(),
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
    let mut notes = Vec::new();
    if has_local {
        notes.push(
            "session rows include agent-native local logs from ~/.claude or ~/.codex when present"
                .to_string(),
        );
    }
    if has_proc {
        notes.push("proc evidence uses /proc for CPU/RSS/process families".to_string());
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
        canonical_events: 0,
        llm_calls: 0,
        total_tokens: rows.iter().filter_map(|row| row.tokens).sum(),
        rows,
        sections: Vec::new(),
        failures: Vec::new(),
        notes,
    }
}

fn local_session_can_attach_to_live(session: &LocalTopSession, row: &AgentTopRow) -> bool {
    match (session.age_s, row.age_s) {
        (Some(local_age_s), Some(process_age_s)) => local_age_s <= process_age_s + 60.0,
        _ => false,
    }
}

fn apply_live_capture(
    rows: &mut [AgentTopRow],
    sample: &LiveSample,
    capture: &LiveCaptureSnapshot,
) {
    if capture.events == 0 {
        return;
    }

    let children = children_by_ppid(&sample.procs);
    let mut attributed = HashSet::new();
    for row in rows.iter_mut() {
        let Some(root_pid) = row.pid else {
            continue;
        };
        let family = live_process_family(root_pid, &children, &sample.procs);
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
            session: format!("proc:{root_pid}"),
            agent,
            pid: Some(root_pid),
            model: None,
            age_s: root.map(|proc_info| process_age_s(proc_info, sample)),
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

fn process_age_s(proc_info: &ProcInfo, sample: &LiveSample) -> f64 {
    let process_start_s = proc_info.starttime_ticks as f64 / ticks_per_second();
    (sample.uptime_s - process_start_s).max(0.0)
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
    label_from_exec_token(comm).or_else(|| label_from_command_argv(command))
}

fn label_from_command_argv(command: &str) -> Option<&'static str> {
    let mut args = command.split_whitespace();
    let argv0 = args.next()?;
    if let Some(label) = label_from_exec_token(argv0) {
        return Some(label);
    }

    args.filter(|arg| looks_like_exec_path(arg))
        .find_map(label_from_exec_token)
}

fn looks_like_exec_path(token: &str) -> bool {
    let token = token.trim_matches(|ch| matches!(ch, '"' | '\''));
    token.contains('/')
}

fn label_from_exec_token(token: &str) -> Option<&'static str> {
    let token = token.trim_matches(|ch| matches!(ch, '"' | '\''));
    if token.is_empty() {
        return None;
    }

    let lower = token.to_ascii_lowercase();
    let basename = Path::new(&lower)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(lower.as_str());

    label_from_exec_name(basename).or_else(|| label_from_known_package_path(&lower))
}

fn label_from_exec_name(name: &str) -> Option<&'static str> {
    match name {
        "claude" | "claude-code" => Some("claude"),
        "codex" | "codex-cli" => Some("codex"),
        "gemini" | "gemini-cli" => Some("gemini"),
        "opencode" => Some("opencode"),
        "aider" => Some("aider"),
        "goose" => Some("goose"),
        "openclaw" => Some("openclaw"),
        name if name.starts_with("openclaw-") => Some("openclaw"),
        _ => None,
    }
}

fn label_from_known_package_path(path: &str) -> Option<&'static str> {
    if path.contains("@anthropic-ai/claude-code") || path.contains("/claude-code/") {
        Some("claude")
    } else if path.contains("@openai/codex") || path.contains("/codex-linux-") {
        Some("codex")
    } else if path.contains("@google/gemini-cli") || path.contains("/gemini-cli/") {
        Some("gemini")
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct LocalTopSession {
    agent: String,
    display_id: String,
    path: PathBuf,
    model: Option<String>,
    age_s: Option<f64>,
    total_tokens: i64,
    tools: usize,
    prompt_preview: Option<String>,
}

fn discover_local_top_sessions(options: &TopOptions, limit: usize) -> Vec<LocalTopSession> {
    let mut candidates = Vec::new();
    for (agent, dir) in local_session_dirs() {
        walk_jsonl(&dir, &mut |path, meta| {
            let updated = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            candidates.push((updated, agent, path.to_path_buf()));
        });
    }
    candidates.sort_by_key(|(updated, _, _)| std::cmp::Reverse(*updated));

    let mut sessions = Vec::new();
    let mut seen_sessions = HashSet::new();
    let target_sessions = limit.clamp(1, 25);
    let candidate_scan = target_sessions.saturating_mul(3).clamp(10, 75);
    for (updated, agent, path) in candidates.into_iter().take(candidate_scan) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let Some(mut session) = parse_local_top_session(agent, &path, &content) else {
            continue;
        };
        session.age_s = SystemTime::now()
            .duration_since(updated)
            .ok()
            .map(|duration| duration.as_secs_f64());
        if !local_session_matches_filter(&session, options) {
            continue;
        }
        if !seen_sessions.insert(session.display_id.clone()) {
            continue;
        }
        sessions.push(session);
        if sessions.len() >= target_sessions {
            break;
        }
    }
    sessions
}

fn local_session_dirs() -> Vec<(&'static str, PathBuf)> {
    let Some(home) = user_home_dir() else {
        return Vec::new();
    };
    [
        ("claude", home.join(".claude/projects")),
        ("codex", home.join(".codex/sessions")),
    ]
    .into_iter()
    .filter(|(_, path)| path.is_dir())
    .collect()
}

fn user_home_dir() -> Option<PathBuf> {
    std::env::var("SUDO_USER")
        .ok()
        .and_then(|user| {
            fs::read_to_string("/etc/passwd").ok().and_then(|passwd| {
                passwd
                    .lines()
                    .find(|line| line.starts_with(&format!("{user}:")))
                    .and_then(|line| line.split(':').nth(5))
                    .map(PathBuf::from)
            })
        })
        .or_else(dirs::home_dir)
}

fn walk_jsonl(dir: &Path, f: &mut dyn FnMut(&Path, &fs::Metadata)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_jsonl(&path, f);
        } else if path.extension().is_some_and(|ext| ext == "jsonl")
            && let Ok(meta) = path.metadata()
        {
            f(&path, &meta);
        }
    }
}

fn parse_local_top_session(agent: &str, path: &Path, content: &str) -> Option<LocalTopSession> {
    let mut session_id = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("session")
        .to_string();
    let mut model = None;
    let mut total_tokens = 0i64;
    let mut claude_message_tokens = 0i64;
    let mut claude_seen_usage = HashSet::new();
    let mut tools = 0usize;
    let mut prompt_preview = None;

    for line in content.lines() {
        let Ok(obj) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(id) = local_session_id(&obj) {
            session_id = id;
        }
        let typ = obj
            .get("type")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        match (agent, typ) {
            ("claude", "result") => {
                if let Some(model_usage) = obj.get("modelUsage").and_then(|value| value.as_object())
                {
                    for (name, usage) in model_usage {
                        model.get_or_insert_with(|| name.clone());
                        total_tokens += json_i64(usage, "inputTokens")
                            + json_i64(usage, "outputTokens")
                            + json_i64(usage, "cacheReadInputTokens")
                            + json_i64(usage, "cacheCreationInputTokens");
                    }
                }
            }
            ("claude", "assistant") => {
                if let Some(name) = obj
                    .pointer("/message/model")
                    .and_then(|value| value.as_str())
                {
                    model.get_or_insert_with(|| name.to_string());
                }
                if let Some(usage) = obj.pointer("/message/usage")
                    && claude_seen_usage.insert(claude_usage_key(&obj))
                {
                    claude_message_tokens += json_i64(usage, "input_tokens")
                        + json_i64(usage, "output_tokens")
                        + json_i64(usage, "cache_read_input_tokens")
                        + json_i64(usage, "cache_creation_input_tokens");
                }
                if let Some(items) = obj
                    .pointer("/message/content")
                    .and_then(|value| value.as_array())
                {
                    tools += items
                        .iter()
                        .filter(|item| {
                            item.get("type").and_then(|value| value.as_str()) == Some("tool_use")
                        })
                        .count();
                }
            }
            ("claude", "user") => {
                if let Some(text) =
                    local_message_preview(obj.pointer("/message/content").unwrap_or(&obj))
                {
                    prompt_preview = Some(text);
                }
            }
            ("codex", "turn_context") => {
                if let Some(name) = obj
                    .pointer("/payload/model")
                    .and_then(|value| value.as_str())
                {
                    model = Some(name.to_string());
                }
            }
            ("codex", "event_msg") => {
                if obj
                    .pointer("/payload/type")
                    .and_then(|value| value.as_str())
                    == Some("token_count")
                    && let Some(usage) = obj.pointer("/payload/info/total_token_usage")
                {
                    total_tokens = json_i64(usage, "total_tokens");
                }
            }
            ("codex", "response_item")
                if obj
                    .pointer("/payload/type")
                    .and_then(|value| value.as_str())
                    == Some("function_call") =>
            {
                tools += 1;
            }
            ("codex", "message") | ("codex", "input") | ("codex", "user") => {
                if let Some(text) = local_message_preview(&obj) {
                    prompt_preview = Some(text);
                }
            }
            _ => {
                if prompt_preview.is_none()
                    && typ.contains("user")
                    && let Some(text) = local_message_preview(&obj)
                {
                    prompt_preview = Some(text);
                }
            }
        }
    }

    if total_tokens == 0 {
        total_tokens = claude_message_tokens;
    }

    if total_tokens == 0 && tools == 0 && prompt_preview.is_none() && model.is_none() {
        return None;
    }

    Some(LocalTopSession {
        agent: agent.to_string(),
        display_id: format!("{agent}:{}", short_session_id(&session_id)),
        path: path.to_path_buf(),
        model,
        age_s: None,
        total_tokens,
        tools,
        prompt_preview,
    })
}

fn local_session_matches_filter(session: &LocalTopSession, options: &TopOptions) -> bool {
    if options.pid.is_some() {
        return true;
    }
    let Some(filter) = &options.comm else {
        return true;
    };
    let filter = filter.to_ascii_lowercase();
    session.agent.to_ascii_lowercase().contains(&filter)
        || session
            .prompt_preview
            .as_ref()
            .is_some_and(|prompt| prompt.to_ascii_lowercase().contains(&filter))
        || session
            .model
            .as_ref()
            .is_some_and(|model| model.to_ascii_lowercase().contains(&filter))
        || session
            .path
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains(&filter)
}

fn local_session_id(obj: &Value) -> Option<String> {
    for key in ["sessionId", "session_id", "conversation_id"] {
        if let Some(value) = obj.get(key).and_then(|value| value.as_str())
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    for pointer in ["/payload/session_id", "/payload/sessionId"] {
        if let Some(value) = obj.pointer(pointer).and_then(|value| value.as_str())
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    None
}

fn claude_usage_key(obj: &Value) -> String {
    obj.get("requestId")
        .or_else(|| obj.pointer("/message/id"))
        .or_else(|| obj.get("uuid"))
        .and_then(|value| value.as_str())
        .unwrap_or("usage")
        .to_string()
}

fn local_message_preview(value: &Value) -> Option<String> {
    let mut parts = Vec::new();
    collect_local_text(value, &mut parts);
    let text = parts
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (!text.is_empty()).then(|| truncate_text(&text, 80))
}

fn collect_local_text(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_local_text(item, out);
            }
        }
        Value::Object(obj) => {
            if obj
                .get("type")
                .and_then(|value| value.as_str())
                .is_some_and(|typ| typ == "tool_use" || typ == "function_call")
            {
                return;
            }
            for key in ["text", "content", "message", "input", "prompt"] {
                if let Some(value) = obj.get(key) {
                    collect_local_text(value, out);
                }
            }
        }
        _ => {}
    }
}

fn json_i64(value: &Value, key: &str) -> i64 {
    value
        .get(key)
        .and_then(|value| value.as_i64().or_else(|| value.as_u64().map(|v| v as i64)))
        .unwrap_or_default()
}

fn short_session_id(id: &str) -> String {
    let id = id.trim();
    if id.is_empty() {
        return "session".to_string();
    }
    let compact = id
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(id)
        .trim_end_matches(".jsonl");
    const MAX_SESSION_ID_CHARS: usize = 12;
    if compact.chars().count() <= MAX_SESSION_ID_CHARS {
        return compact.to_string();
    }
    let head = compact.chars().take(6).collect::<String>();
    let tail = compact
        .chars()
        .rev()
        .take(5)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{head}.{tail}")
}

fn truncate_text(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        text.chars().take(max.saturating_sub(1)).collect()
    }
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

fn number_or_string(value: Option<&Value>) -> Option<f64> {
    value.and_then(|v| {
        v.as_f64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_agent_label_uses_executable_not_model_argument() {
        assert_eq!(
            known_agent_label(
                "python",
                "python benchmark_runner.py --model claude-sonnet-4-5-20250929"
            ),
            None
        );
        assert_eq!(
            known_agent_label(
                "bash",
                "/bin/bash -lc ./target/debug/agentsight top --once -c claude"
            ),
            None
        );
        assert_eq!(
            known_agent_label(
                "docker",
                "docker run image bash -c claude --model claude-sonnet-4"
            ),
            None
        );
        assert_eq!(
            known_agent_label("node", "node /home/user/.nvm/versions/node/v22/bin/codex"),
            Some("codex")
        );
        assert_eq!(
            known_agent_label("node", "node /home/user/.local/bin/claude"),
            Some("claude")
        );
        assert_eq!(known_agent_label("claude", "claude"), Some("claude"));
        assert_eq!(known_agent_label("openclaw-gatewa", ""), Some("openclaw"));
    }

    #[test]
    fn local_session_does_not_attach_to_newer_unrelated_process() {
        let session = LocalTopSession {
            agent: "claude".to_string(),
            display_id: "claude:old".to_string(),
            path: PathBuf::from("/home/user/.claude/projects/old.jsonl"),
            model: None,
            age_s: Some(1_200.0),
            total_tokens: 1,
            tools: 0,
            prompt_preview: None,
        };
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

        assert!(!local_session_can_attach_to_live(&session, &row));
    }
}
