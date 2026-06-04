// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::output::{AgentTopOutput, AgentTopRow, TopOptions};
use crate::text::truncate_text;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
};

pub(crate) fn draw_live_top_tui(
    frame: &mut Frame<'_>,
    top: &AgentTopOutput<'_>,
    selected: usize,
    options: &TopOptions,
    paused: bool,
    show_help: bool,
    show_diagnostics: bool,
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
    } else if show_diagnostics {
        render_top_diagnostics(frame, top);
    }
}

pub(crate) fn next_view_key(current: &str) -> String {
    const VIEWS: [&str; 5] = ["all", "processes", "files", "network", "models"];
    let current = normalize_view_key(current);
    let idx = VIEWS
        .iter()
        .position(|value| *value == current)
        .unwrap_or(0);
    VIEWS[(idx + 1) % VIEWS.len()].to_string()
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
            "q quit | up/down select | s sort | v view | p pause | r refresh | +/- rows | e errors | ? help",
        ),
    ])];
    lines.push(Line::from(vec![
        Span::styled("status ", label_style()),
        Span::raw(tui_status_line(top)),
    ]));
    if let Some(message) = tui_diagnostic_lines(top, 1).into_iter().next() {
        lines.push(Line::from(vec![
            Span::styled("diagnostic ", label_style()),
            Span::raw(message),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title("status").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

pub(crate) fn tui_status_line(top: &AgentTopOutput<'_>) -> String {
    let mut parts = Vec::new();
    if top
        .rows
        .iter()
        .any(|row| row.trace.contains("agent-native"))
    {
        parts.push("agent-native".to_string());
    }
    if top.rows.iter().any(|row| row.trace.contains("proc")) {
        parts.push("/proc".to_string());
    }
    if top.rows.iter().any(|row| row.trace.contains("ebpf")) {
        parts.push("eBPF".to_string());
    }
    if top.rows.iter().any(|row| {
        row.trace.contains("ebpf_file")
            || row.trace.contains("proc_fd")
            || row.trace.contains("sticky")
    }) {
        parts.push("session path linked".to_string());
    }
    if top.total_tokens > 0 {
        parts.push(format!(
            "tokens {}",
            format_token_value(Some(top.total_tokens))
        ));
    }
    if parts.is_empty() {
        if top.rows.is_empty() {
            "no matching sessions".to_string()
        } else {
            "observing".to_string()
        }
    } else {
        parts.join(" | ")
    }
}

pub(crate) fn tui_diagnostic_lines(top: &AgentTopOutput<'_>, limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let recent = crate::recent_tui_diagnostics(limit);
    for message in top
        .notes
        .iter()
        .filter(|note| !is_tui_status_note(note))
        .chain(recent.iter())
    {
        if !out.contains(message) {
            out.push(message.clone());
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn is_tui_status_note(note: &str) -> bool {
    note.starts_with("agent-native sessions are")
        || note.starts_with("proc evidence uses")
        || note.starts_with("agent-native sessions bind")
        || note.starts_with("ebpf evidence is")
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

fn render_top_diagnostics(frame: &mut Frame<'_>, top: &AgentTopOutput<'_>) {
    let area = centered_rect(76, 48, frame.area());
    frame.render_widget(Clear, area);
    let messages = tui_diagnostic_lines(top, 8);
    let mut lines = vec![
        Line::from(vec![Span::styled(
            "Diagnostics",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
    ];
    if messages.is_empty() {
        lines.push(Line::from("No warnings or errors captured."));
    } else {
        for message in messages {
            lines.push(Line::from(message));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from("e close | ? help | q quit"));
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title("diagnostics").borders(Borders::ALL))
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
        parts.push(format!("{} proc", super::format::format_count(row.processes as i64)));
    }
    if row.tools > 0 {
        parts.push(format!("{} tool", super::format::format_count(row.tools as i64)));
    }
    if row.execs > 0 {
        parts.push(format!("{} exec", super::format::format_count(row.execs as i64)));
    }
    if row.failures > 0 {
        parts.push(format!("{} fail", super::format::format_count(row.failures as i64)));
    }
    if row.files > 0 {
        parts.push(format!("{} file", super::format::format_count(row.files as i64)));
    }
    if row.network > 0 {
        parts.push(format!("{} net", super::format::format_count(row.network as i64)));
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
    let ebpf_file = top
        .rows
        .iter()
        .filter(|row| row.trace.contains("ebpf_file"))
        .count();
    let proc_fd = top
        .rows
        .iter()
        .filter(|row| row.trace.contains("proc_fd"))
        .count();
    let sticky = top
        .rows
        .iter()
        .filter(|row| row.trace.contains("sticky"))
        .count();
    let mut parts = Vec::new();
    if local > 0 {
        parts.push(format!("local={local}"));
    }
    if proc_rows > 0 {
        parts.push(format!("proc={proc_rows}"));
    }
    if proc_fd > 0 {
        parts.push(format!("fd={proc_fd}"));
    }
    if sticky > 0 {
        parts.push(format!("sticky={sticky}"));
    }
    if ebpf_file > 0 {
        parts.push(format!("ebpf_file={ebpf_file}"));
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

fn format_token_value(value: Option<i64>) -> String {
    value
        .map(super::format::format_count)
        .unwrap_or_else(|| "-".to_string())
}
