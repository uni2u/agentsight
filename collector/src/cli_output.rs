// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use serde::Serialize;

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

pub(crate) fn print_json<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
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

pub(crate) fn print_top(
    db: &str,
    duration_s: f64,
    canonical_events: i64,
    llm_calls: i64,
    total_tokens: i64,
    resources: &ResourcePeaks,
    sections: &[TopSection],
    failures: &[String],
) {
    let generated_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    println!(
        "AgentSight top · {generated_at} · {db} · {duration_s:.0}s · {canonical_events} events · {llm_calls} LLM calls · {total_tokens} tokens\n"
    );
    for section in sections {
        print_ranked(section);
    }
    if resources.samples > 0 {
        println!("Resources");
        println!("  max CPU {:>8.2}%", resources.max_cpu_percent);
        println!("  max RSS {:>8} MB", resources.max_rss_mb);
        println!();
    }
    if !failures.is_empty() {
        println!("Recent Failures");
        for failure in failures {
            println!("  {failure}");
        }
        println!();
    }
}

fn field(label: &str, value: impl std::fmt::Display) {
    println!("  {:<20}{value}", format!("{label}:"));
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
