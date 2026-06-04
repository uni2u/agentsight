// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

mod projector;
pub mod types;

pub(crate) use projector::ViewProjector;

use crate::framework::core::Event;
use crate::view::types::{
    AgentRow, AuditEventRow, LlmCallRow, NetworkTargetRow, ResourceSampleRow, SessionRow, Snapshot,
    SnapshotOptions, SnapshotSummary, TokenSummary, TokenUsageRow, ToolCallRow, ViewResult,
    ViewUpdate, ViewUpdateSink,
};
use chrono::{SecondsFormat, Utc};
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) struct MaterializedView {
    projector: ViewProjector,
    state: ViewState,
    sinks: Vec<Box<dyn ViewUpdateSink>>,
}

impl MaterializedView {
    pub(crate) fn new() -> Self {
        Self {
            projector: ViewProjector::new(),
            state: ViewState::default(),
            sinks: Vec::new(),
        }
    }

    pub(crate) fn add_sink(&mut self, sink: Box<dyn ViewUpdateSink>) {
        self.sinks.push(sink);
    }

    pub(crate) fn set_source(&mut self, source: impl Into<String>) {
        self.state.source = source.into();
    }

    pub(crate) fn load_update(&mut self, update: ViewUpdate) {
        self.state.apply_update(&update);
    }

    pub(crate) fn ingest_event(&mut self, event: &Event) -> ViewResult<()> {
        let updates = self.projector.ingest_event(event);
        for update in updates {
            self.apply_and_publish_update(&update)?;
        }
        Ok(())
    }

    pub(crate) fn ingest_update(&mut self, update: &ViewUpdate) -> ViewResult<()> {
        self.apply_and_publish_update(update)
    }

    pub(crate) fn ingest_jsonl_file(&mut self, path: impl AsRef<Path>) -> ViewResult<usize> {
        let content = std::fs::read_to_string(path)?;
        let mut inserted = 0usize;
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(update) = serde_json::from_str::<ViewUpdate>(trimmed) {
                self.ingest_update(&update)?;
            } else {
                let event: Event = serde_json::from_str(trimmed)
                    .map_err(|e| format!("failed to parse JSONL line {}: {}", idx + 1, e))?;
                self.ingest_event(&event)?;
            }
            inserted += 1;
        }
        Ok(inserted)
    }

    fn apply_and_publish_update(&mut self, update: &ViewUpdate) -> ViewResult<()> {
        self.state.apply_update(update);
        self.publish_update(update)
    }

    fn publish_update(&mut self, update: &ViewUpdate) -> ViewResult<()> {
        let mut first_error = None;
        for sink in &mut self.sinks {
            if let Err(error) = sink.update(update) {
                log::warn!("MaterializedView: failed to publish view update: {}", error);
                first_error.get_or_insert_with(|| error.to_string());
            }
        }
        if let Some(error) = first_error {
            return Err(std::io::Error::other(error).into());
        }
        Ok(())
    }

    pub(crate) fn export_snapshot(&self, options: SnapshotOptions) -> Snapshot {
        self.state.export_snapshot(options)
    }

    pub(crate) fn token_summary(&self, group_by: &str) -> Vec<TokenSummary> {
        self.state.token_summary(group_by)
    }

    pub(crate) fn audit_rows(&self, audit_type: Option<&str>, limit: usize) -> Vec<AuditEventRow> {
        self.state.audit_rows(audit_type, limit)
    }

    pub(crate) fn llm_call_rows(&self, limit: usize) -> Vec<LlmCallRow> {
        self.state.llm_call_rows(limit)
    }

    pub(crate) fn first_tool_timestamp_ms(&self) -> Option<u64> {
        self.state.first_tool_timestamp_ms()
    }

    pub(crate) fn tool_call_count(&self) -> i64 {
        self.state.tool_call_count()
    }

    pub(crate) fn tool_counts(&self) -> BTreeMap<String, usize> {
        self.state.tool_counts()
    }

    pub(crate) fn tool_durations_ms(&self) -> Vec<u64> {
        self.state.tool_durations_ms()
    }

    pub(crate) fn resource_samples(&self) -> Vec<(Option<f64>, Option<i64>)> {
        self.state.resource_samples()
    }
}

#[derive(Default)]
struct ViewState {
    source: String,
    llm_calls: BTreeMap<String, LlmCallRow>,
    token_usage: BTreeMap<String, TokenUsageRow>,
    audit_events: BTreeMap<String, AuditEventRow>,
    tool_calls: BTreeMap<String, ToolCallRow>,
    sessions: BTreeMap<String, SessionRow>,
    network_targets: BTreeMap<String, NetworkTargetRow>,
    resource_samples: Vec<ResourceSampleRow>,
}

impl ViewState {
    fn apply_update(&mut self, update: &ViewUpdate) {
        match update {
            ViewUpdate::LlmCall(row) => {
                self.llm_calls.insert(row.id.clone(), row.clone());
            }
            ViewUpdate::TokenUsage(row) => {
                self.token_usage.insert(row.id.clone(), row.clone());
            }
            ViewUpdate::AuditEvent(row) => {
                self.audit_events.insert(row.id.clone(), row.clone());
            }
            ViewUpdate::ToolCall(row) => {
                self.tool_calls.insert(row.id.clone(), row.clone());
            }
            ViewUpdate::Session(row) => self.upsert_session(row),
            ViewUpdate::NetworkTarget(row) => self.upsert_network_target(row),
            ViewUpdate::ResourceSample(row) => {
                self.resource_samples.push(row.clone());
            }
        }
    }

    fn upsert_session(&mut self, row: &SessionRow) {
        let Some(existing) = self.sessions.get_mut(&row.id) else {
            self.sessions.insert(row.id.clone(), row.clone());
            return;
        };

        existing.start_timestamp_ms = existing.start_timestamp_ms.min(row.start_timestamp_ms);
        existing.end_timestamp_ms =
            max_optional_timestamp(existing.end_timestamp_ms, row.end_timestamp_ms);
        if row.model.as_deref().is_some_and(|model| model != "unknown") || existing.model.is_none()
        {
            existing.model = row.model.clone();
        }
        existing.input_tokens += row.input_tokens;
        existing.output_tokens += row.output_tokens;
        existing.total_tokens += row.total_tokens;
        existing.confidence = max_optional_f64(existing.confidence, row.confidence);
    }

    fn upsert_network_target(&mut self, row: &NetworkTargetRow) {
        let key = network_target_key(row);
        let Some(existing) = self.network_targets.get_mut(&key) else {
            self.network_targets.insert(key, row.clone());
            return;
        };

        existing.count += row.count;
        existing.error_count += row.error_count;
        existing.first_timestamp_ms =
            min_optional_timestamp(existing.first_timestamp_ms, row.first_timestamp_ms);
        existing.last_timestamp_ms =
            max_optional_timestamp(existing.last_timestamp_ms, row.last_timestamp_ms);
    }

    fn export_snapshot(&self, options: SnapshotOptions) -> Snapshot {
        Snapshot {
            schema_version: 1,
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            summary: self.snapshot_summary(options),
            token_summary: self.token_summary("model"),
            network_targets: self.network_targets(),
            audit_events: self.audit_events(options.audit_limit),
            sessions: self.sessions(),
            agents: self.agents(),
        }
    }

    fn snapshot_summary(&self, options: SnapshotOptions) -> SnapshotSummary {
        let mut start_timestamp_ms = None;
        let mut end_timestamp_ms = None;
        let mut observe = |timestamp| {
            observe_timestamp(&mut start_timestamp_ms, &mut end_timestamp_ms, timestamp);
        };

        for row in self.llm_calls.values() {
            observe(Some(row.start_timestamp_ms));
            observe(row.end_timestamp_ms);
        }
        for row in self.token_usage.values() {
            observe(Some(row.timestamp_ms));
        }
        for row in self.audit_events.values() {
            observe(Some(row.timestamp_ms));
        }
        for row in self.tool_calls.values() {
            observe(Some(row.timestamp_ms));
        }
        for row in self.network_targets.values() {
            observe(row.first_timestamp_ms);
            observe(row.last_timestamp_ms);
        }
        for row in self.sessions.values() {
            observe(Some(row.start_timestamp_ms));
            observe(row.end_timestamp_ms);
        }
        for row in &self.resource_samples {
            observe(Some(row.timestamp_ms));
        }
        let (input_tokens, output_tokens, total_tokens) =
            self.effective_tokens()
                .into_iter()
                .fold((0, 0, 0), |acc, token| {
                    (
                        acc.0 + token.input_tokens,
                        acc.1 + token.output_tokens,
                        acc.2 + token.total_tokens,
                    )
                });

        SnapshotSummary {
            source: if self.source.is_empty() {
                "materialized_view".to_string()
            } else {
                self.source.clone()
            },
            view_events: self.view_events(),
            llm_calls: self.llm_calls.len() as i64,
            token_usage_rows: self.token_usage.len() as i64,
            audit_events: self.audit_events.len() as i64,
            sessions: self.sessions.len() as i64,
            input_tokens,
            output_tokens,
            total_tokens,
            start_timestamp_ms,
            end_timestamp_ms,
            audit_limit: options.audit_limit,
        }
    }

    fn token_summary(&self, group_by: &str) -> Vec<TokenSummary> {
        let mut groups: BTreeMap<String, TokenSummary> = BTreeMap::new();
        for token in self.effective_tokens() {
            let group = token_group(token, group_by);
            let entry = groups.entry(group.clone()).or_insert(TokenSummary {
                group,
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_tokens: 0,
                cache_read_tokens: 0,
                total_tokens: 0,
                calls: 0,
            });
            entry.input_tokens += token.input_tokens;
            entry.output_tokens += token.output_tokens;
            entry.cache_creation_tokens += token.cache_creation_tokens;
            entry.cache_read_tokens += token.cache_read_tokens;
            entry.total_tokens += token.total_tokens;
            entry.calls += 1;
        }
        let mut rows = groups.into_values().collect::<Vec<_>>();
        rows.sort_by(|a, b| {
            b.total_tokens
                .cmp(&a.total_tokens)
                .then_with(|| a.group.cmp(&b.group))
        });
        rows
    }

    fn audit_rows(&self, audit_type: Option<&str>, limit: usize) -> Vec<AuditEventRow> {
        let mut rows = self
            .audit_events
            .values()
            .filter(|row| audit_type.is_none_or(|audit_type| row.audit_type == audit_type))
            .cloned()
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        rows.truncate(limit.clamp(1, 10_000));
        rows
    }

    fn llm_call_rows(&self, limit: usize) -> Vec<LlmCallRow> {
        let token_totals = self.effective_token_totals_by_call();
        let mut rows = self
            .llm_calls
            .values()
            .cloned()
            .map(|mut row| {
                if let Some((input, output, total)) = token_totals.get(&row.id) {
                    row.input_tokens = *input;
                    row.output_tokens = *output;
                    row.total_tokens = *total;
                }
                row
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| b.start_timestamp_ms.cmp(&a.start_timestamp_ms));
        rows.truncate(limit.clamp(1, 10_000));
        rows
    }

    fn first_tool_timestamp_ms(&self) -> Option<u64> {
        self.tool_calls.values().map(|row| row.timestamp_ms).min()
    }

    fn tool_call_count(&self) -> i64 {
        self.tool_calls.len() as i64
    }

    fn tool_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for row in self.tool_calls.values() {
            *counts
                .entry(row.tool_name.clone().unwrap_or_else(|| "?".to_string()))
                .or_default() += 1;
        }
        counts
    }

    fn tool_durations_ms(&self) -> Vec<u64> {
        self.tool_calls
            .values()
            .filter_map(|row| row.duration_ms)
            .collect()
    }

    fn resource_samples(&self) -> Vec<(Option<f64>, Option<i64>)> {
        self.resource_samples
            .iter()
            .map(|row| (row.cpu_percent, row.rss_mb))
            .collect()
    }

    fn network_targets(&self) -> Vec<NetworkTargetRow> {
        let mut rows = self.network_targets.values().cloned().collect::<Vec<_>>();
        rows.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.host.cmp(&b.host))
                .then_with(|| a.path.cmp(&b.path))
        });
        rows
    }

    fn audit_events(&self, limit: usize) -> Vec<AuditEventRow> {
        let mut rows = self.audit_events.values().cloned().collect::<Vec<_>>();
        rows.sort_by(|a, b| {
            a.timestamp_ms
                .cmp(&b.timestamp_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        rows.truncate(limit.min(100_000));
        rows
    }

    fn sessions(&self) -> Vec<SessionRow> {
        let mut rows = self.sessions.values().cloned().collect::<Vec<_>>();
        rows.sort_by(|a, b| {
            a.start_timestamp_ms
                .cmp(&b.start_timestamp_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        rows
    }

    fn agents(&self) -> Vec<AgentRow> {
        let mut agents: BTreeMap<String, AgentRow> = BTreeMap::new();
        for session in self.sessions.values() {
            let entry = agents
                .entry(session.agent_type.clone())
                .or_insert(AgentRow {
                    agent_type: session.agent_type.clone(),
                    agent_name: session.agent_name.clone(),
                    sessions: 0,
                    input_tokens: 0,
                    output_tokens: 0,
                    total_tokens: 0,
                    last_seen_ms: None,
                });
            if session.agent_name > entry.agent_name {
                entry.agent_name = session.agent_name.clone();
            }
            entry.sessions += 1;
            entry.input_tokens += session.input_tokens;
            entry.output_tokens += session.output_tokens;
            entry.total_tokens += session.total_tokens;
            entry.last_seen_ms = max_optional_timestamp(
                entry.last_seen_ms,
                session
                    .end_timestamp_ms
                    .or(Some(session.start_timestamp_ms)),
            );
        }
        agents.into_values().collect()
    }

    fn view_events(&self) -> i64 {
        (self.llm_calls.len()
            + self.token_usage.len()
            + self.audit_events.len()
            + self.tool_calls.len()
            + self.sessions.len()
            + self.network_targets.len()
            + self.resource_samples.len()) as i64
    }

    fn effective_tokens(&self) -> Vec<&TokenUsageRow> {
        let mut selected: BTreeMap<String, &TokenUsageRow> = BTreeMap::new();
        for token in self.token_usage.values() {
            let key = if token.llm_call_id.is_empty() {
                token.id.clone()
            } else {
                token.llm_call_id.clone()
            };
            match selected.get(&key) {
                Some(current) if !token_has_higher_priority(token, current) => {}
                _ => {
                    selected.insert(key, token);
                }
            }
        }
        selected.into_values().collect()
    }

    fn effective_token_totals_by_call(&self) -> BTreeMap<String, (i64, i64, i64)> {
        let mut totals = BTreeMap::new();
        for token in self.effective_tokens() {
            totals.insert(
                token.llm_call_id.clone(),
                (token.input_tokens, token.output_tokens, token.total_tokens),
            );
        }
        totals
    }
}

fn token_group(token: &TokenUsageRow, group_by: &str) -> String {
    match group_by {
        "provider" => token.provider.clone(),
        "comm" => token.comm.clone(),
        "pid" => token.pid.map(|pid| pid.to_string()),
        _ => token.model.clone(),
    }
    .filter(|value| !value.is_empty())
    .unwrap_or_else(|| "unknown".to_string())
}

fn token_has_higher_priority(candidate: &TokenUsageRow, current: &TokenUsageRow) -> bool {
    let candidate_priority = token_source_priority(&candidate.source);
    let current_priority = token_source_priority(&current.source);
    candidate_priority
        .cmp(&current_priority)
        .then_with(|| {
            current
                .confidence
                .unwrap_or_default()
                .partial_cmp(&candidate.confidence.unwrap_or_default())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| candidate.id.cmp(&current.id))
        .is_lt()
}

fn token_source_priority(source: &str) -> u8 {
    match source {
        "response_usage" | "orphan_response_usage" => 0,
        "gemini_cli_stdout_stats" => 1,
        "claude_telemetry" => 2,
        _ => 3,
    }
}

fn network_target_key(row: &NetworkTargetRow) -> String {
    format!(
        "{}\0{}\0{}",
        row.pid.unwrap_or_default(),
        row.host,
        row.path.as_deref().unwrap_or_default()
    )
}

fn observe_timestamp(start: &mut Option<u64>, end: &mut Option<u64>, timestamp: Option<u64>) {
    let Some(timestamp) = timestamp else {
        return;
    };
    *start = Some(start.map_or(timestamp, |current| current.min(timestamp)));
    *end = Some(end.map_or(timestamp, |current| current.max(timestamp)));
}

fn min_optional_timestamp(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn max_optional_timestamp(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn max_optional_f64(left: Option<f64>, right: Option<f64>) -> Option<f64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}
