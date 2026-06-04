// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

mod projection;
pub mod types;

use crate::sources::session::AGENT_NATIVE_SOURCE;
use crate::view::types::{
    AgentRow, AuditEventRow, LlmCallRow, NetworkTargetRow, ProcessNodeRow, ResourceSampleRow,
    SessionRow, Snapshot, SnapshotOptions, SnapshotSummary, TokenSummary, TokenUsageRow,
    ToolCallRow, ViewResult, ViewSink,
};
use chrono::{SecondsFormat, Utc};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

pub(crate) type SharedMaterializedView = Arc<Mutex<MaterializedView>>;

pub(crate) struct MaterializedView {
    source: String,
    llm_calls: BTreeMap<String, LlmCallRow>,
    token_usage: BTreeMap<String, TokenUsageRow>,
    audit_events: BTreeMap<String, AuditEventRow>,
    process_nodes: BTreeMap<String, ProcessNodeRow>,
    tool_calls: BTreeMap<String, ToolCallRow>,
    sessions: BTreeMap<String, SessionRow>,
    network_targets: BTreeMap<String, NetworkTargetRow>,
    resource_samples: Vec<ResourceSampleRow>,
    sinks: Vec<Box<dyn ViewSink>>,
    pending: HashMap<(u32, u64), VecDeque<PendingRequest>>,
    active_processes: HashMap<u32, String>,
    next_seq: u64,
}

#[derive(Debug, Clone)]
struct PendingRequest {
    event_id: String,
    timestamp_ms: u64,
    pid: u32,
    comm: String,
    provider: Option<String>,
    model: Option<String>,
    host: Option<String>,
    path: Option<String>,
    request_id: Option<String>,
    body_json: Option<Value>,
}

impl MaterializedView {
    pub(crate) fn new() -> Self {
        Self {
            source: String::new(),
            llm_calls: BTreeMap::new(),
            token_usage: BTreeMap::new(),
            audit_events: BTreeMap::new(),
            process_nodes: BTreeMap::new(),
            tool_calls: BTreeMap::new(),
            sessions: BTreeMap::new(),
            network_targets: BTreeMap::new(),
            resource_samples: Vec::new(),
            sinks: Vec::new(),
            pending: HashMap::new(),
            active_processes: HashMap::new(),
            next_seq: 0,
        }
    }

    pub(crate) fn shared() -> SharedMaterializedView {
        Arc::new(Mutex::new(Self::new()))
    }

    pub(crate) fn add_sink(&mut self, sink: Box<dyn ViewSink>) {
        self.sinks.push(sink);
    }

    pub(crate) fn set_source(&mut self, source: impl Into<String>) {
        self.source = source.into();
    }

    pub(crate) fn load_llm_call(&mut self, row: LlmCallRow) {
        self.apply_llm_call(&row);
    }

    pub(crate) fn load_token_usage(&mut self, row: TokenUsageRow) {
        self.apply_token_usage(&row);
    }

    pub(crate) fn load_audit_event(&mut self, row: AuditEventRow) {
        self.apply_audit_event(&row);
    }

    pub(crate) fn load_process_node(&mut self, row: ProcessNodeRow) {
        self.upsert_process_node(&row);
    }

    pub(crate) fn load_tool_call(&mut self, row: ToolCallRow) {
        self.apply_tool_call(&row);
    }

    pub(crate) fn load_session(&mut self, row: SessionRow) {
        self.upsert_session(&row);
    }

    pub(crate) fn load_network_target(&mut self, row: NetworkTargetRow) {
        self.upsert_network_target(&row);
    }

    pub(crate) fn load_resource_sample(&mut self, row: ResourceSampleRow) {
        self.apply_resource_sample(&row);
    }

    pub(crate) fn emit_llm_call(&mut self, row: LlmCallRow) -> ViewResult<()> {
        self.apply_llm_call(&row);
        self.publish(|sink| sink.llm_call(&row))
    }

    pub(crate) fn emit_token_usage(&mut self, row: TokenUsageRow) -> ViewResult<()> {
        self.apply_token_usage(&row);
        self.publish(|sink| sink.token_usage(&row))
    }

    pub(crate) fn emit_audit_event(&mut self, row: AuditEventRow) -> ViewResult<()> {
        self.apply_audit_event(&row);
        self.publish(|sink| sink.audit_event(&row))
    }

    pub(crate) fn emit_process_node(&mut self, row: ProcessNodeRow) -> ViewResult<()> {
        self.upsert_process_node(&row);
        self.publish(|sink| sink.process_node(&row))
    }

    pub(crate) fn emit_tool_call(&mut self, row: ToolCallRow) -> ViewResult<()> {
        self.apply_tool_call(&row);
        self.publish(|sink| sink.tool_call(&row))
    }

    pub(crate) fn emit_network_target(&mut self, row: NetworkTargetRow) -> ViewResult<()> {
        self.upsert_network_target(&row);
        self.publish(|sink| sink.network_target(&row))
    }

    pub(crate) fn emit_resource_sample(&mut self, row: ResourceSampleRow) -> ViewResult<()> {
        self.apply_resource_sample(&row);
        self.publish(|sink| sink.resource_sample(&row))
    }

    fn publish<F>(&mut self, mut publish: F) -> ViewResult<()>
    where
        F: FnMut(&mut dyn ViewSink) -> ViewResult<()>,
    {
        let mut first_error = None;
        for sink in &mut self.sinks {
            if let Err(error) = publish(sink.as_mut()) {
                log::warn!("MaterializedView: failed to publish view row: {}", error);
                first_error.get_or_insert_with(|| error.to_string());
            }
        }
        if let Some(error) = first_error {
            return Err(std::io::Error::other(error).into());
        }
        Ok(())
    }
}

impl MaterializedView {
    fn apply_llm_call(&mut self, row: &LlmCallRow) {
        self.llm_calls.insert(row.id.clone(), row.clone());
    }

    fn apply_token_usage(&mut self, row: &TokenUsageRow) {
        self.token_usage.insert(row.id.clone(), row.clone());
    }

    fn apply_audit_event(&mut self, row: &AuditEventRow) {
        self.audit_events.insert(row.id.clone(), row.clone());
    }

    fn apply_tool_call(&mut self, row: &ToolCallRow) {
        self.tool_calls.insert(row.id.clone(), row.clone());
    }

    fn apply_resource_sample(&mut self, row: &ResourceSampleRow) {
        self.resource_samples.push(row.clone());
    }

    fn upsert_session(&mut self, row: &SessionRow) {
        let Some(existing) = self.sessions.get_mut(&row.id) else {
            self.sessions.insert(row.id.clone(), row.clone());
            return;
        };

        existing.start_timestamp_ms = existing.start_timestamp_ms.min(row.start_timestamp_ms);
        existing.end_timestamp_ms = max_optional(existing.end_timestamp_ms, row.end_timestamp_ms);
        if row.model.as_deref().is_some_and(|model| model != "unknown") || existing.model.is_none()
        {
            existing.model = row.model.clone();
        }
        existing.input_tokens = existing.input_tokens.max(row.input_tokens);
        existing.output_tokens = existing.output_tokens.max(row.output_tokens);
        existing.total_tokens = existing.total_tokens.max(row.total_tokens);
        existing.confidence = max_optional(existing.confidence, row.confidence);
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
            min_optional(existing.first_timestamp_ms, row.first_timestamp_ms);
        existing.last_timestamp_ms =
            max_optional(existing.last_timestamp_ms, row.last_timestamp_ms);
    }

    fn upsert_process_node(&mut self, row: &ProcessNodeRow) {
        let Some(existing) = self.process_nodes.get_mut(&row.id) else {
            self.process_nodes.insert(row.id.clone(), row.clone());
            return;
        };

        existing.start_timestamp_ms =
            min_optional(existing.start_timestamp_ms, row.start_timestamp_ms);
        existing.end_timestamp_ms = max_optional(existing.end_timestamp_ms, row.end_timestamp_ms);
        if row.ppid.is_some() {
            existing.ppid = row.ppid;
        }
        if row.root_pid.is_some() {
            existing.root_pid = row.root_pid;
        }
        if row.comm.is_some() {
            existing.comm = row.comm.clone();
        }
        if row.command.is_some() {
            existing.command = row.command.clone();
        }
        if !row.argv.is_empty() {
            existing.argv = row.argv.clone();
        }
        if row.cwd.is_some() {
            existing.cwd = row.cwd.clone();
        }
        if row.exit_code.is_some() {
            existing.exit_code = row.exit_code;
        }
        if row.status.is_some() {
            existing.status = row.status.clone();
        }
        existing.confidence = max_optional(existing.confidence, row.confidence);
    }

    pub(crate) fn export_snapshot(&self, options: SnapshotOptions) -> Snapshot {
        Snapshot {
            schema_version: 1,
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            summary: self.snapshot_summary(options),
            token_summary: self.token_summary("model"),
            network_targets: self.network_targets(),
            process_nodes: self.process_nodes(),
            audit_events: self.audit_events(options.audit_limit),
            resource_samples: self.resource_sample_rows(),
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
        for row in self.process_nodes.values() {
            observe(row.start_timestamp_ms);
            observe(row.end_timestamp_ms);
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

    pub(crate) fn token_summary(&self, group_by: &str) -> Vec<TokenSummary> {
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
        sort_token_summary(&mut rows);
        rows
    }

    pub(crate) fn audit_rows(&self, audit_type: Option<&str>, limit: usize) -> Vec<AuditEventRow> {
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

    pub(crate) fn llm_call_rows(&self, limit: usize) -> Vec<LlmCallRow> {
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

    pub(crate) fn first_tool_timestamp_ms(&self) -> Option<u64> {
        self.tool_calls.values().map(|row| row.timestamp_ms).min()
    }

    pub(crate) fn tool_call_count(&self) -> i64 {
        self.tool_calls.len() as i64
    }

    pub(crate) fn tool_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for row in self.tool_calls.values() {
            *counts
                .entry(row.tool_name.clone().unwrap_or_else(|| "?".to_string()))
                .or_default() += 1;
        }
        counts
    }

    pub(crate) fn tool_durations_ms(&self) -> Vec<u64> {
        self.tool_calls
            .values()
            .filter_map(|row| row.duration_ms)
            .collect()
    }

    pub(crate) fn resource_samples(&self) -> Vec<(Option<f64>, Option<i64>)> {
        self.resource_samples
            .iter()
            .map(|row| (row.cpu_percent, row.rss_mb))
            .collect()
    }

    fn resource_sample_rows(&self) -> Vec<ResourceSampleRow> {
        let mut rows = self.resource_samples.clone();
        rows.sort_by(|a, b| {
            a.timestamp_ms
                .cmp(&b.timestamp_ms)
                .then_with(|| a.pid.cmp(&b.pid))
                .then_with(|| a.comm.cmp(&b.comm))
        });
        rows
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

    fn process_nodes(&self) -> Vec<ProcessNodeRow> {
        let mut rows = self.process_nodes.values().cloned().collect::<Vec<_>>();
        rows.sort_by(|a, b| {
            a.start_timestamp_ms
                .cmp(&b.start_timestamp_ms)
                .then_with(|| a.pid.cmp(&b.pid))
                .then_with(|| a.id.cmp(&b.id))
        });
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
            entry.last_seen_ms = max_optional(
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
            + self.process_nodes.len()
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
        // Agent-native sources are authoritative — prefer them over SSL-captured data.
        AGENT_NATIVE_SOURCE => 0,
        "gemini_cli_stdout_stats" => 1,
        "claude_telemetry" => 2,
        "response_usage" | "orphan_response_usage" => 3,
        _ => 4,
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

fn sort_token_summary(rows: &mut [TokenSummary]) {
    rows.sort_by(|a, b| {
        b.total_tokens
            .cmp(&a.total_tokens)
            .then_with(|| a.group.cmp(&b.group))
    });
}

fn min_optional<T: PartialOrd>(left: Option<T>, right: Option<T>) -> Option<T> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left <= right { left } else { right }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn max_optional<T: PartialOrd>(left: Option<T>, right: Option<T>) -> Option<T> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left >= right { left } else { right }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}
