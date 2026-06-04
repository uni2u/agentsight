// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub type ViewResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSummary {
    pub group: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_creation_tokens: i64,
    pub cache_read_tokens: i64,
    pub total_tokens: i64,
    pub calls: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageRow {
    pub id: String,
    pub llm_call_id: String,
    pub timestamp_ms: u64,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_creation_tokens: i64,
    pub cache_read_tokens: i64,
    pub total_tokens: i64,
    pub source: String,
    pub view_source: String,
    pub confidence: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmCallRow {
    pub id: String,
    pub start_timestamp_ms: u64,
    pub end_timestamp_ms: Option<u64>,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub status_code: Option<u16>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub request: Value,
    pub response: Value,
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotOptions {
    pub audit_limit: usize,
}

impl Default for SnapshotOptions {
    fn default() -> Self {
        Self {
            audit_limit: 10_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema_version: u16,
    pub generated_at: String,
    pub summary: SnapshotSummary,
    pub token_summary: Vec<TokenSummary>,
    pub network_targets: Vec<NetworkTargetRow>,
    pub audit_events: Vec<AuditEventRow>,
    pub sessions: Vec<SessionRow>,
    pub agents: Vec<AgentRow>,
}

impl Snapshot {
    pub(crate) fn empty(source: impl Into<String>) -> Self {
        Self {
            schema_version: 1,
            generated_at: String::new(),
            summary: SnapshotSummary::empty(source),
            token_summary: Vec::new(),
            network_targets: Vec::new(),
            audit_events: Vec::new(),
            sessions: Vec::new(),
            agents: Vec::new(),
        }
    }

    pub(crate) fn model_rows(&self) -> Vec<(String, i64, i64, i64, i64)> {
        let mut models = self
            .token_summary
            .iter()
            .filter(|row| row.input_tokens != 0 || row.output_tokens != 0 || row.total_tokens != 0)
            .map(|row| {
                (
                    row.group.clone(),
                    (
                        row.input_tokens,
                        row.output_tokens,
                        row.total_tokens,
                        row.calls,
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();

        for session in &self.sessions {
            if session.input_tokens == 0 && session.output_tokens == 0 && session.total_tokens == 0
            {
                continue;
            }
            let model = session
                .model
                .as_ref()
                .filter(|model| !model.is_empty())
                .cloned()
                .unwrap_or_else(|| session.agent_type.clone());
            models.entry(model).or_insert((
                session.input_tokens,
                session.output_tokens,
                session.total_tokens,
                1,
            ));
        }

        models
            .into_iter()
            .map(|(model, (input, output, total, calls))| (model, input, output, total, calls))
            .collect()
    }

    pub(crate) fn materialized_token_totals(&self) -> (i64, i64, i64) {
        if self.summary.total_tokens > 0
            || self.summary.input_tokens > 0
            || self.summary.output_tokens > 0
        {
            return (
                self.summary.input_tokens,
                self.summary.output_tokens,
                self.summary.total_tokens,
            );
        }

        let input_tokens = self.sessions.iter().map(|s| s.input_tokens).sum();
        let output_tokens = self.sessions.iter().map(|s| s.output_tokens).sum();
        let total_tokens = self.sessions.iter().map(|s| s.total_tokens).sum();
        (input_tokens, output_tokens, total_tokens)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSummary {
    pub source: String,
    pub view_events: i64,
    pub llm_calls: i64,
    pub token_usage_rows: i64,
    pub audit_events: i64,
    pub sessions: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub start_timestamp_ms: Option<u64>,
    pub end_timestamp_ms: Option<u64>,
    pub audit_limit: usize,
}

impl SnapshotSummary {
    pub(crate) fn empty(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            view_events: 0,
            llm_calls: 0,
            token_usage_rows: 0,
            audit_events: 0,
            sessions: 0,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            start_timestamp_ms: None,
            end_timestamp_ms: None,
            audit_limit: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTargetRow {
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub host: String,
    pub path: Option<String>,
    pub count: i64,
    pub error_count: i64,
    pub first_timestamp_ms: Option<u64>,
    pub last_timestamp_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSampleRow {
    pub timestamp_ms: u64,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub cpu_percent: Option<f64>,
    pub rss_mb: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventRow {
    pub id: String,
    pub timestamp_ms: u64,
    pub audit_type: String,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub subject: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub status: Option<String>,
    pub summary: Option<String>,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRow {
    pub id: String,
    pub session_id: Option<String>,
    pub conversation_id: Option<String>,
    pub timestamp_ms: u64,
    pub tool_name: Option<String>,
    pub tool_call_id: Option<String>,
    pub start_timestamp_ms: Option<u64>,
    pub end_timestamp_ms: Option<u64>,
    pub duration_ms: Option<u64>,
    pub status: Option<String>,
    pub input: Value,
    pub output: Value,
    pub related_pid: Option<u32>,
    pub related_event_id: Option<String>,
    pub view_source: String,
    pub confidence: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRow {
    pub id: String,
    pub agent_type: String,
    pub agent_name: Option<String>,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub start_timestamp_ms: u64,
    pub end_timestamp_ms: Option<u64>,
    pub status: String,
    pub model: Option<String>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub view_source: String,
    pub confidence: Option<f64>,
    pub attributes: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRow {
    pub agent_type: String,
    pub agent_name: Option<String>,
    pub sessions: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub last_seen_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "row", rename_all = "snake_case")]
pub enum ViewUpdate {
    LlmCall(LlmCallRow),
    TokenUsage(TokenUsageRow),
    AuditEvent(AuditEventRow),
    ToolCall(ToolCallRow),
    Session(SessionRow),
    NetworkTarget(NetworkTargetRow),
    ResourceSample(ResourceSampleRow),
}

pub trait ViewUpdateSink: Send {
    fn update(&mut self, update: &ViewUpdate) -> ViewResult<()>;
}
