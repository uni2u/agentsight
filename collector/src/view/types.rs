// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type StorageResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

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
    fn update(&mut self, _update: &ViewUpdate) {}
}
