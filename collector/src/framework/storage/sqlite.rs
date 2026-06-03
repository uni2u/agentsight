// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::framework::core::Event;
use crate::framework::semantic::{
    CanonicalEvent, EventKind, body_json, extract_model, extract_token_usage,
    extract_token_usage_from_sse, normalize_event, provider_from_host,
};
use crate::view::types::{
    AuditEventRow, LlmCallRow, NetworkTargetRow, ResourceSampleRow, SessionRow, StorageResult,
    TokenUsageRow, ToolCallRow, ViewUpdate, ViewUpdateSink,
};
use rusqlite::{Connection, params};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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

pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let conn = Connection::open(path)?;
        reject_legacy_raw_schema(&conn)?;
        let mut store = Self { conn };
        store.init()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    fn init(&mut self) -> StorageResult<()> {
        self.conn.pragma_update(None, "journal_mode", "WAL").ok();
        self.conn.pragma_update(None, "foreign_keys", "ON")?;
        self.conn.execute_batch(SCHEMA)?;
        Ok(())
    }

    pub fn apply_view_update(&mut self, update: &ViewUpdate) -> StorageResult<()> {
        self.increment_stat("ingested_events", 1)?;
        self.store_view_update(update)
    }

    fn store_view_update(&self, update: &ViewUpdate) -> StorageResult<()> {
        match update {
            ViewUpdate::LlmCall(row) => self.insert_llm_call(&LlmCallInsert {
                id: &row.id,
                start_timestamp_ms: row.start_timestamp_ms,
                end_timestamp_ms: row.end_timestamp_ms,
                pid: row.pid.unwrap_or_default(),
                comm: row.comm.as_deref().unwrap_or_default(),
                provider: row.provider.as_deref(),
                model: row.model.as_deref(),
                host: row.host.as_deref(),
                path: row.path.as_deref(),
                status_code: row.status_code,
                request_body_json: Some(&row.request.to_string()),
                response_body_json: Some(&row.response.to_string()),
                view_source: "view_jsonl",
                confidence: 1.0,
            }),
            ViewUpdate::TokenUsage(row) => self.insert_token_usage(&TokenInsert {
                id: &row.id,
                llm_call_id: &row.llm_call_id,
                timestamp_ms: row.timestamp_ms,
                pid: row.pid.unwrap_or_default(),
                comm: row.comm.as_deref().unwrap_or_default(),
                provider: row.provider.as_deref(),
                model: row.model.as_deref(),
                input_tokens: row.input_tokens,
                output_tokens: row.output_tokens,
                cache_creation_tokens: row.cache_creation_tokens,
                cache_read_tokens: row.cache_read_tokens,
                total_tokens: row.total_tokens,
                source: &row.source,
                view_source: &row.view_source,
                confidence: row.confidence.unwrap_or(1.0),
            }),
            ViewUpdate::AuditEvent(row) => self.insert_audit_event(&AuditInsert {
                id: &row.id,
                timestamp_ms: row.timestamp_ms,
                audit_type: &row.audit_type,
                pid: row.pid,
                comm: row.comm.as_deref(),
                subject: row.subject.as_deref(),
                action: row.action.as_deref(),
                target: row.target.as_deref(),
                status: row.status.as_deref(),
                summary: row.summary.as_deref(),
                details_json: &row.details.to_string(),
            }),
            ViewUpdate::ToolCall(row) => self.insert_tool_call(&ToolCallInsert {
                id: &row.id,
                session_id: row.session_id.as_deref(),
                conversation_id: row.conversation_id.as_deref(),
                timestamp_ms: row.timestamp_ms,
                tool_name: row.tool_name.as_deref(),
                tool_call_id: row.tool_call_id.as_deref(),
                start_timestamp_ms: row.start_timestamp_ms,
                end_timestamp_ms: row.end_timestamp_ms,
                duration_ms: row.duration_ms,
                status: row.status.as_deref(),
                input_json: Some(&row.input.to_string()),
                output_json: Some(&row.output.to_string()),
                related_pid: row.related_pid,
                related_event_id: row.related_event_id.as_deref(),
                view_source: &row.view_source,
                confidence: row.confidence.unwrap_or(1.0),
            }),
            ViewUpdate::Session(row) => self.upsert_session(&SessionUpsert {
                id: &row.id,
                agent_type: &row.agent_type,
                agent_name: row.agent_name.as_deref(),
                pid: row.pid,
                comm: row.comm.as_deref(),
                start_timestamp_ms: row.start_timestamp_ms,
                end_timestamp_ms: row.end_timestamp_ms,
                status: &row.status,
                model: row.model.as_deref(),
                input_tokens: row.input_tokens,
                output_tokens: row.output_tokens,
                total_tokens: row.total_tokens,
                view_source: &row.view_source,
                confidence: row.confidence.unwrap_or(1.0) as f32,
                attributes_json: &row.attributes.to_string(),
            }),
            ViewUpdate::NetworkTarget(row) => self.upsert_network_target(row),
            ViewUpdate::ResourceSample(row) => self.insert_resource_sample(row),
        }
    }

    fn increment_stat(&self, key: &str, delta: i64) -> StorageResult<()> {
        self.conn.execute(
            "INSERT INTO view_stats (key, value)
             VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = value + excluded.value",
            params![key, delta],
        )?;
        Ok(())
    }

    fn view_stat(&self, key: &str) -> StorageResult<i64> {
        Ok(self
            .conn
            .query_row(
                "SELECT COALESCE(value, 0) FROM view_stats WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .unwrap_or(0))
    }

    fn upsert_network_target(&self, target: &NetworkTargetRow) -> StorageResult<()> {
        let id = format!(
            "net-{}-{}-{}",
            target.pid.unwrap_or(0),
            sanitize_id(&target.host),
            sanitize_id(target.path.as_deref().unwrap_or(""))
        );
        self.conn.execute(
            "INSERT INTO network_targets (
                id, pid, comm, host, path, count, error_count, first_timestamp_ms, last_timestamp_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
                count = count + excluded.count,
                error_count = error_count + excluded.error_count,
                first_timestamp_ms = MIN(first_timestamp_ms, excluded.first_timestamp_ms),
                last_timestamp_ms = MAX(last_timestamp_ms, excluded.last_timestamp_ms)",
            params![
                id,
                target.pid.map(|v| v as i64),
                target.comm.as_deref(),
                target.host.as_str(),
                target.path.as_deref(),
                target.count,
                target.error_count,
                target.first_timestamp_ms.map(|v| v as i64),
                target.last_timestamp_ms.map(|v| v as i64),
            ],
        )?;
        Ok(())
    }

    fn insert_resource_sample(&self, sample: &ResourceSampleRow) -> StorageResult<()> {
        self.conn.execute(
            "INSERT INTO resource_samples (timestamp_ms, pid, comm, cpu_percent, rss_mb)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                sample.timestamp_ms as i64,
                sample.pid.map(|v| v as i64),
                sample.comm.as_deref(),
                sample.cpu_percent,
                sample.rss_mb,
            ],
        )?;
        Ok(())
    }

    fn insert_llm_call(&self, call: &LlmCallInsert<'_>) -> StorageResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO llm_calls (
                id, start_timestamp_ms, end_timestamp_ms, pid, comm, provider, model,
                host, path, status_code, request_body_json, response_body_json,
                view_source, confidence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                call.id,
                call.start_timestamp_ms as i64,
                call.end_timestamp_ms.map(|v| v as i64),
                call.pid as i64,
                call.comm,
                call.provider,
                call.model,
                call.host,
                call.path,
                call.status_code.map(|v| v as i64),
                call.request_body_json,
                call.response_body_json,
                call.view_source,
                call.confidence,
            ],
        )?;
        Ok(())
    }

    fn insert_token_usage(&self, token: &TokenInsert<'_>) -> StorageResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO token_usage (
                id, llm_call_id, timestamp_ms, pid, comm, provider, model,
                input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens,
                total_tokens, source, view_source, confidence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                token.id,
                token.llm_call_id,
                token.timestamp_ms as i64,
                token.pid as i64,
                token.comm,
                token.provider,
                token.model,
                token.input_tokens,
                token.output_tokens,
                token.cache_creation_tokens,
                token.cache_read_tokens,
                token.total_tokens,
                token.source,
                token.view_source,
                token.confidence,
            ],
        )?;
        Ok(())
    }

    fn insert_audit_event(&self, audit: &AuditInsert<'_>) -> StorageResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO audit_events (
                id, timestamp_ms, audit_type, pid, comm, subject,
                action, target, status, summary, details_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                audit.id,
                audit.timestamp_ms as i64,
                audit.audit_type,
                audit.pid.map(|v| v as i64),
                audit.comm,
                audit.subject,
                audit.action,
                audit.target,
                audit.status,
                audit.summary,
                audit.details_json,
            ],
        )?;
        Ok(())
    }

    fn insert_tool_call(&self, tool: &ToolCallInsert<'_>) -> StorageResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO tool_calls (
                id, session_id, conversation_id, timestamp_ms, tool_name, tool_call_id,
                start_timestamp_ms, end_timestamp_ms, duration_ms, status, input_json,
                output_json, related_pid, related_event_id, view_source, confidence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                tool.id,
                tool.session_id,
                tool.conversation_id,
                tool.timestamp_ms as i64,
                tool.tool_name,
                tool.tool_call_id,
                tool.start_timestamp_ms.map(|v| v as i64),
                tool.end_timestamp_ms.map(|v| v as i64),
                tool.duration_ms.map(|v| v as i64),
                tool.status,
                tool.input_json,
                tool.output_json,
                tool.related_pid.map(|v| v as i64),
                tool.related_event_id,
                tool.view_source,
                tool.confidence,
            ],
        )?;
        Ok(())
    }

    fn upsert_session(&self, session: &SessionUpsert<'_>) -> StorageResult<()> {
        self.conn.execute(
            "INSERT INTO agent_sessions (
                id, agent_type, agent_name, pid, comm, start_timestamp_ms, end_timestamp_ms,
                status, model, input_tokens, output_tokens, total_tokens, view_source, confidence,
                attributes_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(id) DO UPDATE SET
                start_timestamp_ms = MIN(start_timestamp_ms, excluded.start_timestamp_ms),
                end_timestamp_ms = MAX(COALESCE(end_timestamp_ms, 0), COALESCE(excluded.end_timestamp_ms, 0)),
                status = excluded.status,
                model = COALESCE(NULLIF(excluded.model, 'unknown'), model, excluded.model),
                input_tokens = input_tokens + excluded.input_tokens,
                output_tokens = output_tokens + excluded.output_tokens,
                total_tokens = total_tokens + excluded.total_tokens,
                confidence = MAX(COALESCE(confidence, 0), COALESCE(excluded.confidence, 0))",
            params![
                session.id,
                session.agent_type,
                session.agent_name,
                session.pid.map(|v| v as i64),
                session.comm,
                session.start_timestamp_ms as i64,
                session.end_timestamp_ms.map(|v| v as i64),
                session.status,
                session.model,
                session.input_tokens,
                session.output_tokens,
                session.total_tokens,
                session.view_source,
                session.confidence,
                session.attributes_json,
            ],
        )?;
        Ok(())
    }

    pub fn llm_call_rows(&self, limit: usize) -> StorageResult<Vec<LlmCallRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, start_timestamp_ms, end_timestamp_ms, pid, comm,
                    provider, model, host, path, status_code,
                    COALESCE(request_body_json, '{}'), COALESCE(response_body_json, '{}')
             FROM llm_calls
             ORDER BY start_timestamp_ms DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.clamp(1, 10_000) as i64], |row| {
            let request_json: String = row.get(10)?;
            let response_json: String = row.get(11)?;
            Ok(LlmCallRow {
                id: row.get(0)?,
                start_timestamp_ms: row.get::<_, i64>(1)? as u64,
                end_timestamp_ms: row.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                pid: row.get::<_, Option<i64>>(3)?.map(|v| v as u32),
                comm: row.get(4)?,
                provider: row.get(5)?,
                model: row.get(6)?,
                host: row.get(7)?,
                path: row.get(8)?,
                status_code: row.get::<_, Option<i64>>(9)?.map(|v| v as u16),
                input_tokens: 0,
                output_tokens: 0,
                total_tokens: 0,
                request: parse_json_value(&request_json),
                response: parse_json_value(&response_json),
            })
        })?;
        collect_rows(rows)
    }

    pub fn token_usage_rows(&self) -> StorageResult<Vec<TokenUsageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, llm_call_id, timestamp_ms, pid, comm, provider, model,
                    input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens,
                    total_tokens, source, view_source, confidence
             FROM token_usage
             ORDER BY timestamp_ms, id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TokenUsageRow {
                id: row.get(0)?,
                llm_call_id: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                timestamp_ms: row.get::<_, i64>(2)? as u64,
                pid: row.get::<_, Option<i64>>(3)?.map(|v| v as u32),
                comm: row.get(4)?,
                provider: row.get(5)?,
                model: row.get(6)?,
                input_tokens: row.get(7)?,
                output_tokens: row.get(8)?,
                cache_creation_tokens: row.get(9)?,
                cache_read_tokens: row.get(10)?,
                total_tokens: row.get(11)?,
                source: row
                    .get::<_, Option<String>>(12)?
                    .unwrap_or_else(|| "unknown".to_string()),
                view_source: row
                    .get::<_, Option<String>>(13)?
                    .unwrap_or_else(|| "view".to_string()),
                confidence: row.get(14)?,
            })
        })?;
        collect_rows(rows)
    }

    pub fn tool_call_rows(&self) -> StorageResult<Vec<ToolCallRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, conversation_id, timestamp_ms, tool_name, tool_call_id,
                    start_timestamp_ms, end_timestamp_ms, duration_ms, status, input_json,
                    output_json, related_pid, related_event_id, view_source, confidence
             FROM tool_calls
             ORDER BY timestamp_ms, id",
        )?;
        let rows = stmt.query_map([], |row| {
            let input_json: Option<String> = row.get(10)?;
            let output_json: Option<String> = row.get(11)?;
            Ok(ToolCallRow {
                id: row.get(0)?,
                session_id: row.get(1)?,
                conversation_id: row.get(2)?,
                timestamp_ms: row.get::<_, i64>(3)? as u64,
                tool_name: row.get(4)?,
                tool_call_id: row.get(5)?,
                start_timestamp_ms: row.get::<_, Option<i64>>(6)?.map(|v| v as u64),
                end_timestamp_ms: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                duration_ms: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
                status: row.get(9)?,
                input: parse_optional_json(input_json.as_deref()),
                output: parse_optional_json(output_json.as_deref()),
                related_pid: row.get::<_, Option<i64>>(12)?.map(|v| v as u32),
                related_event_id: row.get(13)?,
                view_source: row.get(14)?,
                confidence: row.get(15)?,
            })
        })?;
        collect_rows(rows)
    }

    pub fn resource_sample_rows(&self) -> StorageResult<Vec<ResourceSampleRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ms, pid, comm, cpu_percent, rss_mb
             FROM resource_samples
             ORDER BY timestamp_ms",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ResourceSampleRow {
                timestamp_ms: row.get::<_, i64>(0)? as u64,
                pid: row.get::<_, Option<i64>>(1)?.map(|v| v as u32),
                comm: row.get(2)?,
                cpu_percent: row.get(3)?,
                rss_mb: row.get(4)?,
            })
        })?;
        collect_rows(rows)
    }

    pub fn ingested_event_count(&self) -> StorageResult<i64> {
        self.view_stat("ingested_events")
    }

    pub fn network_target_rows(&self) -> StorageResult<Vec<NetworkTargetRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT pid, comm, host, path, count, error_count, first_timestamp_ms, last_timestamp_ms
             FROM network_targets
             ORDER BY count DESC, host, path",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(NetworkTargetRow {
                pid: row.get::<_, Option<i64>>(0)?.map(|v| v as u32),
                comm: row.get(1)?,
                host: row.get(2)?,
                path: row.get(3)?,
                count: row.get(4)?,
                error_count: row.get(5)?,
                first_timestamp_ms: row.get::<_, Option<i64>>(6)?.map(|v| v as u64),
                last_timestamp_ms: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
            })
        })?;
        collect_rows(rows)
    }

    pub fn audit_event_rows(&self, limit: usize) -> StorageResult<Vec<AuditEventRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp_ms, audit_type, pid, comm, subject, action,
                    target, status, summary, details_json
             FROM audit_events
             ORDER BY timestamp_ms, id
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![bounded_limit(limit)], |row| {
            let details_json: String = row.get(10)?;
            Ok(AuditEventRow {
                id: row.get(0)?,
                timestamp_ms: row.get::<_, i64>(1)? as u64,
                audit_type: row.get(2)?,
                pid: row.get::<_, Option<i64>>(3)?.map(|v| v as u32),
                comm: row.get(4)?,
                subject: row.get(5)?,
                action: row.get(6)?,
                target: row.get(7)?,
                status: row.get(8)?,
                summary: row.get(9)?,
                details: parse_json_value(&details_json),
            })
        })?;
        collect_rows(rows)
    }

    pub fn session_rows(&self) -> StorageResult<Vec<SessionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, agent_type, agent_name, pid, comm, start_timestamp_ms,
                    NULLIF(end_timestamp_ms, 0), status, model, input_tokens, output_tokens,
                    total_tokens, view_source, confidence, attributes_json
             FROM agent_sessions
             ORDER BY start_timestamp_ms, id",
        )?;
        let rows = stmt.query_map([], |row| {
            let attributes_json: String = row.get(14)?;
            Ok(SessionRow {
                id: row.get(0)?,
                agent_type: row.get(1)?,
                agent_name: row.get(2)?,
                pid: row.get::<_, Option<i64>>(3)?.map(|v| v as u32),
                comm: row.get(4)?,
                start_timestamp_ms: row.get::<_, i64>(5)? as u64,
                end_timestamp_ms: row.get::<_, Option<i64>>(6)?.map(|v| v as u64),
                status: row.get(7)?,
                model: row.get(8)?,
                input_tokens: row.get(9)?,
                output_tokens: row.get(10)?,
                total_tokens: row.get(11)?,
                view_source: row.get(12)?,
                confidence: row.get(13)?,
                attributes: parse_json_value(&attributes_json),
            })
        })?;
        collect_rows(rows)
    }

}

#[derive(Default)]
pub struct ViewProjector {
    pending: HashMap<(u32, u64), VecDeque<PendingRequest>>,
    sinks: Vec<Box<dyn ViewUpdateSink>>,
    emitted: Vec<ViewUpdate>,
    next_seq: u64,
}

impl ViewProjector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_sink(&mut self, sink: Box<dyn ViewUpdateSink>) {
        self.sinks.push(sink);
    }

    pub fn drain_updates(&mut self) -> Vec<ViewUpdate> {
        std::mem::take(&mut self.emitted)
    }

    pub fn notify_update(&mut self, update: &ViewUpdate) {
        for sink in &mut self.sinks {
            sink.update(update);
        }
    }

    pub fn ingest_event(&mut self, event: &Event) -> StorageResult<CanonicalEvent> {
        self.next_seq += 1;
        let raw_id = format!(
            "event-{}-{}-{}-{}",
            event.timestamp,
            sanitize_id(&event.source),
            event.pid,
            self.next_seq
        );
        let canonical = normalize_event(event, raw_id, now_ms());
        if let Some(sample) = resource_sample_from_event(&canonical) {
            self.emit(ViewUpdate::ResourceSample(sample));
        }
        if let Some(target) = network_target_from_event(&canonical) {
            self.emit(ViewUpdate::NetworkTarget(target));
        }
        self.ingest(&canonical)?;
        Ok(canonical)
    }

    fn emit(&mut self, update: ViewUpdate) {
        for sink in &mut self.sinks {
            sink.update(&update);
        }
        self.emitted.push(update);
    }

    fn insert_llm_call(&mut self, call: &LlmCallInsert<'_>) -> StorageResult<LlmCallRow> {
        Ok(call.to_row())
    }

    fn insert_token_usage(&mut self, token: &TokenInsert<'_>) -> StorageResult<TokenUsageRow> {
        let row = token.to_row();
        self.emit(ViewUpdate::TokenUsage(row.clone()));
        Ok(row)
    }

    fn insert_audit_event(&mut self, audit: &AuditInsert<'_>) -> StorageResult<AuditEventRow> {
        let row = audit.to_row();
        self.emit(ViewUpdate::AuditEvent(row.clone()));
        Ok(row)
    }

    fn insert_tool_call(&mut self, tool: &ToolCallInsert<'_>) -> StorageResult<ToolCallRow> {
        let row = tool.to_row();
        self.emit(ViewUpdate::ToolCall(row.clone()));
        Ok(row)
    }

    fn upsert_session(&mut self, session: &SessionUpsert<'_>) -> StorageResult<SessionRow> {
        let row = session.to_row();
        self.emit(ViewUpdate::Session(row.clone()));
        Ok(row)
    }

    fn ingest(&mut self, event: &CanonicalEvent) -> StorageResult<()> {
        self.ingest_agent_specific_event(event)?;
        match event.kind {
            EventKind::LlmRequest => self.ingest_llm_request(event)?,
            EventKind::HttpResponse | EventKind::LlmResponse | EventKind::LlmError => {
                self.ingest_llm_response(event)?
            }
            EventKind::ProcessExec => self.ingest_process_audit(event, "exec")?,
            EventKind::ProcessExit => self.ingest_process_audit(event, "exit")?,
            EventKind::FsOpen if is_writable_open(event) => self.ingest_file_audit(event)?,
            EventKind::FsWrite | EventKind::FsMutation => self.ingest_file_audit(event)?,
            _ => {}
        }
        Ok(())
    }

    fn ingest_llm_request(&mut self, event: &CanonicalEvent) -> StorageResult<()> {
        let (Some(pid), Some(tid)) = (event.pid, event.tid) else {
            return Ok(());
        };
        let req = PendingRequest {
            event_id: event.event_id.clone(),
            timestamp_ms: event.timestamp_ms,
            pid,
            comm: event.comm.clone().unwrap_or_default(),
            provider: event.provider.clone(),
            model: event.model.clone(),
            host: event.host.clone(),
            path: event.path.clone(),
            request_id: event.request_id.clone(),
            body_json: body_json(&event.attributes),
        };
        self.insert_orphan_llm_request(&req)?;
        self.pending.entry((pid, tid)).or_default().push_back(req);
        Ok(())
    }

    fn ingest_llm_response(&mut self, event: &CanonicalEvent) -> StorageResult<()> {
        let Some(pid) = event.pid else {
            return Ok(());
        };
        if let Some(tid) = event.tid
            && let Some((req, confidence)) = self.take_matching_request(pid, tid, event)
        {
            return self.upsert_llm_pair(req, event, confidence);
        }
        self.insert_orphan_llm_response(event)
    }

    fn take_matching_request(
        &mut self,
        pid: u32,
        tid: u64,
        resp: &CanonicalEvent,
    ) -> Option<(PendingRequest, f32)> {
        let requests = self.pending.get_mut(&(pid, tid))?;
        let (req, confidence) = if let Some(resp_request_id) = resp.request_id.as_deref() {
            let pos = requests
                .iter()
                .position(|req| req.request_id.as_deref() == Some(resp_request_id))?;
            (requests.remove(pos)?, 0.95)
        } else if requests.len() == 1 {
            (requests.pop_front()?, 0.75)
        } else {
            return None;
        };
        if requests.is_empty() {
            self.pending.remove(&(pid, tid));
        }
        Some((req, confidence))
    }

    fn upsert_llm_pair(
        &mut self,
        req: PendingRequest,
        resp: &CanonicalEvent,
        confidence: f32,
    ) -> StorageResult<()> {
        let response_body = response_body_json(resp);
        let model = req
            .model
            .clone()
            .or_else(|| response_body.as_ref().and_then(extract_model))
            .or_else(|| resp.model.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let provider = req
            .provider
            .clone()
            .or_else(|| req.host.as_deref().map(provider_from_host));
        let llm_call_id = format!("llm-{}", req.event_id);
        let request_body_json = req.body_json.as_ref().map(Value::to_string);
        let response_body_json = response_body.as_ref().map(Value::to_string);
        let status_code = resp.status_code;
        let mut call_row = self.insert_llm_call(&LlmCallInsert {
            id: &llm_call_id,
            start_timestamp_ms: req.timestamp_ms,
            end_timestamp_ms: Some(resp.timestamp_ms),
            pid: req.pid,
            comm: &req.comm,
            provider: provider.as_deref(),
            model: Some(&model),
            host: req.host.as_deref(),
            path: req.path.as_deref(),
            status_code,
            request_body_json: request_body_json.as_deref(),
            response_body_json: response_body_json.as_deref(),
            view_source: "view",
            confidence,
        })?;
        if let Some(usage) = self.ingest_response_usage_and_tools(
            resp,
            &llm_call_id,
            req.pid,
            &req.comm,
            provider.as_deref(),
            &model,
            req.host.as_deref(),
            request_body_json.as_deref(),
            response_body_json.as_deref(),
            confidence,
        )? {
            call_row.input_tokens = usage.input_tokens;
            call_row.output_tokens = usage.output_tokens;
            call_row.total_tokens = usage.total_tokens;
        }
        self.insert_audit_event(&AuditInsert {
            id: &format!("audit-{llm_call_id}"),
            timestamp_ms: resp.timestamp_ms,
            audit_type: "llm",
            pid: Some(req.pid),
            comm: Some(&req.comm),
            subject: Some(&model),
            action: Some("call"),
            target: req.host.as_deref(),
            status: Some(if status_code.map(|c| c >= 400).unwrap_or(false) {
                "failure"
            } else {
                "success"
            }),
            summary: Some("LLM call"),
            details_json: response_body_json.as_deref().unwrap_or("{}"),
        })?;
        self.emit(ViewUpdate::LlmCall(call_row.clone()));
        Ok(())
    }

    fn insert_orphan_llm_request(&mut self, req: &PendingRequest) -> StorageResult<()> {
        let llm_call_id = format!("llm-{}", req.event_id);
        let provider = req
            .provider
            .clone()
            .or_else(|| req.host.as_deref().map(provider_from_host));
        let request_body_json = req.body_json.as_ref().map(Value::to_string);
        let call_row = self.insert_llm_call(&LlmCallInsert {
            id: &llm_call_id,
            start_timestamp_ms: req.timestamp_ms,
            end_timestamp_ms: None,
            pid: req.pid,
            comm: &req.comm,
            provider: provider.as_deref(),
            model: req.model.as_deref(),
            host: req.host.as_deref(),
            path: req.path.as_deref(),
            status_code: None,
            request_body_json: request_body_json.as_deref(),
            response_body_json: None,
            view_source: "view",
            confidence: 0.40,
        })?;
        self.insert_audit_event(&AuditInsert {
            id: &format!("audit-{llm_call_id}"),
            timestamp_ms: req.timestamp_ms,
            audit_type: "llm",
            pid: Some(req.pid),
            comm: Some(&req.comm),
            subject: req.model.as_deref(),
            action: Some("request"),
            target: req.host.as_deref(),
            status: Some("orphan_request"),
            summary: Some("LLM request"),
            details_json: request_body_json.as_deref().unwrap_or("{}"),
        })?;
        self.emit(ViewUpdate::LlmCall(call_row.clone()));
        Ok(())
    }

    fn insert_orphan_llm_response(&mut self, resp: &CanonicalEvent) -> StorageResult<()> {
        let response_body = response_body_json(resp);
        let response_body_text = response_body.as_ref().map(Value::to_string);
        let model = resp
            .model
            .clone()
            .or_else(|| response_body.as_ref().and_then(extract_model))
            .unwrap_or_else(|| "unknown".to_string());
        let provider = resp
            .provider
            .clone()
            .or_else(|| resp.host.as_deref().map(provider_from_host));
        let pid = resp.pid.unwrap_or(0);
        let comm = resp.comm.clone().unwrap_or_default();
        let llm_call_id = format!("llm-orphan-{}", resp.event_id);
        let mut call_row = self.insert_llm_call(&LlmCallInsert {
            id: &llm_call_id,
            start_timestamp_ms: resp.timestamp_ms,
            end_timestamp_ms: Some(resp.timestamp_ms),
            pid,
            comm: &comm,
            provider: provider.as_deref(),
            model: Some(&model),
            host: resp.host.as_deref(),
            path: resp.path.as_deref(),
            status_code: resp.status_code,
            request_body_json: None,
            response_body_json: response_body_text.as_deref(),
            view_source: "view",
            confidence: 0.35,
        })?;
        if let Some(usage) = self.ingest_response_usage_and_tools(
            resp,
            &llm_call_id,
            pid,
            &comm,
            provider.as_deref(),
            &model,
            resp.host.as_deref(),
            None,
            response_body_text.as_deref(),
            0.35,
        )? {
            call_row.input_tokens = usage.input_tokens;
            call_row.output_tokens = usage.output_tokens;
            call_row.total_tokens = usage.total_tokens;
        }
        self.insert_audit_event(&AuditInsert {
            id: &format!("audit-{llm_call_id}"),
            timestamp_ms: resp.timestamp_ms,
            audit_type: "llm",
            pid: Some(pid),
            comm: Some(&comm),
            subject: Some(&model),
            action: Some("response"),
            target: resp.host.as_deref(),
            status: Some("orphan_response"),
            summary: Some("LLM response"),
            details_json: response_body_text.as_deref().unwrap_or("{}"),
        })?;
        self.emit(ViewUpdate::LlmCall(call_row.clone()));
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn ingest_response_usage_and_tools(
        &mut self,
        resp: &CanonicalEvent,
        llm_call_id: &str,
        pid: u32,
        comm: &str,
        provider: Option<&str>,
        model: &str,
        host: Option<&str>,
        request_body_json: Option<&str>,
        response_body_json: Option<&str>,
        confidence: f32,
    ) -> StorageResult<Option<TokenUsageRow>> {
        let response_body =
            response_body_json.and_then(|text| serde_json::from_str::<Value>(text).ok());
        let usage = if resp.source == "sse_processor" {
            extract_token_usage_from_sse(&resp.attributes)
        } else {
            response_body
                .as_ref()
                .map(extract_token_usage)
                .unwrap_or_default()
        };
        let mut usage_row = None;
        if !usage.is_empty() {
            let token_id = format!("token-{llm_call_id}");
            usage_row = Some(self.insert_token_usage(&TokenInsert {
                id: &token_id,
                llm_call_id,
                timestamp_ms: resp.timestamp_ms,
                pid,
                comm,
                provider,
                model: Some(model),
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cache_creation_tokens: usage.cache_creation_tokens,
                cache_read_tokens: usage.cache_read_tokens,
                total_tokens: usage.total_tokens(),
                source: "response_usage",
                view_source: "view",
                confidence,
            })?);
            self.upsert_known_agent_session(
                pid,
                comm,
                resp.timestamp_ms,
                Some(resp.timestamp_ms),
                provider,
                host,
                Some(model),
                usage.input_tokens,
                usage.output_tokens,
                usage.total_tokens(),
                request_body_json,
                response_body_json,
                confidence,
            )?;
        }
        self.ingest_sse_tools(resp, llm_call_id, pid, confidence)?;
        Ok(usage_row)
    }

    fn ingest_agent_specific_event(&mut self, event: &CanonicalEvent) -> StorageResult<()> {
        self.ingest_claude_telemetry(event)?;
        self.ingest_gemini_stdio_stats(event)
    }

    fn ingest_claude_telemetry(&mut self, event: &CanonicalEvent) -> StorageResult<()> {
        let host = event.host.as_deref().unwrap_or_default();
        if !host.contains("datadoghq.com") && event.source != "ssl" {
            return Ok(());
        }
        let body = body_json(&event.attributes).or_else(|| {
            event
                .attributes
                .get("data")
                .and_then(|v| v.as_str())
                .and_then(parse_json_str)
        });
        let Some(Value::Array(items)) = body else {
            return Ok(());
        };
        let pid = event.pid.unwrap_or(0);
        let comm = event.comm.as_deref().unwrap_or_default();
        for (idx, item) in items.iter().enumerate() {
            let message = item
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if message == "tengu_api_success" {
                let input = json_i64(item, "input_tokens");
                let output = json_i64(item, "output_tokens");
                let cache = json_i64(item, "cached_input_tokens");
                let total = input + output + cache;
                if total <= 0 {
                    continue;
                }
                let model = item
                    .get("model")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let llm_call_id = format!("claude-telemetry-{}-{idx}", event.event_id);
                self.insert_token_usage(&TokenInsert {
                    id: &format!("token-{llm_call_id}"),
                    llm_call_id: &llm_call_id,
                    timestamp_ms: event.timestamp_ms,
                    pid,
                    comm,
                    provider: Some("anthropic"),
                    model: Some(model),
                    input_tokens: input,
                    output_tokens: output,
                    cache_creation_tokens: 0,
                    cache_read_tokens: cache,
                    total_tokens: total,
                    source: "claude_telemetry",
                    view_source: "view",
                    confidence: 0.80,
                })?;
                self.upsert_session_for_agent(
                    "claude-code",
                    "Claude Code",
                    pid,
                    comm,
                    event.timestamp_ms,
                    Some(event.timestamp_ms),
                    Some(model),
                    input,
                    output,
                    total,
                    0.80,
                    "claude-telemetry",
                )?;
            } else if message == "tengu_tool_use_success" {
                let tool_name = item.get("tool_name").and_then(Value::as_str).unwrap_or("?");
                let duration_ms = item
                    .get("duration_ms")
                    .and_then(Value::as_i64)
                    .map(|v| v as u64);
                let request_id = item.get("request_id").and_then(Value::as_str);
                self.insert_tool_call(&ToolCallInsert {
                    id: &format!("claude-tool-telemetry-{}-{idx}", event.event_id),
                    session_id: Some(&format!("claude-code-pid-{pid}")),
                    conversation_id: None,
                    timestamp_ms: event.timestamp_ms,
                    tool_name: Some(tool_name),
                    tool_call_id: request_id,
                    start_timestamp_ms: duration_ms.and_then(|d| event.timestamp_ms.checked_sub(d)),
                    end_timestamp_ms: Some(event.timestamp_ms),
                    duration_ms,
                    status: Some("completed"),
                    input_json: Some("{}"),
                    output_json: Some("{}"),
                    related_pid: Some(pid),
                    related_event_id: Some(event.event_id.as_str()),
                    view_source: "view",
                    confidence: 0.75,
                })?;
            }
        }
        Ok(())
    }

    fn ingest_gemini_stdio_stats(&mut self, event: &CanonicalEvent) -> StorageResult<()> {
        if !matches!(event.kind, EventKind::StdioMessage | EventKind::StdioRpc) {
            return Ok(());
        }
        let Some(payload) = event.attributes.get("data").and_then(Value::as_str) else {
            return Ok(());
        };
        let Some(obj) = parse_json_str(payload) else {
            return Ok(());
        };
        let Some(models) = obj.pointer("/stats/models").and_then(Value::as_object) else {
            return Ok(());
        };
        let pid = event.pid.unwrap_or(0);
        let comm = event.comm.as_deref().unwrap_or("gemini");
        for (model, stats) in models {
            let tokens = stats.get("tokens").unwrap_or(stats);
            let input = json_i64(tokens, "prompt").max(json_i64(tokens, "input"));
            let output = json_i64(tokens, "candidates")
                + json_i64(tokens, "thoughts")
                + json_i64(tokens, "tool");
            let cache = json_i64(tokens, "cached");
            let total = json_i64(tokens, "total").max(input + output + cache);
            if total <= 0 {
                continue;
            }
            let llm_call_id = format!("gemini-stdout-{}-{}", event.event_id, sanitize_id(model));
            self.insert_token_usage(&TokenInsert {
                id: &format!("token-{llm_call_id}"),
                llm_call_id: &llm_call_id,
                timestamp_ms: event.timestamp_ms,
                pid,
                comm,
                provider: Some("gcp.gen_ai"),
                model: Some(model),
                input_tokens: input,
                output_tokens: output,
                cache_creation_tokens: 0,
                cache_read_tokens: cache,
                total_tokens: total,
                source: "gemini_cli_stdout_stats",
                view_source: "view",
                confidence: 0.85,
            })?;
            self.upsert_session_for_agent(
                "gemini-cli",
                "Gemini CLI",
                pid,
                comm,
                event.timestamp_ms,
                Some(event.timestamp_ms),
                Some(model),
                input,
                output,
                total,
                0.85,
                "gemini-stdio",
            )?;
        }
        Ok(())
    }

    fn ingest_sse_tools(
        &mut self,
        event: &CanonicalEvent,
        llm_call_id: &str,
        pid: u32,
        confidence: f32,
    ) -> StorageResult<()> {
        let Some(events) = event.attributes.get("sse_events").and_then(Value::as_array) else {
            return Ok(());
        };
        let session_id = classify_agent(
            event.comm.as_deref().unwrap_or_default(),
            event.host.as_deref(),
            None,
            Some(&event.attributes.to_string()),
            event.model.as_deref(),
        )
        .map(|agent| format!("{}-pid-{pid}", agent.agent_type));
        for (idx, sse) in events.iter().enumerate() {
            let Some(block) = sse.pointer("/parsed_data/content_block") else {
                continue;
            };
            if block.get("type").and_then(Value::as_str) != Some("tool_use") {
                continue;
            }
            let name = block.get("name").and_then(Value::as_str).unwrap_or("?");
            let tool_call_id = block.get("id").and_then(Value::as_str);
            let input_json = block.get("input").map(Value::to_string);
            let tool_id = tool_call_id
                .map(str::to_string)
                .unwrap_or_else(|| format!("tool-{idx}"));
            self.insert_tool_call(&ToolCallInsert {
                id: &format!("tool-{llm_call_id}-{tool_id}"),
                session_id: session_id.as_deref(),
                conversation_id: Some(&format!("conv-{llm_call_id}")),
                timestamp_ms: event.timestamp_ms,
                tool_name: Some(name),
                tool_call_id,
                start_timestamp_ms: Some(event.timestamp_ms),
                end_timestamp_ms: None,
                duration_ms: None,
                status: Some("observed"),
                input_json: input_json.as_deref(),
                output_json: None,
                related_pid: Some(pid),
                related_event_id: Some(event.event_id.as_str()),
                view_source: "view",
                confidence,
            })?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert_known_agent_session(
        &mut self,
        pid: u32,
        comm: &str,
        start_timestamp_ms: u64,
        end_timestamp_ms: Option<u64>,
        provider: Option<&str>,
        host: Option<&str>,
        model: Option<&str>,
        input_tokens: i64,
        output_tokens: i64,
        total_tokens: i64,
        request_body_json: Option<&str>,
        response_body_json: Option<&str>,
        confidence: f32,
    ) -> StorageResult<()> {
        let classifier_text = [request_body_json, response_body_json]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n");
        let agent = classify_agent(comm, host.or(provider), Some(&classifier_text), None, model);
        if let Some(agent) = agent {
            self.upsert_session_for_agent(
                agent.agent_type,
                agent.agent_name,
                pid,
                comm,
                start_timestamp_ms,
                end_timestamp_ms,
                model,
                input_tokens,
                output_tokens,
                total_tokens,
                confidence,
                "llm",
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert_session_for_agent(
        &mut self,
        agent_type: &'static str,
        agent_name: &'static str,
        pid: u32,
        comm: &str,
        start_timestamp_ms: u64,
        end_timestamp_ms: Option<u64>,
        model: Option<&str>,
        input_tokens: i64,
        output_tokens: i64,
        total_tokens: i64,
        confidence: f32,
        view_source: &str,
    ) -> StorageResult<()> {
        let id = format!("{agent_type}-pid-{pid}");
        let attrs = serde_json::json!({ "source": view_source }).to_string();
        self.upsert_session(&SessionUpsert {
            id: &id,
            agent_type,
            agent_name: Some(agent_name),
            pid: Some(pid),
            comm: Some(comm),
            start_timestamp_ms,
            end_timestamp_ms,
            model,
            input_tokens,
            output_tokens,
            total_tokens,
            view_source: "view",
            confidence,
            status: "observed",
            attributes_json: &attrs,
        })?;
        Ok(())
    }

    fn ingest_process_audit(&mut self, event: &CanonicalEvent, action: &str) -> StorageResult<()> {
        let target = event.attributes.get("filename").and_then(Value::as_str);
        self.insert_audit_event(&AuditInsert {
            id: &format!("audit-{}", event.event_id),
            timestamp_ms: event.timestamp_ms,
            audit_type: "process",
            pid: event.pid,
            comm: event.comm.as_deref(),
            subject: event.comm.as_deref(),
            action: Some(action),
            target,
            status: Some(process_audit_status(action, &event.attributes)),
            summary: event.summary.as_deref(),
            details_json: &event.attributes.to_string(),
        })?;
        Ok(())
    }

    fn ingest_file_audit(&mut self, event: &CanonicalEvent) -> StorageResult<()> {
        let target = event
            .attributes
            .get("path")
            .or_else(|| event.attributes.get("filepath"))
            .and_then(Value::as_str);
        self.insert_audit_event(&AuditInsert {
            id: &format!("audit-{}", event.event_id),
            timestamp_ms: event.timestamp_ms,
            audit_type: "file",
            pid: event.pid,
            comm: event.comm.as_deref(),
            subject: event.comm.as_deref(),
            action: Some("write"),
            target,
            status: Some("observed"),
            summary: event.summary.as_deref(),
            details_json: &event.attributes.to_string(),
        })?;
        Ok(())
    }
}

struct AgentClass {
    agent_type: &'static str,
    agent_name: &'static str,
}

fn classify_agent(
    comm: &str,
    host: Option<&str>,
    request_text: Option<&str>,
    response_text: Option<&str>,
    model: Option<&str>,
) -> Option<AgentClass> {
    let haystack = [Some(comm), host, request_text, response_text, model]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    if haystack.contains("openclaw") {
        Some(AgentClass {
            agent_type: "openclaw",
            agent_name: "OpenClaw",
        })
    } else if haystack.contains("gemini")
        || haystack.contains("cloudcode-pa.googleapis.com")
        || haystack.contains("generativelanguage")
    {
        Some(AgentClass {
            agent_type: "gemini-cli",
            agent_name: "Gemini CLI",
        })
    } else if haystack.contains("claude") || haystack.contains("anthropic") {
        Some(AgentClass {
            agent_type: "claude-code",
            agent_name: "Claude Code",
        })
    } else {
        None
    }
}

fn response_body_json(event: &CanonicalEvent) -> Option<Value> {
    body_json(&event.attributes)
        .or_else(|| (event.source == "sse_processor").then(|| event.attributes.clone()))
}

fn process_audit_status(action: &str, attributes: &Value) -> &'static str {
    if action != "exit" {
        return "observed";
    }
    match attributes.get("exit_code").and_then(Value::as_i64) {
        Some(0) => "success",
        Some(_) => "failure",
        None => "observed",
    }
}

fn is_writable_open(event: &CanonicalEvent) -> bool {
    let flags = event
        .attributes
        .get("flags")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    const O_ACCMODE: i64 = 0o3;
    const O_CREAT: i64 = 0o100;
    const O_TRUNC: i64 = 0o1000;
    const O_APPEND: i64 = 0o2000;
    (flags & O_ACCMODE) != 0 || (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0
}

fn parse_json_str(text: &str) -> Option<Value> {
    serde_json::from_str(text).ok()
}

fn json_i64(value: &Value, key: &str) -> i64 {
    value
        .get(key)
        .and_then(|value| value.as_i64().or_else(|| value.as_u64().map(|v| v as i64)))
        .unwrap_or_default()
}

fn number_or_string(value: Option<&Value>) -> Option<f64> {
    value.and_then(|v| {
        v.as_f64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
    })
}

fn network_target_from_event(event: &CanonicalEvent) -> Option<NetworkTargetRow> {
    let host = event.host.as_deref().filter(|host| !host.is_empty())?;
    let path = event.path.as_deref().filter(|path| !path.is_empty());
    let error_count = i64::from(
        event.kind == EventKind::LlmError
            || event.status_code.map(|code| code >= 400).unwrap_or(false),
    );
    Some(NetworkTargetRow {
        pid: event.pid,
        comm: event.comm.clone(),
        host: host.to_string(),
        path: path.map(str::to_string),
        count: 1,
        error_count,
        first_timestamp_ms: Some(event.timestamp_ms),
        last_timestamp_ms: Some(event.timestamp_ms),
    })
}

fn resource_sample_from_event(event: &CanonicalEvent) -> Option<ResourceSampleRow> {
    if event.kind != EventKind::ResourceSample {
        return None;
    }
    let cpu = number_or_string(event.attributes.get("cpu").and_then(|v| v.get("percent")));
    let rss_mb = number_or_string(event.attributes.get("memory").and_then(|v| v.get("rss_mb")));
    Some(ResourceSampleRow {
        timestamp_ms: event.timestamp_ms,
        pid: event.pid,
        comm: event.comm.clone(),
        cpu_percent: cpu,
        rss_mb: rss_mb.map(|v| v.max(0.0) as i64),
    })
}

fn bounded_limit(limit: usize) -> i64 {
    limit.min(100_000) as i64
}

fn parse_json_value(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string()))
}

fn parse_optional_json(text: Option<&str>) -> Value {
    text.map(parse_json_value).unwrap_or(Value::Null)
}

fn collect_rows<T, F>(rows: rusqlite::MappedRows<'_, F>) -> StorageResult<Vec<T>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn reject_legacy_raw_schema(conn: &Connection) -> StorageResult<()> {
    let has_raw = sqlite_table_exists(conn, "raw_events")?;
    let has_canonical = sqlite_table_exists(conn, "canonical_events")?;
    let has_view = sqlite_table_exists(conn, "view_stats")?;
    if (has_raw || has_canonical) && !has_view {
        return Err(
            "legacy raw-event SQLite schema is no longer supported; re-import the JSONL capture to materialize view tables"
                .into(),
        );
    }
    Ok(())
}

fn sqlite_table_exists(conn: &Connection, table: &str) -> StorageResult<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1
        )",
        params![table],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

struct LlmCallInsert<'a> {
    id: &'a str,
    start_timestamp_ms: u64,
    end_timestamp_ms: Option<u64>,
    pid: u32,
    comm: &'a str,
    provider: Option<&'a str>,
    model: Option<&'a str>,
    host: Option<&'a str>,
    path: Option<&'a str>,
    status_code: Option<u16>,
    request_body_json: Option<&'a str>,
    response_body_json: Option<&'a str>,
    view_source: &'a str,
    confidence: f32,
}

struct TokenInsert<'a> {
    id: &'a str,
    llm_call_id: &'a str,
    timestamp_ms: u64,
    pid: u32,
    comm: &'a str,
    provider: Option<&'a str>,
    model: Option<&'a str>,
    input_tokens: i64,
    output_tokens: i64,
    cache_creation_tokens: i64,
    cache_read_tokens: i64,
    total_tokens: i64,
    source: &'a str,
    view_source: &'a str,
    confidence: f32,
}

struct AuditInsert<'a> {
    id: &'a str,
    timestamp_ms: u64,
    audit_type: &'a str,
    pid: Option<u32>,
    comm: Option<&'a str>,
    subject: Option<&'a str>,
    action: Option<&'a str>,
    target: Option<&'a str>,
    status: Option<&'a str>,
    summary: Option<&'a str>,
    details_json: &'a str,
}

struct ToolCallInsert<'a> {
    id: &'a str,
    session_id: Option<&'a str>,
    conversation_id: Option<&'a str>,
    timestamp_ms: u64,
    tool_name: Option<&'a str>,
    tool_call_id: Option<&'a str>,
    start_timestamp_ms: Option<u64>,
    end_timestamp_ms: Option<u64>,
    duration_ms: Option<u64>,
    status: Option<&'a str>,
    input_json: Option<&'a str>,
    output_json: Option<&'a str>,
    related_pid: Option<u32>,
    related_event_id: Option<&'a str>,
    view_source: &'a str,
    confidence: f32,
}

struct SessionUpsert<'a> {
    id: &'a str,
    agent_type: &'a str,
    agent_name: Option<&'a str>,
    pid: Option<u32>,
    comm: Option<&'a str>,
    start_timestamp_ms: u64,
    end_timestamp_ms: Option<u64>,
    status: &'a str,
    model: Option<&'a str>,
    input_tokens: i64,
    output_tokens: i64,
    total_tokens: i64,
    view_source: &'a str,
    confidence: f32,
    attributes_json: &'a str,
}

impl LlmCallInsert<'_> {
    fn to_row(&self) -> LlmCallRow {
        LlmCallRow {
            id: self.id.to_string(),
            start_timestamp_ms: self.start_timestamp_ms,
            end_timestamp_ms: self.end_timestamp_ms,
            pid: Some(self.pid),
            comm: Some(self.comm.to_string()),
            provider: self.provider.map(str::to_string),
            model: self.model.map(str::to_string),
            host: self.host.map(str::to_string),
            path: self.path.map(str::to_string),
            status_code: self.status_code,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            request: parse_optional_json(self.request_body_json),
            response: parse_optional_json(self.response_body_json),
        }
    }
}

impl TokenInsert<'_> {
    fn to_row(&self) -> TokenUsageRow {
        TokenUsageRow {
            id: self.id.to_string(),
            llm_call_id: self.llm_call_id.to_string(),
            timestamp_ms: self.timestamp_ms,
            pid: Some(self.pid),
            comm: Some(self.comm.to_string()),
            provider: self.provider.map(str::to_string),
            model: self.model.map(str::to_string),
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cache_creation_tokens: self.cache_creation_tokens,
            cache_read_tokens: self.cache_read_tokens,
            total_tokens: self.total_tokens,
            source: self.source.to_string(),
            view_source: self.view_source.to_string(),
            confidence: Some(self.confidence),
        }
    }
}

impl AuditInsert<'_> {
    fn to_row(&self) -> AuditEventRow {
        AuditEventRow {
            id: self.id.to_string(),
            timestamp_ms: self.timestamp_ms,
            audit_type: self.audit_type.to_string(),
            pid: self.pid,
            comm: self.comm.map(str::to_string),
            subject: self.subject.map(str::to_string),
            action: self.action.map(str::to_string),
            target: self.target.map(str::to_string),
            status: self.status.map(str::to_string),
            summary: self.summary.map(str::to_string),
            details: parse_json_value(self.details_json),
        }
    }
}

impl ToolCallInsert<'_> {
    fn to_row(&self) -> ToolCallRow {
        ToolCallRow {
            id: self.id.to_string(),
            session_id: self.session_id.map(str::to_string),
            conversation_id: self.conversation_id.map(str::to_string),
            timestamp_ms: self.timestamp_ms,
            tool_name: self.tool_name.map(str::to_string),
            tool_call_id: self.tool_call_id.map(str::to_string),
            start_timestamp_ms: self.start_timestamp_ms,
            end_timestamp_ms: self.end_timestamp_ms,
            duration_ms: self.duration_ms,
            status: self.status.map(str::to_string),
            input: parse_optional_json(self.input_json),
            output: parse_optional_json(self.output_json),
            related_pid: self.related_pid,
            related_event_id: self.related_event_id.map(str::to_string),
            view_source: self.view_source.to_string(),
            confidence: Some(self.confidence),
        }
    }
}

impl SessionUpsert<'_> {
    fn to_row(&self) -> SessionRow {
        SessionRow {
            id: self.id.to_string(),
            agent_type: self.agent_type.to_string(),
            agent_name: self.agent_name.map(str::to_string),
            pid: self.pid,
            comm: self.comm.map(str::to_string),
            start_timestamp_ms: self.start_timestamp_ms,
            end_timestamp_ms: self.end_timestamp_ms,
            status: self.status.to_string(),
            model: self.model.map(str::to_string),
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            total_tokens: self.total_tokens,
            view_source: self.view_source.to_string(),
            confidence: Some(self.confidence as f64),
            attributes: parse_json_value(self.attributes_json),
        }
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS view_stats (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS network_targets (
  id TEXT PRIMARY KEY,
  pid INTEGER,
  comm TEXT,
  host TEXT NOT NULL,
  path TEXT,
  count INTEGER NOT NULL DEFAULT 0,
  error_count INTEGER NOT NULL DEFAULT 0,
  first_timestamp_ms INTEGER,
  last_timestamp_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_network_targets_host ON network_targets(host);
CREATE INDEX IF NOT EXISTS idx_network_targets_pid ON network_targets(pid);

CREATE TABLE IF NOT EXISTS llm_calls (
  id TEXT PRIMARY KEY,
  start_timestamp_ms INTEGER NOT NULL,
  end_timestamp_ms INTEGER,
  pid INTEGER,
  comm TEXT,
  provider TEXT,
  model TEXT,
  host TEXT,
  path TEXT,
  status_code INTEGER,
  request_body_json TEXT,
  response_body_json TEXT,
  view_source TEXT,
  confidence REAL
);

CREATE INDEX IF NOT EXISTS idx_llm_calls_time ON llm_calls(start_timestamp_ms);

CREATE TABLE IF NOT EXISTS token_usage (
  id TEXT PRIMARY KEY,
  llm_call_id TEXT,
  timestamp_ms INTEGER NOT NULL,
  pid INTEGER,
  comm TEXT,
  provider TEXT,
  model TEXT,
  input_tokens INTEGER DEFAULT 0,
  output_tokens INTEGER DEFAULT 0,
  cache_creation_tokens INTEGER DEFAULT 0,
  cache_read_tokens INTEGER DEFAULT 0,
  total_tokens INTEGER DEFAULT 0,
  source TEXT NOT NULL,
  view_source TEXT,
  confidence REAL
);

CREATE INDEX IF NOT EXISTS idx_token_time ON token_usage(timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_token_model_time ON token_usage(model, timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_token_comm_time ON token_usage(comm, timestamp_ms);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  timestamp_ms INTEGER NOT NULL,
  audit_type TEXT NOT NULL,
  pid INTEGER,
  comm TEXT,
  subject TEXT,
  action TEXT,
  target TEXT,
  status TEXT,
  summary TEXT,
  details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_type_time ON audit_events(audit_type, timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_audit_pid_time ON audit_events(pid, timestamp_ms);

CREATE TABLE IF NOT EXISTS agent_sessions (
  id TEXT PRIMARY KEY,
  agent_type TEXT NOT NULL,
  agent_name TEXT,
  pid INTEGER,
  comm TEXT,
  start_timestamp_ms INTEGER NOT NULL,
  end_timestamp_ms INTEGER,
  status TEXT NOT NULL DEFAULT 'active',
  model TEXT,
  input_tokens INTEGER DEFAULT 0,
  output_tokens INTEGER DEFAULT 0,
  total_tokens INTEGER DEFAULT 0,
  view_source TEXT NOT NULL,
  confidence REAL,
  attributes_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tool_calls (
  id TEXT PRIMARY KEY,
  session_id TEXT,
  conversation_id TEXT,
  timestamp_ms INTEGER NOT NULL,
  start_timestamp_ms INTEGER,
  end_timestamp_ms INTEGER,
  duration_ms INTEGER,
  tool_name TEXT,
  tool_call_id TEXT,
  status TEXT,
  input_json TEXT,
  output_json TEXT,
  related_pid INTEGER,
  related_event_id TEXT,
  view_source TEXT NOT NULL,
  confidence REAL
);

CREATE INDEX IF NOT EXISTS idx_tool_time ON tool_calls(timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_tool_name_time ON tool_calls(tool_name, timestamp_ms);

CREATE TABLE IF NOT EXISTS resource_samples (
  timestamp_ms INTEGER NOT NULL,
  pid INTEGER,
  comm TEXT,
  cpu_percent REAL,
  rss_mb INTEGER
);

"#;
