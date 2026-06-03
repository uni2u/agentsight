// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::framework::storage::sqlite::SqliteStore;
use crate::view::types::{
    AuditEventRow, LlmCallRow, NetworkTargetRow, ResourceSampleRow, SessionRow, StorageResult,
    TokenUsageRow, ToolCallRow, ViewUpdate, ViewUpdateSink,
};
use std::path::Path;

pub(crate) struct SqliteSink {
    store: SqliteStore,
}

impl SqliteSink {
    pub(crate) fn new(path: impl AsRef<Path>) -> StorageResult<Self> {
        Ok(Self {
            store: SqliteStore::open(path)?,
        })
    }

    fn apply(&mut self, update: ViewUpdate) {
        if let Err(error) = self.store.apply_view_update(&update) {
            log::warn!("SqliteSink: failed to store view update: {}", error);
        }
    }
}

impl ViewUpdateSink for SqliteSink {
    fn llm_call(&mut self, call: &LlmCallRow) {
        self.apply(ViewUpdate::LlmCall(call.clone()));
    }

    fn token_usage(&mut self, token: &TokenUsageRow) {
        self.apply(ViewUpdate::TokenUsage(token.clone()));
    }

    fn audit_event(&mut self, audit: &AuditEventRow) {
        self.apply(ViewUpdate::AuditEvent(audit.clone()));
    }

    fn tool_call(&mut self, tool: &ToolCallRow) {
        self.apply(ViewUpdate::ToolCall(tool.clone()));
    }

    fn session(&mut self, session: &SessionRow) {
        self.apply(ViewUpdate::Session(session.clone()));
    }

    fn network_target(&mut self, target: &NetworkTargetRow) {
        self.apply(ViewUpdate::NetworkTarget(target.clone()));
    }

    fn resource_sample(&mut self, sample: &ResourceSampleRow) {
        self.apply(ViewUpdate::ResourceSample(sample.clone()));
    }
}
