// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::framework::storage::sqlite::SqliteStore;
use crate::view::MaterializedView;
use crate::view::types::{StorageResult, ViewUpdate};
use std::path::Path;

pub(crate) struct SqliteSource(MaterializedView);

impl SqliteSource {
    pub(crate) fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let store = SqliteStore::open(path)?;
        let mut view = MaterializedView::new();
        view.set_source("sqlite");

        for row in store.llm_call_rows(100_000)? {
            view.load_update(ViewUpdate::LlmCall(row));
        }
        for row in store.token_usage_rows()? {
            view.load_update(ViewUpdate::TokenUsage(row));
        }
        for row in store.audit_event_rows(100_000)? {
            view.load_update(ViewUpdate::AuditEvent(row));
        }
        for row in store.tool_call_rows()? {
            view.load_update(ViewUpdate::ToolCall(row));
        }
        for row in store.session_rows()? {
            view.load_update(ViewUpdate::Session(row));
        }
        for row in store.network_target_rows()? {
            view.load_update(ViewUpdate::NetworkTarget(row));
        }
        for row in store.resource_sample_rows()? {
            view.load_update(ViewUpdate::ResourceSample(row));
        }

        Ok(Self(view))
    }

    pub(crate) fn into_view(self) -> MaterializedView {
        self.0
    }
}
