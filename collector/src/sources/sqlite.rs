// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::stores::sqlite::SqliteStore;
use crate::view::MaterializedView;
use crate::view::types::{ViewResult, ViewUpdate};
use std::path::Path;

pub(crate) fn load_view(path: impl AsRef<Path>) -> ViewResult<MaterializedView> {
    let store = SqliteStore::open_readonly(path)?;
    let mut view = MaterializedView::new();
    view.set_source("sqlite");

    for row in store.all_llm_call_rows()? {
        view.load_update(ViewUpdate::LlmCall(row));
    }
    for row in store.token_usage_rows()? {
        view.load_update(ViewUpdate::TokenUsage(row));
    }
    for row in store.all_audit_event_rows()? {
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

    Ok(view)
}
