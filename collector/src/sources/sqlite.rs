// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::stores::sqlite::SqliteStore;
use crate::view::MaterializedView;
use crate::view::types::ViewResult;
use std::path::Path;

pub(crate) fn load_view(path: impl AsRef<Path>) -> ViewResult<MaterializedView> {
    let store = SqliteStore::open_readonly(path)?;
    let mut view = MaterializedView::new();
    view.set_source("sqlite");

    for row in store.all_llm_call_rows()? {
        view.load_llm_call(row);
    }
    for row in store.token_usage_rows()? {
        view.load_token_usage(row);
    }
    for row in store.all_audit_event_rows()? {
        view.load_audit_event(row);
    }
    for row in store.process_node_rows()? {
        view.load_process_node(row);
    }
    for row in store.tool_call_rows()? {
        view.load_tool_call(row);
    }
    for row in store.session_rows()? {
        view.load_session(row);
    }
    for row in store.network_target_rows()? {
        view.load_network_target(row);
    }
    for row in store.resource_sample_rows()? {
        view.load_resource_sample(row);
    }

    Ok(view)
}
