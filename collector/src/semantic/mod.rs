// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

mod canonical;
pub mod llm;

pub use canonical::{CanonicalEvent, EventKind, normalize_event};
pub use llm::{
    body_json, extract_model, extract_token_usage, extract_token_usage_from_sse, provider_from_host,
};
