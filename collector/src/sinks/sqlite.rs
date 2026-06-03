// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::framework::storage::sqlite::SqliteStore;
use crate::view::types::{StorageResult, ViewUpdate, ViewUpdateSink};
use std::path::Path;

pub(crate) struct SqliteSink(SqliteStore);

impl SqliteSink {
    pub(crate) fn new(path: impl AsRef<Path>) -> StorageResult<Self> {
        Ok(Self(SqliteStore::open(path)?))
    }
}

impl ViewUpdateSink for SqliteSink {
    fn update(&mut self, update: &ViewUpdate) {
        if let Err(error) = self.0.apply_view_update(update) {
            log::warn!("SqliteSink: failed to store view update: {}", error);
        }
    }
}
