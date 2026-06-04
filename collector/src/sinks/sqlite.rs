// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::stores::sqlite::SqliteStore;
use crate::view::types::{ViewResult, ViewUpdate, ViewUpdateSink};
use std::path::Path;

pub(crate) struct SqliteSink(SqliteStore);

impl SqliteSink {
    pub(crate) fn new(path: impl AsRef<Path>) -> ViewResult<Self> {
        Ok(Self(SqliteStore::open(path)?))
    }
}

impl ViewUpdateSink for SqliteSink {
    fn update(&mut self, update: &ViewUpdate) -> ViewResult<()> {
        self.0.apply_view_update(update)
    }
}
