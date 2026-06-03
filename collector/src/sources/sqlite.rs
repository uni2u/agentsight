// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::view::MaterializedView;
use crate::view::types::StorageResult;
use std::path::Path;

pub(crate) struct SqliteSource {
    view: MaterializedView,
}

impl SqliteSource {
    pub(crate) fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        Ok(Self {
            view: MaterializedView::open_sqlite(path)?,
        })
    }

    pub(crate) fn into_view(self) -> MaterializedView {
        self.view
    }
}
