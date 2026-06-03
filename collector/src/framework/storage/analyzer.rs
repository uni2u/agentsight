// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::framework::analyzers::{Analyzer, AnalyzerError};
use crate::framework::runners::EventStream;
use crate::framework::storage::sqlite::{SqliteStore, ViewProjector, ViewUpdateSink};
use async_trait::async_trait;
use futures::stream::StreamExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct StorageAnalyzer {
    store: Arc<Mutex<SqliteStore>>,
    view: Arc<Mutex<ViewProjector>>,
}

impl StorageAnalyzer {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            store: Arc::new(Mutex::new(SqliteStore::open(path)?)),
            view: Arc::new(Mutex::new(ViewProjector::new())),
        })
    }

    pub fn in_memory() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            store: Arc::new(Mutex::new(SqliteStore::open_in_memory()?)),
            view: Arc::new(Mutex::new(ViewProjector::new())),
        })
    }

    pub fn add_view_sink(self, sink: Box<dyn ViewUpdateSink>) -> Self {
        if let Ok(mut view) = self.view.lock() {
            view.add_sink(sink);
        }
        self
    }
}

#[async_trait]
impl Analyzer for StorageAnalyzer {
    async fn process(&mut self, stream: EventStream) -> Result<EventStream, AnalyzerError> {
        let store = Arc::clone(&self.store);
        let view = Arc::clone(&self.view);

        let processed = stream.map(move |event| {
            if let (Ok(mut store), Ok(mut view)) = (store.lock(), view.lock())
                && let Err(e) = store.insert_event(&event, &mut view)
            {
                log::warn!("StorageAnalyzer: failed to store event: {}", e);
            }
            event
        });

        Ok(Box::pin(processed))
    }
}
