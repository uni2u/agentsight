// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::framework::analyzers::{Analyzer, AnalyzerError};
use crate::framework::runners::EventStream;
use crate::view::MaterializedView;
use crate::view::types::ViewUpdateSink;
use async_trait::async_trait;
use futures::stream::StreamExt;
use std::sync::{Arc, Mutex};

pub struct StorageAnalyzer {
    view: Arc<Mutex<MaterializedView>>,
}

impl StorageAnalyzer {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            view: Arc::new(Mutex::new(MaterializedView::open_in_memory()?)),
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
        let view = Arc::clone(&self.view);

        let processed = stream.map(move |event| {
            if let Ok(mut view) = view.lock()
                && let Err(e) = view.ingest_event(&event)
            {
                log::warn!("StorageAnalyzer: failed to ingest event: {}", e);
            }
            event
        });

        Ok(Box::pin(processed))
    }
}
