// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::framework::analyzers::{Analyzer, AnalyzerError};
use crate::framework::runners::EventStream;
use crate::view::SharedMaterializedView;
use crate::view::types::ViewUpdateSink;
use async_trait::async_trait;
use futures::stream::StreamExt;

pub struct MaterializingAnalyzer {
    view: SharedMaterializedView,
}

impl MaterializingAnalyzer {
    pub fn with_view(view: SharedMaterializedView) -> Self {
        Self { view }
    }

    pub fn add_view_sink(self, sink: Box<dyn ViewUpdateSink>) -> Self {
        if let Ok(mut view) = self.view.lock() {
            view.add_sink(sink);
        } else {
            log::warn!("MaterializingAnalyzer: failed to acquire view lock while adding sink");
        }
        self
    }
}

#[async_trait]
impl Analyzer for MaterializingAnalyzer {
    async fn process(&mut self, stream: EventStream) -> Result<EventStream, AnalyzerError> {
        let view = self.view.clone();

        let processed = stream.map(move |event| {
            if let Ok(mut view) = view.lock() {
                if let Err(error) = view.ingest_event(&event) {
                    log::warn!("MaterializingAnalyzer: failed to ingest event: {}", error);
                }
            } else {
                log::warn!(
                    "MaterializingAnalyzer: failed to acquire view lock while ingesting event"
                );
            }
            event
        });

        Ok(Box::pin(processed))
    }
}
