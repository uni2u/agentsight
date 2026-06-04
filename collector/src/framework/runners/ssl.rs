// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use super::common::{AnalyzerProcessor, BinaryExecutor, parse_json_event};
use super::{EventStream, Runner, RunnerError};
use crate::framework::analyzers::Analyzer;
use async_trait::async_trait;
use futures::stream::StreamExt;
use std::path::Path;
use std::sync::{Arc, atomic::AtomicU64};

pub struct SslRunner {
    analyzers: Vec<Box<dyn Analyzer>>,
    executor: BinaryExecutor,
}

impl SslRunner {
    pub fn from_binary_extractor(binary_path: impl AsRef<Path>) -> Self {
        Self {
            analyzers: Vec::new(),
            executor: BinaryExecutor::new(binary_path.as_ref().to_string_lossy().into_owned())
                .with_runner_name("SSL".to_string()),
        }
    }

    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let args = args
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect::<Vec<_>>();
        self.executor = self
            .executor
            .with_args(&args)
            .with_runner_name("SSL".to_string());
        self
    }
}

#[async_trait]
impl Runner for SslRunner {
    async fn run(&mut self) -> Result<EventStream, RunnerError> {
        let json_stream = self.executor.get_json_stream().await?;
        let errors = Arc::new(AtomicU64::new(0));
        let stream =
            json_stream.map(move |v| parse_json_event("ssl", "timestamp_ns", v, &errors));
        AnalyzerProcessor::process_through_analyzers(Box::pin(stream), &mut self.analyzers).await
    }

    fn add_analyzer(mut self, analyzer: Box<dyn Analyzer>) -> Self {
        self.analyzers.push(analyzer);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires real binary and sudo"]
    async fn test_ssl_runner_with_real_binary() {
        use tokio::time::timeout;
        let binary_path = "../src/sslsniff";
        if !Path::new(binary_path).exists() {
            return;
        }
        let mut runner = SslRunner::from_binary_extractor(binary_path);
        if let Ok(mut stream) = runner.run().await {
            let _ = timeout(std::time::Duration::from_secs(30), async {
                while futures::StreamExt::next(&mut stream).await.is_some() {}
            })
            .await;
        }
    }
}
