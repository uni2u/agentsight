// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

#[cfg(test)]
use super::SslConfig;
use super::common::{AnalyzerProcessor, BinaryExecutor};
use super::{EventStream, Runner, RunnerError};
use crate::framework::analyzers::Analyzer;
use crate::framework::core::Event;
use async_trait::async_trait;
use futures::stream::StreamExt;
use std::path::Path;

/// Runner for collecting SSL/TLS events
pub struct SslRunner {
    // Config is only exercised by the builder/tests; excluded from prod builds.
    #[cfg(test)]
    config: SslConfig,
    analyzers: Vec<Box<dyn Analyzer>>,
    executor: BinaryExecutor,
    additional_args: Vec<String>,
}

impl SslRunner {
    /// Create from binary extractor (real execution mode)
    pub fn from_binary_extractor(binary_path: impl AsRef<Path>) -> Self {
        let path_str = binary_path.as_ref().to_string_lossy().to_string();
        Self {
            #[cfg(test)]
            config: SslConfig::default(),
            analyzers: Vec::new(),
            executor: BinaryExecutor::new(path_str).with_runner_name("SSL".to_string()),
            additional_args: Vec::new(),
        }
    }

    /// Add additional command-line arguments to pass to the binary
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.additional_args = args.into_iter().map(|s| s.as_ref().to_string()).collect();
        // Update the executor with the additional args
        self.executor = self
            .executor
            .with_args(&self.additional_args)
            .with_runner_name("SSL".to_string());
        self
    }

    /// Set the TLS version filter
    #[cfg(test)]
    pub fn tls_version(mut self, version: String) -> Self {
        self.config.tls_version = Some(version);
        self
    }
}

#[async_trait]
impl Runner for SslRunner {
    async fn run(&mut self) -> Result<EventStream, RunnerError> {
        // Get raw JSON stream from the binary executor
        let json_stream = self.executor.get_json_stream().await?;

        // Convert JSON values directly to framework Events
        let event_stream = json_stream.map(|json_value| {
            // Extract timestamp if available, otherwise panic
            let timestamp = json_value
                .get("timestamp_ns")
                .and_then(|v| v.as_u64())
                .unwrap_or_else(|| {
                    panic!("Missing timestamp_ns field in ssl event: {}", json_value);
                });

            // Extract pid - panic if not found
            let pid = json_value
                .get("pid")
                .and_then(|v| v.as_u64())
                .map(|p| p as u32)
                .unwrap_or_else(|| {
                    panic!("Missing pid field in ssl event: {}", json_value);
                });

            // Extract comm - panic if not found
            let comm = json_value
                .get("comm")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| {
                    panic!("Missing comm field in ssl event: {}", json_value);
                })
                .to_string();

            Event::new_with_timestamp(
                timestamp,
                "ssl".to_string(), // source is runner name
                pid,
                comm,
                json_value,
            )
        });

        AnalyzerProcessor::process_through_analyzers(Box::pin(event_stream), &mut self.analyzers)
            .await
    }

    fn add_analyzer(mut self, analyzer: Box<dyn Analyzer>) -> Self {
        self.analyzers.push(analyzer);
        self
    }

    fn name(&self) -> &str {
        "ssl"
    }

    fn id(&self) -> String {
        "ssl".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssl_runner_creation() {
        let runner = SslRunner::from_binary_extractor("/fake/path/sslsniff");
        assert_eq!(runner.name(), "ssl");
        assert_eq!(runner.id(), "ssl");
    }

    #[test]
    fn test_ssl_runner_with_custom_config() {
        let runner =
            SslRunner::from_binary_extractor("/fake/path/sslsniff").tls_version("1.2".to_string());

        assert_eq!(runner.id(), "ssl");
    }

    /// Test that actually runs the real SSL binary
    ///
    /// This test is ignored by default and only runs when specifically requested.
    /// To run this test: `cargo test test_ssl_runner_with_real_binary -- --ignored`
    ///
    /// Prerequisites:
    /// - The sslsniff binary must be built and available at ../src/sslsniff
    /// - Sufficient privileges to run eBPF programs (usually requires sudo)
    ///
    /// Note: This test may fail if:
    /// - The binary doesn't exist
    /// - Insufficient privileges
    /// - No SSL/TLS traffic occurs during the execution window
    #[tokio::test]
    #[ignore = "requires real binary and may need sudo privileges"]
    async fn test_ssl_runner_with_real_binary() {
        use std::path::Path;
        use std::time::Duration;
        use tokio::time::timeout;

        // Initialize debug logging for the test
        let _ = env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let binary_path = "../src/sslsniff";

        // Check if binary exists before attempting to run
        if !Path::new(binary_path).exists() {
            return;
        }

        // Create runner with real binary
        let mut runner = SslRunner::from_binary_extractor(binary_path)
            .add_analyzer(Box::new(crate::framework::analyzers::OutputAnalyzer::new()));

        // Run the binary and collect events for 30 seconds
        if let Ok(mut stream) = runner.run().await {
            let _ = timeout(Duration::from_secs(30), async {
                while futures::StreamExt::next(&mut stream).await.is_some() {}
            })
            .await;
        }
    }
}
