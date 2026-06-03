// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use super::common::{AnalyzerProcessor, BinaryExecutor, current_boot_time_ns, parse_error_event};
use super::{EventStream, Runner, RunnerError};
use crate::framework::analyzers::Analyzer;
use crate::framework::core::Event;
use crate::procfs::PidSeed;
use async_trait::async_trait;
use futures::stream::StreamExt;
use std::path::Path;
use std::sync::{Arc, atomic::AtomicU64};

/// Runner for collecting process/system events
pub struct ProcessRunner {
    analyzers: Vec<Box<dyn Analyzer>>,
    executor: BinaryExecutor,
    additional_args: Vec<String>,
}

impl ProcessRunner {
    /// Create from binary extractor (real execution mode)
    pub fn from_binary_extractor(binary_path: impl AsRef<Path>) -> Self {
        let path_str = binary_path.as_ref().to_string_lossy().to_string();
        Self {
            analyzers: Vec::new(),
            executor: BinaryExecutor::new(path_str).with_runner_name("Process".to_string()),
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
            .with_runner_name("Process".to_string());
        self
    }

    pub fn with_seed_pids(mut self, seeds: &[PidSeed]) -> Self {
        for seed in seeds {
            self.additional_args.push("--seed-pid".to_string());
            self.additional_args.push(seed.arg_value());
        }
        self.executor = self
            .executor
            .with_args(&self.additional_args)
            .with_runner_name("Process".to_string());
        self
    }

    fn parse_process_event(json_value: serde_json::Value, errors: &AtomicU64) -> Event {
        if json_value.get("event").and_then(|v| v.as_str()) == Some("CLOCK_SYNC") {
            return Event::new_with_timestamp(
                current_boot_time_ns(),
                "diagnostic".to_string(),
                0,
                "process".to_string(),
                json_value,
            );
        }

        let Some(pid) = json_value
            .get("pid")
            .and_then(|v| v.as_u64())
            .map(|p| p as u32)
        else {
            return parse_error_event("process", json_value, "missing pid", errors);
        };
        let Some(timestamp) = json_value.get("timestamp").and_then(|v| v.as_u64()) else {
            return parse_error_event("process", json_value, "missing timestamp", errors);
        };
        let Some(comm) = json_value
            .get("comm")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        else {
            return parse_error_event("process", json_value, "missing comm", errors);
        };

        Event::new_with_timestamp(timestamp, "process".to_string(), pid, comm, json_value)
    }
}

#[async_trait]
impl Runner for ProcessRunner {
    async fn run(&mut self) -> Result<EventStream, RunnerError> {
        // Get raw JSON stream from the binary executor
        let json_stream = self.executor.get_json_stream().await?;

        let errors = Arc::new(AtomicU64::new(0));
        let event_stream =
            json_stream.map(move |json_value| Self::parse_process_event(json_value, &errors));

        AnalyzerProcessor::process_through_analyzers(Box::pin(event_stream), &mut self.analyzers)
            .await
    }

    fn add_analyzer(mut self, analyzer: Box<dyn Analyzer>) -> Self {
        self.analyzers.push(analyzer);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that actually runs the real process binary
    ///
    /// This test is ignored by default and only runs when specifically requested.
    /// To run this test: `cargo test test_process_runner_with_real_binary -- --ignored`
    ///
    /// Prerequisites:
    /// - The process binary must be built and available at ../src/process
    /// - Sufficient privileges to run eBPF programs (usually requires sudo)
    ///
    /// Note: This test may fail if:
    /// - The binary doesn't exist
    /// - Insufficient privileges
    /// - No process events occur during the short execution window
    #[tokio::test]
    #[ignore = "requires real binary and may need sudo privileges"]
    async fn test_process_runner_with_real_binary() {
        use std::path::Path;
        use std::time::Duration;
        use tokio::time::timeout;

        // Initialize debug logging for the test
        let _ = env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let binary_path = "../src/process";

        // Check if binary exists before attempting to run
        if !Path::new(binary_path).exists() {
            return;
        }

        // Create runner with real binary
        let mut runner = ProcessRunner::from_binary_extractor(binary_path);

        // Run the binary and collect events for 30 seconds
        if let Ok(mut stream) = runner.run().await {
            let _ = timeout(Duration::from_secs(30), async {
                while futures::StreamExt::next(&mut stream).await.is_some() {}
            })
            .await;
        }
    }
}
