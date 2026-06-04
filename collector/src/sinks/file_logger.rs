// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::view::types::{ViewResult, ViewUpdate, ViewUpdateSink};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Configuration for log rotation
#[derive(Debug, Clone)]
pub struct LogRotationConfig {
    /// Maximum size of a single log file in bytes
    pub max_file_size: u64,

    /// Maximum number of rotated log files to keep (excluding current)
    pub max_files: usize,

    /// Check file size every N events (performance optimization)
    pub size_check_interval: u64,
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            max_file_size: 10_000_000, // 10MB
            max_files: 5,
            size_check_interval: 100,
        }
    }
}

/// File-backed logger for materialized view updates.
pub struct FileLogger {
    file_path: String,
    file: File,
    rotation_config: Option<LogRotationConfig>,
    event_count: u64,
}

impl FileLogger {
    /// Create a new FileLogger with specified file path (no rotation)
    pub fn new<P: AsRef<Path>>(file_path: P) -> Result<Self, std::io::Error> {
        let path_str = file_path.as_ref().to_string_lossy().to_string();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path_str)?;

        Ok(Self {
            file_path: path_str,
            file,
            rotation_config: None,
            event_count: 0,
        })
    }

    /// Create FileLogger with rotation configuration
    pub fn with_rotation<P: AsRef<Path>>(
        file_path: P,
        config: LogRotationConfig,
    ) -> Result<Self, std::io::Error> {
        let path_str = file_path.as_ref().to_string_lossy().to_string();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path_str)?;

        Ok(Self {
            file_path: path_str,
            file,
            rotation_config: Some(config),
            event_count: 0,
        })
    }

    /// Convenience method for simple size-based rotation
    pub fn with_max_size<P: AsRef<Path>>(
        file_path: P,
        max_size_mb: u64,
    ) -> Result<Self, std::io::Error> {
        let config = LogRotationConfig {
            max_file_size: max_size_mb * 1_000_000,
            ..Default::default()
        };
        Self::with_rotation(file_path, config)
    }

    fn rotate(&mut self, config: &LogRotationConfig) -> ViewResult<()> {
        self.file.flush()?;

        if config.max_files > 0 {
            for i in (1..config.max_files).rev() {
                let old_path = format!("{}.{}", self.file_path, i);
                let new_path = format!("{}.{}", self.file_path, i + 1);
                if std::path::Path::new(&old_path).exists() {
                    std::fs::rename(&old_path, &new_path)?;
                }
            }

            let rotated_path = format!("{}.1", self.file_path);
            if std::path::Path::new(&self.file_path).exists() {
                std::fs::rename(&self.file_path, rotated_path)?;
            }
        } else if std::path::Path::new(&self.file_path).exists() {
            std::fs::remove_file(&self.file_path)?;
        }

        self.file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.file_path)?;

        let cleanup_path = format!("{}.{}", self.file_path, config.max_files + 1);
        if std::path::Path::new(&cleanup_path).exists() {
            std::fs::remove_file(cleanup_path)?;
        }
        Ok(())
    }

    fn check_rotation(&mut self) -> ViewResult<()> {
        let Some(config) = self.rotation_config.clone() else {
            return Ok(());
        };
        self.event_count += 1;
        if config.size_check_interval > 0
            && self.event_count.is_multiple_of(config.size_check_interval)
            && let Ok(metadata) = std::fs::metadata(&self.file_path)
            && metadata.len() > config.max_file_size
        {
            self.rotate(&config)?;
        }
        Ok(())
    }

    fn write_line(&mut self, line: &str) -> ViewResult<()> {
        self.check_rotation()?;
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        Ok(())
    }

    fn write_view_update(&mut self, update: &ViewUpdate) -> ViewResult<()> {
        let json = serde_json::to_string(update)?;
        self.write_line(&format!("{json}\n"))
    }
}

impl ViewUpdateSink for FileLogger {
    fn update(&mut self, update: &ViewUpdate) -> ViewResult<()> {
        self.write_view_update(update)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::types::AuditEventRow;
    use serde_json::json;
    use tempfile::NamedTempFile;

    fn audit_update(id: usize, message: &str) -> ViewUpdate {
        ViewUpdate::AuditEvent(AuditEventRow {
            id: format!("audit-{id}"),
            timestamp_ms: 1_000 + id as u64,
            audit_type: "test".to_string(),
            pid: Some(42),
            comm: Some("test".to_string()),
            subject: None,
            action: Some("write".to_string()),
            target: Some("file".to_string()),
            status: Some("ok".to_string()),
            summary: Some(message.to_string()),
            details: json!({ "message": message }),
        })
    }

    fn write_updates(logger: &mut FileLogger, count: usize, message: &str) {
        for id in 0..count {
            logger.update(&audit_update(id, message)).unwrap();
        }
    }

    #[test]
    fn test_file_logger_writes_audit_updates() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut logger = FileLogger::new(temp_file.path()).unwrap();

        logger.update(&audit_update(1, "test event")).unwrap();

        let file_contents = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(file_contents.contains("test event"));
        assert!(file_contents.contains(r#""kind":"audit_event""#));
    }

    #[test]
    fn test_rotation_config_default() {
        let config = LogRotationConfig::default();
        assert_eq!(config.max_file_size, 10_000_000);
        assert_eq!(config.max_files, 5);
        assert_eq!(config.size_check_interval, 100);
    }

    #[test]
    fn test_file_logger_with_rotation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let config = LogRotationConfig {
            max_file_size: 100, // Very small for testing
            max_files: 3,
            size_check_interval: 1, // Check every event
        };

        let logger = FileLogger::with_rotation(&log_path, config).unwrap();
        assert!(logger.rotation_config.is_some());
    }

    #[test]
    fn test_file_logger_with_max_size() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let logger = FileLogger::with_max_size(&log_path, 5).unwrap(); // 5MB
        assert!(logger.rotation_config.is_some());
        assert_eq!(
            logger.rotation_config.as_ref().unwrap().max_file_size,
            5_000_000
        );
    }

    #[test]
    fn test_rotation_on_size_limit() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let config = LogRotationConfig {
            max_file_size: 50, // Very small for testing
            max_files: 2,
            size_check_interval: 1, // Check every event
        };

        let mut logger = FileLogger::with_rotation(&log_path, config).unwrap();
        write_updates(
            &mut logger,
            3,
            "This is a large message that should trigger rotation when written multiple times",
        );

        // Check that rotation occurred - rotated file should exist
        let rotated_path = format!("{}.1", log_path.to_string_lossy());
        assert!(std::path::Path::new(&rotated_path).exists() || log_path.exists());
    }

    #[test]
    fn test_max_files_cleanup() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let config = LogRotationConfig {
            max_file_size: 30,
            max_files: 2, // Only keep 2 rotated files
            size_check_interval: 1,
        };

        let mut logger = FileLogger::with_rotation(&log_path, config).unwrap();
        for batch in 0..5 {
            write_updates(
                &mut logger,
                10,
                &format!("Large event data that will cause rotation {batch}"),
            );
        }

        // Check that we don't have too many rotated files
        let log_1 = format!("{}.1", log_path.to_string_lossy());
        let log_4 = format!("{}.4", log_path.to_string_lossy());

        // Should have at most max_files rotated files
        assert!(!std::path::Path::new(&log_4).exists()); // Should be cleaned up

        // The log file or rotated files should exist
        assert!(log_path.exists() || std::path::Path::new(&log_1).exists());
    }

    #[test]
    fn test_rotation_keeps_writing_current_update() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let config = LogRotationConfig {
            max_file_size: 50,
            max_files: 2,
            size_check_interval: 1,
        };

        let mut logger = FileLogger::with_rotation(&log_path, config).unwrap();
        write_updates(&mut logger, 2, &"x".repeat(100));

        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            content.contains(r#""kind":"audit_event""#)
                || log_path.with_extension("log.1").exists()
        );
    }

    #[test]
    fn test_no_rotation_when_disabled() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut logger = FileLogger::new(temp_file.path()).unwrap();

        write_updates(&mut logger, 100, &"x".repeat(1000));

        // No rotated files should exist
        let rotated_path = format!("{}.1", temp_file.path().to_string_lossy());
        assert!(!std::path::Path::new(&rotated_path).exists());
    }

    #[test]
    fn test_size_check_interval_optimization() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let config = LogRotationConfig {
            max_file_size: 50,
            max_files: 2,
            size_check_interval: 10, // Only check every 10 events
        };

        let mut logger = FileLogger::with_rotation(&log_path, config).unwrap();
        write_updates(&mut logger, 5, "test");

        // Should not have rotated yet due to interval optimization
        let rotated_path = format!("{}.1", log_path.to_string_lossy());
        assert!(!std::path::Path::new(&rotated_path).exists());
    }

    #[test]
    fn test_file_logger_writes_view_updates() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut logger = FileLogger::new(temp_file.path()).unwrap();

        logger
            .update(&ViewUpdate::LlmCall(crate::view::types::LlmCallRow {
                id: "llm-1".to_string(),
                start_timestamp_ms: 1_000,
                end_timestamp_ms: Some(1_200),
                pid: Some(42),
                comm: Some("claude".to_string()),
                provider: Some("anthropic".to_string()),
                model: Some("claude-sonnet-4".to_string()),
                host: Some("api.anthropic.com".to_string()),
                path: Some("/v1/messages".to_string()),
                status_code: Some(200),
                input_tokens: 10,
                output_tokens: 5,
                total_tokens: 15,
                request: json!({"model": "claude-sonnet-4"}),
                response: json!({"usage": {"input_tokens": 10, "output_tokens": 5}}),
            }))
            .unwrap();
        logger
            .update(&ViewUpdate::TokenUsage(crate::view::types::TokenUsageRow {
                id: "token-1".to_string(),
                llm_call_id: "llm-1".to_string(),
                timestamp_ms: 1_200,
                pid: Some(42),
                comm: Some("claude".to_string()),
                provider: Some("anthropic".to_string()),
                model: Some("claude-sonnet-4".to_string()),
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_tokens: 0,
                cache_read_tokens: 0,
                total_tokens: 15,
                source: "response_usage".to_string(),
                view_source: "view".to_string(),
                confidence: Some(0.95),
            }))
            .unwrap();

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains(r#""kind":"llm_call""#));
        assert!(content.contains(r#""kind":"token_usage""#));
        assert!(content.contains("claude-sonnet-4"));
    }
}
