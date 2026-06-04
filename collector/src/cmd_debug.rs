// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::binary_resolver::{parse_container_ref, resolve_container_binary_path};
use crate::cmd_trace::{
    build_stdio_args, drive_stream_until_shutdown, start_web_server_if_enabled,
};
use crate::framework::{
    analyzers::{
        AuthHeaderRemover, HTTPFilter, HTTPParser, MaterializingAnalyzer, SSEProcessor, SSLFilter,
        TimestampNormalizer,
    },
    binary_extractor::BinaryExtractor,
    runners::{ProcessRunner, Runner, RunnerError, SslRunner, StdioRunner, SystemRunner},
};
use crate::view::MaterializedView;

/// Show raw SSL events as JSON with optional chunk merging and HTTP parsing
pub(crate) async fn run_raw_ssl(
    binary_extractor: &BinaryExtractor,
    enable_chunk_merger: bool,
    enable_http_parser: bool,
    include_raw_data: bool,
    http_filter_patterns: &[String],
    disable_auth_removal: bool,
    ssl_filter_patterns: &[String],
    quiet: bool,
    enable_server: bool,
    server_listen: &str,
    server_port: u16,
    binary_path: Option<&str>,
    args: &[String],
) -> Result<(), RunnerError> {
    println!("Raw SSL Events");
    println!("{}", "=".repeat(60));

    let mut ssl_runner = SslRunner::from_binary_extractor(binary_extractor.get_sslsniff_path());

    // Translate a `docker://<container>` binary path to the explicit host-side
    // SSL attach target (see resolve_container_binary_path).
    let container_resolved: Option<String> = match binary_path.and_then(parse_container_ref) {
        Some(reference) => {
            Some(resolve_container_binary_path(reference).map_err(RunnerError::from)?)
        }
        None => None,
    };
    let binary_path = container_resolved.as_deref().or(binary_path);

    // Build arguments list with binary_path if provided
    let mut final_args = Vec::new();
    if let Some(path) = binary_path {
        final_args.push("--binary-path".to_string());
        final_args.push(path.to_string());
    }
    final_args.extend_from_slice(args);

    // Add all arguments if we have any
    if !final_args.is_empty() {
        ssl_runner = ssl_runner.with_args(&final_args);
    }

    // Add TimestampNormalizer first to convert nanoseconds since boot to milliseconds since epoch
    ssl_runner = ssl_runner.add_analyzer(Box::new(TimestampNormalizer::new()));

    // Add SSL filter if patterns are provided
    if !ssl_filter_patterns.is_empty() {
        ssl_runner = ssl_runner.add_analyzer(Box::new(SSLFilter::with_patterns(
            ssl_filter_patterns.to_vec(),
        )));
    }

    // Add analyzers based on flags - when HTTP parser is enabled, always enable SSE merge first
    if enable_http_parser {
        ssl_runner = ssl_runner.add_analyzer(Box::new(SSEProcessor::new_with_timeout(30000)));
        let parser = if include_raw_data {
            HTTPParser::new()
        } else {
            HTTPParser::new().disable_raw_data()
        };
        ssl_runner = ssl_runner.add_analyzer(Box::new(parser));
        if !http_filter_patterns.is_empty() {
            ssl_runner = ssl_runner.add_analyzer(Box::new(HTTPFilter::with_patterns(
                http_filter_patterns.to_vec(),
            )));
        }
        if !disable_auth_removal {
            ssl_runner = ssl_runner.add_analyzer(Box::new(AuthHeaderRemover::new()));
        }
        println!(
            "Starting SSL event stream with SSE processing + HTTP parsing (press Ctrl+C to stop):"
        );
    } else if enable_chunk_merger {
        ssl_runner = ssl_runner.add_analyzer(Box::new(SSEProcessor::new_with_timeout(30000)));
        println!("Starting SSL event stream with SSE processing (press Ctrl+C to stop):");
    } else {
        println!("Starting SSL event stream with raw JSON output (press Ctrl+C to stop):");
    }

    let live_view = MaterializedView::shared();
    ssl_runner = ssl_runner.add_analyzer(Box::new(MaterializingAnalyzer::with_view(
        live_view.clone(),
    )));

    // Start web server if enabled
    let _server_handle =
        start_web_server_if_enabled(enable_server, server_listen, server_port, live_view)
            .await
            .map_err(|e| RunnerError::from(format!("Failed to start server: {}", e)))?;

    let mut stream = ssl_runner.run().await?;
    drive_stream_until_shutdown(&mut stream, !quiet).await;

    Ok(())
}

/// Show raw process events as JSON
pub(crate) async fn run_raw_process(
    binary_extractor: &BinaryExtractor,
    quiet: bool,
    enable_server: bool,
    server_listen: &str,
    server_port: u16,
    args: &Vec<String>,
) -> Result<(), RunnerError> {
    println!("Raw Process Events");
    println!("{}", "=".repeat(60));

    let mut process_runner =
        ProcessRunner::from_binary_extractor(binary_extractor.get_process_path());

    // Add additional arguments if provided
    if !args.is_empty() {
        process_runner = process_runner.with_args(args);
    }

    // Add TimestampNormalizer first to convert nanoseconds since boot to milliseconds since epoch
    process_runner = process_runner.add_analyzer(Box::new(TimestampNormalizer::new()));

    let live_view = MaterializedView::shared();
    process_runner = process_runner.add_analyzer(Box::new(MaterializingAnalyzer::with_view(
        live_view.clone(),
    )));

    // Start web server if enabled
    let _server_handle =
        start_web_server_if_enabled(enable_server, server_listen, server_port, live_view)
            .await
            .map_err(|e| RunnerError::from(format!("Failed to start server: {}", e)))?;

    println!("Starting process event stream with raw JSON output (press Ctrl+C to stop):");
    let mut stream = process_runner.run().await?;
    drive_stream_until_shutdown(&mut stream, !quiet).await;

    Ok(())
}

/// Show raw stdio events as JSON
pub(crate) async fn run_raw_stdio(
    binary_extractor: &BinaryExtractor,
    pid: u32,
    uid: Option<u32>,
    comm: Option<&str>,
    all_fds: bool,
    max_bytes: u32,
    quiet: bool,
    enable_server: bool,
    server_listen: &str,
    server_port: u16,
) -> Result<(), RunnerError> {
    println!("Raw Stdio Events");
    println!("{}", "=".repeat(60));

    let mut stdio_runner =
        StdioRunner::from_binary_extractor(binary_extractor.get_stdiocap_path()?);

    let stdio_args = build_stdio_args(pid, uid, comm, all_fds, max_bytes);
    stdio_runner = stdio_runner.with_args(&stdio_args);

    // Add TimestampNormalizer first to convert nanoseconds since boot to milliseconds since epoch
    stdio_runner = stdio_runner.add_analyzer(Box::new(TimestampNormalizer::new()));

    let live_view = MaterializedView::shared();
    stdio_runner = stdio_runner.add_analyzer(Box::new(MaterializingAnalyzer::with_view(
        live_view.clone(),
    )));

    // Start web server if enabled
    let _server_handle =
        start_web_server_if_enabled(enable_server, server_listen, server_port, live_view)
            .await
            .map_err(|e| RunnerError::from(format!("Failed to start server: {}", e)))?;

    println!(
        "Starting stdio event stream for PID {} (press Ctrl+C to stop):",
        pid
    );
    let mut stream = stdio_runner.run().await?;
    drive_stream_until_shutdown(&mut stream, !quiet).await;

    Ok(())
}

/// Monitor system resources (CPU and memory)
pub(crate) async fn run_system(
    interval: u64,
    pid: Option<u32>,
    comm: Option<&str>,
    include_children: bool,
    cpu_threshold: Option<f64>,
    memory_threshold: Option<u64>,
    quiet: bool,
    enable_server: bool,
    server_listen: &str,
    server_port: u16,
) -> Result<(), RunnerError> {
    println!("System Resource Monitoring");
    println!("{}", "=".repeat(60));

    let mut system_runner = SystemRunner::new().interval(interval);

    // Configure monitoring target
    if let Some(pid) = pid {
        system_runner = system_runner.pid(pid);
        println!("Monitoring PID: {}", pid);
    } else if let Some(comm) = comm {
        system_runner = system_runner.comm(comm);
        println!("Monitoring process: {}", comm);
    } else {
        println!("Monitoring system-wide resources");
    }

    // Configure options
    system_runner = system_runner.include_children(include_children);

    if let Some(threshold) = cpu_threshold {
        system_runner = system_runner.cpu_threshold(threshold);
        println!("CPU alert threshold: {}%", threshold);
    }

    if let Some(threshold) = memory_threshold {
        system_runner = system_runner.memory_threshold(threshold);
        println!("Memory alert threshold: {} MB", threshold);
    }

    println!("Interval: {}s", interval);
    println!("Include children: {}", include_children);
    println!("{}", "=".repeat(60));
    println!("Starting system monitoring (press Ctrl+C to stop):");

    // Add TimestampNormalizer first
    system_runner = system_runner.add_analyzer(Box::new(TimestampNormalizer::new()));

    let live_view = MaterializedView::shared();
    system_runner = system_runner.add_analyzer(Box::new(MaterializingAnalyzer::with_view(
        live_view.clone(),
    )));

    // Start web server if enabled
    let _server_handle =
        start_web_server_if_enabled(enable_server, server_listen, server_port, live_view)
            .await
            .map_err(|e| RunnerError::from(format!("Failed to start server: {}", e)))?;

    let mut stream = system_runner.run().await?;
    drive_stream_until_shutdown(&mut stream, !quiet).await;

    Ok(())
}
