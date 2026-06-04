// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use futures::stream::StreamExt;

use crate::binary_resolver::{
    binary_embeds_ssl, parse_container_ref, resolve_binary_path, resolve_container_binary_path,
};
use crate::framework::{
    analyzers::{
        AuthHeaderRemover, HTTPFilter, HTTPParser, MaterializingAnalyzer, SSEProcessor, SSLFilter,
        TimestampNormalizer,
    },
    binary_extractor::BinaryExtractor,
    runners::{
        AgentRunner, EventStream, ProcessRunner, Runner, RunnerError, SslRunner, StdioRunner,
        SystemRunner,
    },
};
use crate::output::{
    print_event_json, print_trace_container_binary_resolved, print_trace_header,
    print_trace_shutdown, print_trace_ssl_binary_discovered, print_trace_start,
    print_web_server_error, print_web_server_start,
};
use crate::server::WebServer;
use crate::sinks::OtelExporter;
use crate::sources::proc::{PidSeed, ProcSnapshot};
use crate::stores::sqlite::SqliteStore;
use crate::view::{MaterializedView, SharedMaterializedView};

pub(crate) const DEFAULT_SERVER_LISTEN: &str = "127.0.0.1";
pub(crate) const DEFAULT_RECORD_STDIO_MAX_BYTES: u32 = 65_536;

pub(crate) struct StartedWebServer {
    pub(crate) url: String,
    pub(crate) _handle: tokio::task::JoinHandle<()>,
}

/// Configuration for exporting GenAI spans to an OpenTelemetry Collector.
#[derive(Clone)]
pub(crate) struct OtelConfig {
    /// OTLP/HTTP base endpoint; `None` falls back to env vars / localhost.
    pub(crate) endpoint: Option<String>,
    /// Opt-in: include prompt/completion content in spans.
    pub(crate) capture_content: bool,
}

/// All options for a trace/record/exec monitoring session.
///
/// Collapses what used to be ~28 positional arguments threaded through
/// trace and record commands. The `Default` impl is the neutral
/// "nothing enabled" baseline; the `trace` and `record` handlers each
/// fill in only the fields they care about.
#[derive(Default)]
pub(crate) struct TraceConfig {
    pub(crate) ssl: bool,
    pub(crate) pid: Option<u32>,
    pub(crate) session_id: Option<u32>,
    pub(crate) ssl_uid: Option<u32>,
    pub(crate) comm: Option<String>,
    pub(crate) ssl_filter: Vec<String>,
    pub(crate) ssl_handshake: bool,
    pub(crate) ssl_http: bool,
    pub(crate) ssl_raw_data: bool,
    pub(crate) process: bool,
    pub(crate) process_seed_pids: Vec<PidSeed>,
    pub(crate) stdio: bool,
    pub(crate) stdio_uid: Option<u32>,
    pub(crate) stdio_comm: Option<String>,
    pub(crate) stdio_all_fds: bool,
    pub(crate) stdio_max_bytes: u32,
    pub(crate) duration: Option<u32>,
    pub(crate) mode: Option<u32>,
    pub(crate) system: bool,
    pub(crate) system_interval: u64,
    pub(crate) http_filter: Vec<String>,
    pub(crate) disable_auth_removal: bool,
    pub(crate) otel: Option<OtelConfig>,
    /// SSL binary path; may be a `docker://` ref that `run_trace` resolves in place.
    pub(crate) binary_path: Option<String>,
    pub(crate) db_path: Option<String>,
    pub(crate) quiet: bool,
    pub(crate) server: bool,
    pub(crate) server_listen: Option<String>,
    pub(crate) server_port: u16,
}

pub(crate) fn build_stdio_args(
    pid: u32,
    uid: Option<u32>,
    comm: Option<&str>,
    all_fds: bool,
    max_bytes: u32,
) -> Vec<String> {
    let mut args = vec!["-p".to_string(), pid.to_string()];

    if let Some(uid_filter) = uid {
        args.extend(["-u".to_string(), uid_filter.to_string()]);
    }
    if let Some(comm_filter) = comm {
        args.extend(["-c".to_string(), comm_filter.to_string()]);
    }
    if all_fds {
        args.push("--all-fds".to_string());
    }
    args.extend(["--max-bytes".to_string(), max_bytes.to_string()]);

    args
}

pub(crate) fn prepare_process_seeds(cfg: &mut TraceConfig) -> Result<(), RunnerError> {
    if !cfg.process || !cfg.process_seed_pids.is_empty() {
        return Ok(());
    }

    let snapshot = ProcSnapshot::collect()
        .map_err(|e| RunnerError::from(format!("failed to collect /proc snapshot: {}", e)))?;
    cfg.process_seed_pids = if let Some(session_id) = cfg.session_id {
        snapshot.seeds_for_session(session_id)
    } else if let Some(pid) = cfg.pid {
        snapshot.seeds_for_pid_family(pid)
    } else if let Some(comm) = cfg.comm.as_deref() {
        snapshot.seeds_for_comm(comm)
    } else if cfg.mode.unwrap_or(1) == 1 {
        snapshot.seeds_for_all()
    } else {
        Vec::new()
    };
    Ok(())
}

pub(crate) fn build_trace_agent_with_view(
    binary_extractor: &BinaryExtractor,
    cfg: &TraceConfig,
    view: SharedMaterializedView,
) -> Result<AgentRunner, RunnerError> {
    // Bind config fields to the local names the body below uses.
    let ssl_enabled = cfg.ssl;
    let pid = cfg.pid;
    let session_id = cfg.session_id;
    let ssl_uid = cfg.ssl_uid;
    let comm = cfg.comm.as_deref();
    let ssl_filter = cfg.ssl_filter.as_slice();
    let ssl_handshake = cfg.ssl_handshake;
    let ssl_http = cfg.ssl_http;
    let ssl_raw_data = cfg.ssl_raw_data;
    let process_enabled = cfg.process;
    let process_seed_pids = cfg.process_seed_pids.as_slice();
    let stdio_enabled = cfg.stdio;
    let stdio_uid = cfg.stdio_uid;
    let stdio_comm = cfg.stdio_comm.as_deref();
    let stdio_all_fds = cfg.stdio_all_fds;
    let stdio_max_bytes = cfg.stdio_max_bytes;
    let duration = cfg.duration;
    let mode = cfg.mode;
    let system_enabled = cfg.system;
    let system_interval = cfg.system_interval;
    let http_filter = cfg.http_filter.as_slice();
    let disable_auth_removal = cfg.disable_auth_removal;
    let otel = &cfg.otel;
    let binary_path = cfg.binary_path.as_deref();
    let db_path = cfg.db_path.as_deref();

    let mut agent = AgentRunner::new();

    // Add SSL runner if enabled
    if ssl_enabled {
        let mut ssl_runner = SslRunner::from_binary_extractor(binary_extractor.get_sslsniff_path());

        // Configure SSL runner arguments (sslsniff supports -p, -u, -c, -h, -v, --binary-path)
        let mut ssl_args = Vec::new();
        if session_id.is_none()
            && let Some(pid_filter) = pid
        {
            ssl_args.extend(["-p".to_string(), pid_filter.to_string()]);
        }
        if let Some(session_filter) = session_id {
            ssl_args.extend(["--session".to_string(), session_filter.to_string()]);
        }
        if let Some(uid_filter) = ssl_uid {
            ssl_args.extend(["-u".to_string(), uid_filter.to_string()]);
        }
        // Note: when --binary-path is specified, we skip the --comm filter for sslsniff
        // because SSL traffic comes from "HTTP Client" thread (not the process name).
        // bpf_get_current_comm() returns thread name, so -c <process-name> would filter
        // out all SSL traffic. Instead, --binary-path alone provides sufficient targeting.
        if binary_path.is_none()
            && let Some(comm_filter) = comm
        {
            ssl_args.extend(["-c".to_string(), comm_filter.to_string()]);
        }
        if ssl_handshake {
            ssl_args.push("--handshake".to_string());
        }
        if let Some(path) = binary_path {
            ssl_args.extend(["--binary-path".to_string(), path.to_string()]);
        }
        if !ssl_args.is_empty() {
            ssl_runner = ssl_runner.with_args(&ssl_args);
        }

        // Add TimestampNormalizer first
        ssl_runner = ssl_runner.add_analyzer(Box::new(TimestampNormalizer::new()));

        // Add SSL-specific analyzers
        if !ssl_filter.is_empty() {
            ssl_runner =
                ssl_runner.add_analyzer(Box::new(SSLFilter::with_patterns(ssl_filter.to_vec())));
        }

        if ssl_http {
            ssl_runner = ssl_runner.add_analyzer(Box::new(SSEProcessor::new_with_timeout(30000)));

            let http_parser = if ssl_raw_data {
                HTTPParser::new()
            } else {
                HTTPParser::new().disable_raw_data()
            };
            ssl_runner = ssl_runner.add_analyzer(Box::new(http_parser));

            // Add HTTP filter to SSL runner if patterns are provided
            if !http_filter.is_empty() {
                ssl_runner = ssl_runner
                    .add_analyzer(Box::new(HTTPFilter::with_patterns(http_filter.to_vec())));
            }

            // Add authorization header remover by default (unless disabled)
            if !disable_auth_removal {
                ssl_runner = ssl_runner.add_analyzer(Box::new(AuthHeaderRemover::new()));
            }
        }

        agent = agent.add_runner(Box::new(ssl_runner));
    }

    // Add stdio runner if enabled
    if stdio_enabled {
        let pid_filter =
            pid.ok_or_else(|| RunnerError::from("stdio capture currently requires --pid"))?;
        let mut stdio_runner =
            StdioRunner::from_binary_extractor(binary_extractor.get_stdiocap_path()?);
        let mut stdio_args = build_stdio_args(
            pid_filter,
            stdio_uid,
            stdio_comm,
            stdio_all_fds,
            stdio_max_bytes,
        );
        if let Some(session_filter) = session_id {
            stdio_args.extend(["--session".to_string(), session_filter.to_string()]);
        }

        stdio_runner = stdio_runner.with_args(&stdio_args);
        stdio_runner = stdio_runner.add_analyzer(Box::new(TimestampNormalizer::new()));

        agent = agent.add_runner(Box::new(stdio_runner));
    }

    // Add process runner if enabled
    if process_enabled {
        let mut process_runner =
            ProcessRunner::from_binary_extractor(binary_extractor.get_process_path());

        // Configure process runner arguments.
        let mut process_args = Vec::new();
        if let Some(pid_filter) = pid {
            process_args.extend(["-p".to_string(), pid_filter.to_string()]);
        }
        if let Some(session_filter) = session_id {
            process_args.extend(["--session".to_string(), session_filter.to_string()]);
        }
        if let Some(comm_filter) = comm {
            process_args.extend(["-c".to_string(), comm_filter.to_string()]);
        }
        if let Some(duration_filter) = duration {
            process_args.extend(["-d".to_string(), duration_filter.to_string()]);
        }
        if let Some(mode_filter) = mode {
            process_args.extend(["-m".to_string(), mode_filter.to_string()]);
        }
        if !process_args.is_empty() {
            process_runner = process_runner.with_args(&process_args);
        }
        process_runner = process_runner.with_seed_pids(process_seed_pids);

        // Add TimestampNormalizer first
        process_runner = process_runner.add_analyzer(Box::new(TimestampNormalizer::new()));

        agent = agent.add_runner(Box::new(process_runner));
    }

    // Add system resource runner if enabled
    if system_enabled {
        let mut system_runner = SystemRunner::new().interval(system_interval);

        // Use same comm filter as other runners if provided
        if let Some(comm_filter) = comm {
            system_runner = system_runner.comm(comm_filter);
        }

        // Use same pid filter if provided
        if let Some(pid_filter) = pid {
            system_runner = system_runner.pid(pid_filter);
        }
        if let Some(session_filter) = session_id {
            system_runner = system_runner.session(session_filter);
        }

        // Add TimestampNormalizer first
        system_runner = system_runner.add_analyzer(Box::new(TimestampNormalizer::new()));

        agent = agent.add_runner(Box::new(system_runner));
    }

    // Ensure at least one runner is enabled
    if !ssl_enabled && !process_enabled && !stdio_enabled && !system_enabled {
        return Err(
            "At least one monitoring type must be enabled (--ssl, --process, --stdio, or --system)"
                .into(),
        );
    }

    // Add global materialized view. Optional exporters consume projected rows,
    // not raw runner events.
    let mut materializer = MaterializingAnalyzer::with_view(view);
    if let Some(path) = db_path {
        materializer =
            materializer.add_view_sink(Box::new(SqliteStore::open(path).map_err(|e| {
                RunnerError::from(format!("failed to open SQLite database '{}': {}", path, e))
            })?));
    }
    if let Some(otel_config) = otel {
        materializer = materializer.add_view_sink(Box::new(OtelExporter::new(
            otel_config.endpoint.clone(),
            otel_config.capture_content,
        )));
    }
    agent = agent.add_global_analyzer(Box::new(materializer));

    Ok(agent)
}

/// Trace monitoring with configurable runners and analyzers
pub(crate) async fn run_trace(
    binary_extractor: &BinaryExtractor,
    mut cfg: TraceConfig,
) -> Result<(), RunnerError> {
    print_trace_header();

    // A `--binary-path docker://<container>` (or `docker:<container>`) reference
    // is translated in Rust to an explicit host-side SSL attach target. The C
    // sslsniff binary only consumes that path; it does not scan container
    // process maps itself.
    if let Some(reference) = cfg
        .binary_path
        .as_deref()
        .and_then(parse_container_ref)
        .map(str::to_string)
    {
        let resolved = resolve_container_binary_path(&reference).map_err(RunnerError::from)?;
        print_trace_container_binary_resolved(&reference, &resolved);
        cfg.binary_path = Some(resolved);
    }

    // When the user enabled SSL but didn't pin a --binary-path, try to discover
    // one from --comm. This fixes the common "record -c node" case: Node (and
    // gemini-cli, which runs on Node) statically links OpenSSL, so there is no
    // system libssl.so to hook. Only adopt the resolved binary if it actually
    // embeds SSL, so dynamically-linked runtimes like Python are left to
    // sslsniff's system-libssl path with comm filtering intact.
    if cfg.ssl && cfg.binary_path.is_none() {
        let resolved = cfg
            .comm
            .as_deref()
            .filter(|c| !c.contains(','))
            .and_then(|c| resolve_binary_path(c).ok())
            .filter(|p| binary_embeds_ssl(p));
        if let Some(p) = resolved {
            print_trace_ssl_binary_discovered(cfg.comm.as_deref().unwrap_or(""), &p);
            cfg.binary_path = Some(p);
        }
    }

    let enable_server = cfg.server;
    let server_listen = cfg
        .server_listen
        .as_deref()
        .unwrap_or(DEFAULT_SERVER_LISTEN)
        .to_string();
    let server_port = cfg.server_port;

    prepare_process_seeds(&mut cfg)?;
    let live_view = MaterializedView::shared();
    let mut agent = build_trace_agent_with_view(binary_extractor, &cfg, live_view.clone())?;

    print_trace_start(agent.runner_count(), agent.analyzer_count());

    // Start web server if enabled
    let _server_handle =
        start_web_server_if_enabled(enable_server, &server_listen, server_port, live_view)
            .await
            .map_err(|e| RunnerError::from(format!("Failed to start server: {}", e)))?;

    let mut stream = agent.run().await?;

    // Drive the stream so the analyzer chain (file logging, storage, etc.) runs.
    drive_stream_until_shutdown(&mut stream, !cfg.quiet).await;
    drop(stream);
    drop(agent);

    Ok(())
}

pub(crate) async fn start_web_server_if_enabled(
    enable_server: bool,
    listen: &str,
    port: u16,
    view: SharedMaterializedView,
) -> Result<Option<StartedWebServer>, Box<dyn std::error::Error>> {
    if !enable_server {
        return Ok(None);
    }

    let listen = if listen.trim().is_empty() {
        DEFAULT_SERVER_LISTEN
    } else {
        listen.trim()
    };
    let addr = format!("{}:{}", listen, port)
        .parse()
        .map_err(|e| format!("Invalid server address: {}", e))?;
    let web_server =
        WebServer::new(view).map_err(|e| format!("Failed to create web server: {}", e))?;

    let host = if listen == "0.0.0.0" || listen == "::" {
        "127.0.0.1"
    } else {
        listen
    };
    let url = format!("http://{}:{}/", host, port);
    print_web_server_start(&url);

    let server_handle = tokio::spawn(async move {
        if let Err(e) = web_server.start(addr).await {
            print_web_server_error(e);
        }
    });

    // Give the server a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    Ok(Some(StartedWebServer {
        url,
        _handle: server_handle,
    }))
}

pub(crate) async fn drive_stream_until_shutdown(stream: &mut EventStream, print_events: bool) {
    let shutdown = crate::shutdown_notify();
    loop {
        tokio::select! {
            maybe_event = stream.next() => {
                match maybe_event {
                    Some(event) => {
                        if print_events {
                            print_event_json(&event);
                        }
                    }
                    None => break,
                }
            }
            _ = shutdown.notified() => {
                print_trace_shutdown();
                break;
            }
        }
    }
}

pub(crate) async fn drain_stream_for(stream: &mut EventStream, duration: tokio::time::Duration) {
    let shutdown = crate::shutdown_notify();
    let deadline = tokio::time::sleep(duration);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            maybe_event = stream.next() => {
                if maybe_event.is_none() {
                    break;
                }
            }
            _ = &mut deadline => {
                break;
            }
            _ = shutdown.notified() => {
                break;
            }
        }
    }
}

pub(crate) fn convert_runner_error(e: RunnerError) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::other(e.to_string()))
}
