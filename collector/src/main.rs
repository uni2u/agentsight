// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

// The trace/record/exec path now uses the TraceConfig struct instead of ~28
// positional args. The remaining offenders are the raw `ssl`/`stdio`/`system`
// CLI handlers and HTTPEvent::new; collapsing those is a follow-up, so the lint
// stays allowed crate-wide until then.
#![allow(clippy::too_many_arguments)]

use clap::{Parser, Subcommand};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use tokio::signal;
use tokio::sync::Notify;

mod binary_resolver;
mod cli_db;
mod cli_discover;
mod cmd_debug;
mod cmd_exec;
mod cmd_trace;
mod framework;
mod server;
mod session;

use cli_db::{
    AdapterCommand, configured_db_path, run_adapters_command, run_audit_query, run_db_summary,
    run_export, run_replay, run_token_query,
};
use cli_discover::run_discover;
use cmd_debug::{run_raw_process, run_raw_ssl, run_raw_stdio, run_system};
use cmd_exec::run_exec;
use cmd_trace::{OtelConfig, TraceConfig, convert_runner_error, run_trace};
use framework::{
    analyzers::{print_global_http_filter_metrics, print_global_ssl_filter_metrics},
    binary_extractor::BinaryExtractor,
};
use session::{resolve_db_or_latest, run_db_list};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_NOTIFY: OnceLock<Arc<Notify>> = OnceLock::new();

fn shutdown_notify() -> Arc<Notify> {
    SHUTDOWN_NOTIFY
        .get_or_init(|| Arc::new(Notify::new()))
        .clone()
}

async fn setup_signal_handler() {
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .expect("Failed to install SIGINT handler");

    tokio::spawn(async move {
        sigint.recv().await;
        println!("\n\nReceived SIGINT, shutting down...");

        // Print HTTP filter metrics using the global function
        print_global_http_filter_metrics();

        // Print SSL filter metrics using the global function
        print_global_ssl_filter_metrics();

        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
        shutdown_notify().notify_waiters();
    });
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "AgentSight: See what your AI agents actually do.\n\n\
             eBPF probes require root — AgentSight auto-elevates them via sudo\n\
             while your agent runs as your normal user."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch a command and automatically discover + trace it (zero config).
    /// Example: agentsight exec -- claude     (or)  agentsight exec -- python my_agent.py
    Exec {
        /// Override the auto-discovered SSL binary path (rarely needed)
        #[arg(long)]
        binary_path: Option<String>,
        /// Log file for output and server
        #[arg(short = 'o', long, default_value = "record.log")]
        log_file: String,
        /// SQLite database path for production queries and adapters
        #[arg(long)]
        db: Option<String>,
        /// SQL adapter to run after capture when --db is set: auto, anthropic, claude-code, openclaw, gemini-cli
        #[arg(long, default_value = "auto")]
        adapter: String,
        /// Do not run SQL adapters after capture
        #[arg(long)]
        no_adapters: bool,
        /// Enable log rotation
        #[arg(long, default_value = "true")]
        rotate_logs: bool,
        /// Maximum log file size in MB (used with --rotate-logs)
        #[arg(long, default_value = "10")]
        max_log_size: u64,
        /// Disable the web server (enabled by default on --server-port)
        #[arg(long)]
        no_server: bool,
        /// Server port for the web UI
        #[arg(long, default_value = "7395")]
        server_port: u16,
        /// The command (and its arguments) to launch and trace
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Record agent activity with optimized filters and settings
    Record {
        /// Process command filter (defaults to "claude")
        #[arg(short = 'c', long)]
        comm: String,
        /// Path to the binary executable to monitor (e.g., ~/.nvm/versions/node/v20.0.0/bin/node)
        #[arg(long)]
        binary_path: Option<String>,
        /// Log file for output and server
        #[arg(short = 'o', long, default_value = "record.log")]
        log_file: String,
        /// SQLite database path for production queries and adapters
        #[arg(long)]
        db: Option<String>,
        /// SQL adapter to run after capture when --db is set: auto, anthropic, claude-code, openclaw, gemini-cli
        #[arg(long, default_value = "auto")]
        adapter: String,
        /// Do not run SQL adapters after capture
        #[arg(long)]
        no_adapters: bool,
        /// Enable log rotation
        #[arg(long, default_value = "true")]
        rotate_logs: bool,
        /// Maximum log file size in MB (used with --rotate-logs)
        #[arg(long, default_value = "10")]
        max_log_size: u64,
        /// Server port (used with --server, always enabled)
        #[arg(long, default_value = "7395")]
        server_port: u16,
    },
    /// Discover supported local agent CLIs and recommended capture settings
    Discover {
        /// Emit JSON output
        #[arg(long)]
        json: bool,
    },
    /// Database operations: query tokens, audit events, import/export, adapters
    #[command(subcommand)]
    Db(DbCommands),
    /// Low-level debugging tools: raw SSL/process/stdio/system/trace monitors
    #[command(subcommand)]
    Debug(DebugCommands),
}

#[derive(Subcommand)]
enum DbCommands {
    /// Session summary: what the agent did, tokens, processes, files
    Summary {
        /// SQLite database path (defaults to latest session)
        #[arg(long)]
        db: Option<String>,
    },
    /// Query token usage from a SQLite database
    Token {
        /// SQLite database path (defaults to latest session)
        #[arg(long)]
        db: Option<String>,
        /// Grouping key: model, provider, comm, pid
        #[arg(long, default_value = "model")]
        group_by: String,
        /// Emit JSON output
        #[arg(long)]
        json: bool,
    },
    /// Query audit events from a SQLite database
    Audit {
        /// SQLite database path (defaults to latest session)
        #[arg(long)]
        db: Option<String>,
        /// Audit type: llm, process, file
        #[arg(long)]
        audit_type: Option<String>,
        /// Maximum rows
        #[arg(long, default_value = "100")]
        limit: usize,
        /// Emit JSON output
        #[arg(long)]
        json: bool,
    },
    /// Export a web/demo snapshot from a SQLite database
    Export {
        /// SQLite database path (defaults to latest session)
        #[arg(long)]
        db: Option<String>,
        /// Output snapshot path, or '-' for stdout
        #[arg(short, long)]
        output: String,
        /// Maximum canonical events to include
        #[arg(long, default_value = "10000")]
        event_limit: usize,
        /// Maximum audit events to include
        #[arg(long, default_value = "10000")]
        audit_limit: usize,
    },
    /// Import a JSONL capture into SQLite and run generic projections/adapters
    Import {
        /// Input JSONL log file
        #[arg(short, long)]
        input: String,
        /// SQLite database path
        #[arg(long)]
        db: String,
        /// SQL adapter to run after import: auto, anthropic, claude-code, openclaw, gemini-cli
        #[arg(long, default_value = "auto")]
        adapter: String,
        /// Do not run SQL adapters after import
        #[arg(long)]
        no_adapters: bool,
    },
    /// List or run built-in SQL adapters
    Adapters {
        /// Emit JSON output when listing adapters
        #[arg(long)]
        json: bool,
        #[command(subcommand)]
        command: Option<AdapterCommand>,
    },
    /// List session databases
    List,
}

#[derive(Subcommand)]
enum DebugCommands {
    /// Analyze SSL traffic with raw JSON output
    Ssl {
        /// Enable SSE processing for SSL traffic
        #[arg(long)]
        sse_merge: bool,
        /// Enable HTTP parsing (automatically enables SSE merge first)
        #[arg(long)]
        http_parser: bool,
        /// Include raw SSL data in HTTP parser events
        #[arg(long)]
        http_raw_data: bool,
        /// HTTP filter patterns to exclude events (can be used multiple times)
        #[arg(long)]
        http_filter: Vec<String>,
        /// Disable authorization header removal from HTTP traffic
        #[arg(long)]
        disable_auth_removal: bool,
        /// SSL filter patterns to exclude events (can be used multiple times)
        #[arg(long)]
        ssl_filter: Vec<String>,
        /// Suppress console output
        #[arg(short, long)]
        quiet: bool,
        /// Enable log rotation
        #[arg(long)]
        rotate_logs: bool,
        /// Maximum log file size in MB (used with --rotate-logs)
        #[arg(long, default_value = "10")]
        max_log_size: u64,
        /// Start web server on port 7395
        #[arg(long)]
        server: bool,
        /// Server port (used with --server)
        #[arg(long, default_value = "7395")]
        server_port: u16,
        /// Log file to serve via API (used with --server)
        #[arg(long, default_value = "ssl.log")]
        log_file: String,
        /// Path to the binary executable to monitor (e.g., ~/.nvm/versions/node/v20.0.0/bin/node)
        #[arg(long)]
        binary_path: Option<String>,
        /// Additional arguments to pass to the SSL binary
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Test process runner with embedded binary
    Process {
        /// Suppress console output
        #[arg(short, long)]
        quiet: bool,
        /// Enable log rotation
        #[arg(long)]
        rotate_logs: bool,
        /// Maximum log file size in MB (used with --rotate-logs)
        #[arg(long, default_value = "10")]
        max_log_size: u64,
        /// Start web server on port 7395
        #[arg(long)]
        server: bool,
        /// Server port (used with --server)
        #[arg(long, default_value = "7395")]
        server_port: u16,
        /// Log file to serve via API (used with --server)
        #[arg(long, default_value = "process.log")]
        log_file: String,
        /// Additional arguments to pass to the process binary
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Capture local stdio payloads from a target process
    Stdio {
        /// Target PID (required)
        #[arg(short = 'p', long)]
        pid: u32,
        /// Filter by UID
        #[arg(short = 'u', long)]
        uid: Option<u32>,
        /// Filter by command name
        #[arg(short = 'c', long)]
        comm: Option<String>,
        /// Capture all FDs instead of only stdin/stdout/stderr
        #[arg(long)]
        all_fds: bool,
        /// Maximum bytes captured per event
        #[arg(long, default_value = "8192")]
        max_bytes: u32,
        /// Suppress console output
        #[arg(short, long)]
        quiet: bool,
        /// Enable log rotation
        #[arg(long)]
        rotate_logs: bool,
        /// Maximum log file size in MB (used with --rotate-logs)
        #[arg(long, default_value = "10")]
        max_log_size: u64,
        /// Start web server on port 7395
        #[arg(long)]
        server: bool,
        /// Server port (used with --server)
        #[arg(long, default_value = "7395")]
        server_port: u16,
        /// Log file to serve via API (used with --server)
        #[arg(long, default_value = "stdio.log")]
        log_file: String,
    },
    /// Combined SSL and Process monitoring with configurable options
    Trace {
        /// Enable SSL monitoring
        #[arg(long, action = clap::ArgAction::Set, default_value = "true")]
        ssl: bool,
        /// SSL filter by UID
        #[arg(long)]
        ssl_uid: Option<u32>,
        /// SSL filter patterns (for analyzer-level filtering)
        #[arg(long)]
        ssl_filter: Vec<String>,
        /// Show SSL handshake events
        #[arg(long)]
        ssl_handshake: bool,
        /// Enable HTTP parsing for SSL
        #[arg(long, action = clap::ArgAction::Set, default_value = "true")]
        ssl_http: bool,
        /// Include raw SSL data in HTTP parser events
        #[arg(long)]
        ssl_raw_data: bool,
        /// Enable process monitoring
        #[arg(long, action = clap::ArgAction::Set, default_value = "true")]
        process: bool,
        /// Enable stdio payload monitoring (requires --pid)
        #[arg(long, requires = "pid")]
        stdio: bool,
        /// Stdio filter by UID
        #[arg(long)]
        stdio_uid: Option<u32>,
        /// Stdio filter by command name
        #[arg(long)]
        stdio_comm: Option<String>,
        /// Capture all FDs for stdio monitoring instead of only 0/1/2
        #[arg(long)]
        stdio_all_fds: bool,
        /// Maximum bytes captured per stdio event
        #[arg(long, default_value = "8192")]
        stdio_max_bytes: u32,
        /// Process command filter (comma-separated list)
        #[arg(short = 'c', long)]
        comm: Option<String>,
        /// Process PID filter
        #[arg(short = 'p', long)]
        pid: Option<u32>,
        /// Process duration filter (minimum duration in ms)
        #[arg(long)]
        duration: Option<u32>,
        /// Process filtering mode (0=all, 1=proc, 2=filter)
        #[arg(long)]
        mode: Option<u32>,
        /// Enable system resource monitoring (CPU and memory)
        #[arg(long)]
        system: bool,
        /// System monitoring interval in seconds
        #[arg(long, default_value = "2")]
        system_interval: u64,
        /// HTTP filters (applied to SSL runner after HTTP parsing)
        #[arg(long)]
        http_filter: Vec<String>,
        /// Disable authorization header removal from HTTP traffic
        #[arg(long)]
        disable_auth_removal: bool,
        /// Export GenAI spans to an OpenTelemetry Collector via OTLP/HTTP
        #[arg(long)]
        otel: bool,
        /// OTLP/HTTP endpoint for --otel (default: $OTEL_EXPORTER_OTLP_ENDPOINT or http://localhost:4318)
        #[arg(long)]
        otel_endpoint: Option<String>,
        /// Include prompt/completion content in exported GenAI spans (opt-in; off by default for privacy)
        #[arg(long)]
        otel_capture_content: bool,
        /// Path to the binary executable to monitor (e.g., ~/.nvm/versions/node/v20.0.0/bin/node)
        #[arg(long)]
        binary_path: Option<String>,
        /// Log file for output and server
        #[arg(short = 'o', long, default_value = "trace.log")]
        log_file: String,
        /// SQLite database path for production queries and adapters
        #[arg(long)]
        db: Option<String>,
        /// SQL adapter to run after capture when --db is set: auto, anthropic, claude-code, openclaw, gemini-cli
        #[arg(long, default_value = "auto")]
        adapter: String,
        /// Do not run SQL adapters after capture
        #[arg(long)]
        no_adapters: bool,
        /// Suppress console output
        #[arg(short, long)]
        quiet: bool,
        /// Enable log rotation
        #[arg(long)]
        rotate_logs: bool,
        /// Maximum log file size in MB (used with --rotate-logs)
        #[arg(long, default_value = "10")]
        max_log_size: u64,
        /// Start web server on port 7395
        #[arg(long)]
        server: bool,
        /// Server port (used with --server)
        #[arg(long, default_value = "7395")]
        server_port: u16,
    },
    /// Monitor system resources (CPU and memory)
    System {
        /// Monitoring interval in seconds
        #[arg(short = 'i', long, default_value = "2")]
        interval: u64,
        /// Process PID to monitor
        #[arg(short = 'p', long)]
        pid: Option<u32>,
        /// Process command name to monitor
        #[arg(short = 'c', long)]
        comm: Option<String>,
        /// Exclude children processes from aggregation
        #[arg(long)]
        no_children: bool,
        /// CPU usage threshold for alerts (%)
        #[arg(long)]
        cpu_threshold: Option<f64>,
        /// Memory usage threshold for alerts (MB)
        #[arg(long)]
        memory_threshold: Option<u64>,
        /// Log file for output and server
        #[arg(short = 'o', long, default_value = "system.log")]
        log_file: String,
        /// Suppress console output
        #[arg(short, long)]
        quiet: bool,
        /// Enable log rotation
        #[arg(long)]
        rotate_logs: bool,
        /// Maximum log file size in MB (used with --rotate-logs)
        #[arg(long, default_value = "10")]
        max_log_size: u64,
        /// Start web server on port 7395
        #[arg(long)]
        server: bool,
        /// Server port (used with --server)
        #[arg(long, default_value = "7395")]
        server_port: u16,
    },
}

#[tokio::main]
async fn main() {
    // Print errors as a clean one-line `Error: <message>` (Display) and exit 1,
    // instead of the default `-> Result` behavior which prints them via Debug.
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize env_logger with default log level of info
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    // Setup signal handler for graceful shutdown
    setup_signal_handler().await;

    // Handle commands that don't need the binary extractor first.
    match &cli.command {
        Commands::Db(cmd) => {
            match cmd {
                DbCommands::Summary { db } => {
                    let resolved = resolve_db_or_latest(db).ok();
                    run_db_summary(resolved.as_deref())?;
                }
                DbCommands::Import {
                    input,
                    db,
                    adapter,
                    no_adapters,
                } => run_replay(input, db, (!*no_adapters).then_some(adapter.as_str()))?,
                DbCommands::Token { db, group_by, json } => {
                    let db = resolve_db_or_latest(db)?;
                    run_token_query(&db, group_by, *json)?;
                }
                DbCommands::Audit {
                    db,
                    audit_type,
                    limit,
                    json,
                } => {
                    if let Ok(db) = resolve_db_or_latest(db) {
                        run_audit_query(&db, audit_type.as_deref(), *limit, *json)?;
                    } else {
                        cli_db::run_local_audit(*json)?;
                    }
                }
                DbCommands::Export {
                    db,
                    output,
                    event_limit,
                    audit_limit,
                } => {
                    let db = resolve_db_or_latest(db)?;
                    run_export(&db, output, *event_limit, *audit_limit)?;
                }
                DbCommands::Adapters { json, command } => run_adapters_command(*json, command)?,
                DbCommands::List => run_db_list()?,
            }
            return Ok(());
        }
        Commands::Discover { json } => {
            run_discover(*json)?;
            return Ok(());
        }
        _ => {}
    }

    // Create BinaryExtractor with embedded binaries
    let binary_extractor = BinaryExtractor::new().await?;

    match &cli.command {
        Commands::Exec {
            binary_path,
            log_file,
            db,
            adapter,
            no_adapters,
            rotate_logs,
            max_log_size,
            no_server,
            server_port,
            command,
        } => run_exec(
            &binary_extractor,
            command,
            binary_path.as_deref(),
            log_file,
            configured_db_path(db),
            (!*no_adapters).then_some(adapter.as_str()),
            *rotate_logs,
            *max_log_size,
            !*no_server,
            *server_port,
        )
        .await
        .map_err(convert_runner_error)?,
        Commands::Record {
            comm,
            binary_path,
            log_file,
            db,
            adapter,
            no_adapters,
            rotate_logs,
            max_log_size,
            server_port,
        } => {
            // Predefined filter patterns optimized for agent monitoring. Enables
            // SSL + process + system monitoring and the web server by default.
            let cfg = TraceConfig {
                name: "trace",
                ssl: true,
                comm: Some(comm.clone()),
                ssl_filter: vec!["data=0\\r\\n\\r\\n".to_string()],
                ssl_http: true,
                process: true,
                stdio_max_bytes: 8192,
                system: true,
                system_interval: 2,
                http_filter: vec!["request.path_prefix=/v1/rgstr | response.status_code=202 | request.method=HEAD | response.body=".to_string()],
                binary_path: binary_path.clone(),
                log_file: log_file.clone(),
                db_path: configured_db_path(db),
                adapter: (!*no_adapters).then_some(adapter.clone()),
                quiet: true,
                rotate_logs: *rotate_logs,
                max_log_size: *max_log_size,
                server: true,
                server_port: *server_port,
                ..Default::default()
            };
            run_trace(&binary_extractor, cfg)
                .await
                .map_err(convert_runner_error)?
        }
        Commands::Debug(cmd) => match cmd {
            DebugCommands::Ssl {
                sse_merge,
                http_parser,
                http_raw_data,
                http_filter,
                disable_auth_removal,
                ssl_filter,
                quiet,
                rotate_logs,
                max_log_size,
                server,
                server_port,
                log_file,
                binary_path,
                args,
            } => run_raw_ssl(
                &binary_extractor,
                *sse_merge,
                *http_parser,
                *http_raw_data,
                http_filter,
                *disable_auth_removal,
                ssl_filter,
                *quiet,
                *rotate_logs,
                *max_log_size,
                *server,
                *server_port,
                log_file,
                binary_path.as_deref(),
                args,
            )
            .await
            .map_err(convert_runner_error)?,
            DebugCommands::Process {
                quiet,
                rotate_logs,
                max_log_size,
                server,
                server_port,
                log_file,
                args,
            } => run_raw_process(
                &binary_extractor,
                *quiet,
                *rotate_logs,
                *max_log_size,
                *server,
                *server_port,
                log_file,
                args,
            )
            .await
            .map_err(convert_runner_error)?,
            DebugCommands::Stdio {
                pid,
                uid,
                comm,
                all_fds,
                max_bytes,
                quiet,
                rotate_logs,
                max_log_size,
                server,
                server_port,
                log_file,
            } => run_raw_stdio(
                &binary_extractor,
                *pid,
                *uid,
                comm.as_deref(),
                *all_fds,
                *max_bytes,
                *quiet,
                *rotate_logs,
                *max_log_size,
                *server,
                *server_port,
                log_file,
            )
            .await
            .map_err(convert_runner_error)?,
            DebugCommands::Trace {
                ssl,
                ssl_uid,
                pid,
                comm,
                ssl_filter,
                ssl_handshake,
                ssl_http,
                ssl_raw_data,
                process,
                stdio,
                stdio_uid,
                stdio_comm,
                stdio_all_fds,
                stdio_max_bytes,
                duration,
                mode,
                system,
                system_interval,
                http_filter,
                disable_auth_removal,
                otel,
                otel_endpoint,
                otel_capture_content,
                binary_path,
                log_file,
                db,
                adapter,
                no_adapters,
                quiet,
                rotate_logs,
                max_log_size,
                server,
                server_port,
            } => {
                let cfg = TraceConfig {
                    name: "trace",
                    ssl: *ssl,
                    pid: *pid,
                    ssl_uid: *ssl_uid,
                    comm: comm.clone(),
                    ssl_filter: ssl_filter.clone(),
                    ssl_handshake: *ssl_handshake,
                    ssl_http: *ssl_http,
                    ssl_raw_data: *ssl_raw_data,
                    process: *process,
                    stdio: *stdio,
                    stdio_uid: *stdio_uid,
                    stdio_comm: stdio_comm.clone(),
                    stdio_all_fds: *stdio_all_fds,
                    stdio_max_bytes: *stdio_max_bytes,
                    duration: *duration,
                    mode: *mode,
                    system: *system,
                    system_interval: *system_interval,
                    http_filter: http_filter.clone(),
                    disable_auth_removal: *disable_auth_removal,
                    otel: otel.then(|| OtelConfig {
                        endpoint: otel_endpoint.clone(),
                        capture_content: *otel_capture_content,
                    }),
                    binary_path: binary_path.clone(),
                    log_file: log_file.clone(),
                    db_path: configured_db_path(db),
                    adapter: (!*no_adapters).then_some(adapter.clone()),
                    quiet: *quiet,
                    rotate_logs: *rotate_logs,
                    max_log_size: *max_log_size,
                    server: *server,
                    server_port: *server_port,
                };
                run_trace(&binary_extractor, cfg)
                    .await
                    .map_err(convert_runner_error)?
            }
            DebugCommands::System {
                interval,
                pid,
                comm,
                no_children,
                cpu_threshold,
                memory_threshold,
                log_file,
                quiet,
                rotate_logs,
                max_log_size,
                server,
                server_port,
            } => run_system(
                *interval,
                *pid,
                comm.as_deref(),
                !*no_children,
                *cpu_threshold,
                *memory_threshold,
                log_file,
                *quiet,
                *rotate_logs,
                *max_log_size,
                *server,
                *server_port,
            )
            .await
            .map_err(convert_runner_error)?,
        },
        // Already handled above; unreachable but needed for exhaustive match.
        Commands::Db(_) | Commands::Discover { .. } => unreachable!(),
    }

    Ok(())
}
