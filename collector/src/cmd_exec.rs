// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use futures::stream::StreamExt;

use crate::binary_resolver::resolve_binary_path;
use crate::cli_db::{run_capture_adapters, SessionSummary};
use crate::cmd_trace::{
    build_trace_agent, drain_stream_for, start_web_server_if_enabled,
    TraceConfig,
};
use crate::framework::{
    analyzers::{print_global_http_filter_metrics, print_global_ssl_filter_metrics},
    binary_extractor::BinaryExtractor,
    capture::cli_output::{
        CLI_OUTPUT_CAPTURE_MAX_BYTES, persist_cli_output_evidence, should_capture_cli_output,
        tee_child_stream,
    },
    runners::{Runner, RunnerError},
};
use crate::session::sessions_dir;

/// Launch a target command and automatically trace it with eBPF.
///
/// This is the zero-configuration entry point: it discovers the target's real
/// ELF binary (for SSL uprobe attachment), derives the process `--comm` filter
/// from the command name, starts SSL + process + system monitoring in the
/// background (quiet, so the child owns the terminal), then spawns the child.
/// Monitoring stops automatically when the child exits.
pub(crate) fn target_user_ids() -> Option<(libc::uid_t, libc::gid_t)> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let uid = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid = std::env::var("SUDO_GID").ok()?.parse().ok()?;
    Some((uid, gid))
}

pub(crate) fn default_session_db_path() -> Result<String, RunnerError> {
    let dir = sessions_dir()
        .ok_or_else(|| RunnerError::from("cannot determine home directory for session DB"))?;
    std::fs::create_dir_all(&dir).map_err(|e| {
        RunnerError::from(format!("failed to create session directory {}: {}", dir.display(), e))
    })?;
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
    Ok(dir.join(format!("{}.db", ts)).to_string_lossy().to_string())
}

pub(crate) fn print_session_summary(db_path: &str) {
    if let Ok(summary) = SessionSummary::from_sqlite(db_path) {
        println!("\n{}", "─".repeat(60));
        println!("📊 Session Summary");
        println!("{}", "─".repeat(60));
        summary.print();
        println!("{}", "─".repeat(60));
    }
}

pub(crate) async fn run_exec(
    binary_extractor: &BinaryExtractor,
    command: &[String],
    binary_path_override: Option<&str>,
    log_file: &str,
    db_path: Option<String>,
    adapter: Option<&str>,
    rotate_logs: bool,
    max_log_size: u64,
    enable_server: bool,
    server_port: u16,
) -> Result<(), RunnerError> {
    let program = command.first().ok_or_else(|| {
        RunnerError::from("exec requires a command to run, e.g. `agentsight exec -- claude`")
    })?;
    let prog_args = &command[1..];

    // Auto-create a session database when the user didn't specify --db.
    let (db_path, adapter) = if db_path.is_some() {
        (db_path, adapter)
    } else {
        match default_session_db_path() {
            Ok(p) => (Some(p), Some(adapter.unwrap_or("auto"))),
            Err(e) => {
                eprintln!("⚠ Could not create session DB ({}), continuing without it.", e);
                (None, adapter)
            }
        }
    };

    println!("AgentSight exec");
    println!("{}", "=".repeat(60));

    // Derive the process comm filter from the command's base name. The kernel
    // truncates comm to 15 chars (TASK_COMM_LEN - 1), so match that here.
    let base = std::path::Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(program);
    let comm: String = base.chars().take(15).collect();

    // Auto-discover the SSL binary unless the user pinned it explicitly.
    let binary_path = match binary_path_override {
        Some(p) => {
            println!("→ Using provided binary path: {}", p);
            Some(p.to_string())
        }
        None => match resolve_binary_path(program) {
            Ok(p) => {
                println!("✓ Auto-discovered binary: {}", p);
                Some(p)
            }
            Err(e) => {
                // Non-fatal: process/system monitoring still works without SSL.
                println!("⚠ Could not auto-discover binary for SSL capture: {}", e);
                println!("  SSL traffic may not be captured. Pass --binary-path to override.");
                None
            }
        },
    };
    println!("✓ Process filter (--comm): {}", comm);

    // Same optimized filters as the `record` command.
    let db_path_for_adapters = db_path.clone();
    let cfg = TraceConfig {
        name: "exec",
        ssl: true,
        comm: Some(comm.clone()),
        ssl_filter: vec!["data=0\\r\\n\\r\\n".to_string()],
        ssl_http: true,
        process: true,
        stdio_max_bytes: 8192,
        system: true,
        system_interval: 2,
        http_filter: vec!["request.path_prefix=/v1/rgstr | response.status_code=202 | request.method=HEAD | response.body=".to_string()],
        binary_path,
        log_file: log_file.to_string(),
        db_path,
        adapter: adapter.map(str::to_string),
        quiet: true,
        rotate_logs,
        max_log_size,
        ..Default::default()
    };

    // When not running as root, warm the sudo credential cache so the
    // user is prompted once (with a visible terminal) before eBPF binaries
    // are spawned with piped stdio.  Skip if passwordless sudo already works.
    if unsafe { libc::geteuid() } != 0 {
        let has_cached = std::process::Command::new("sudo")
            .args(["-n", "true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !has_cached {
            println!("🔑 eBPF probes require root. Requesting sudo access...");
            let ok = std::process::Command::new("sudo")
                .arg("true")
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                return Err(RunnerError::from(
                    "sudo authentication failed. Either run as root (`sudo -E agentsight exec -- ...`) \
                     or grant your user passwordless sudo for the eBPF binaries."
                ));
            }
        }
    }

    let mut agent = build_trace_agent(binary_extractor, &cfg)?;

    // Start web server before launching the child so the UI is ready immediately.
    let _server_handle = start_web_server_if_enabled(
        enable_server,
        server_port,
        log_file,
        db_path_for_adapters.as_deref(),
    )
    .await
    .map_err(|e| RunnerError::from(format!("Failed to start server: {}", e)))?;

    // Attach eBPF first (uprobes bind to the binary file, so they catch the
    // child even though it starts a moment later).
    let mut stream = agent.run().await?;

    if enable_server {
        println!("🌐 Web UI: http://127.0.0.1:{}", server_port);
    }
    println!("▶ Launching: {}", command.join(" "));
    println!("{}", "=".repeat(60));

    // Keep interactive tools on inherited stdio. For known headless JSON runs,
    // tee stdout/stderr so CLI-native usage summaries can be stored as evidence.
    let capture_cli_output =
        should_capture_cli_output(program, prog_args, db_path_for_adapters.as_deref());
    if capture_cli_output {
        println!("✓ CLI output evidence capture enabled");
    }

    let mut command_builder = tokio::process::Command::new(program);
    command_builder.args(prog_args);
    if capture_cli_output {
        command_builder
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
    }
    // When running as root (via sudo), drop the child back to the real user
    // so the agent doesn't have elevated privileges.
    if let Some((uid, gid)) = target_user_ids() {
        println!("✓ Dropping child to uid={} gid={}", uid, gid);
        unsafe {
            command_builder.pre_exec(move || {
                if libc::setgid(gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = command_builder
        .spawn()
        .map_err(|e| RunnerError::from(format!("failed to launch '{}': {}", program, e)))?;
    let child_pid = child.id().unwrap_or_default();
    let stdout_task = if capture_cli_output {
        child.stdout.take().map(|stdout| {
            tokio::spawn(tee_child_stream(
                stdout,
                "stdout",
                CLI_OUTPUT_CAPTURE_MAX_BYTES,
            ))
        })
    } else {
        None
    };
    let stderr_task = if capture_cli_output {
        child.stderr.take().map(|stderr| {
            tokio::spawn(tee_child_stream(
                stderr,
                "stderr",
                CLI_OUTPUT_CAPTURE_MAX_BYTES,
            ))
        })
    } else {
        None
    };

    let shutdown = crate::shutdown_notify();
    let mut target_exited = false;
    let mut exit_status = None;
    // Consume events and watch for the child to exit, whichever happens.
    loop {
        tokio::select! {
            maybe_event = stream.next() => {
                match maybe_event {
                    Some(_event) => {} // drive the stream; events are persisted via the file logger
                    None => {
                        println!("\n⚠ Monitoring stream ended before target exited. Stopping target.");
                        break;
                    }
                }
            }
            status = child.wait() => {
                match status {
                    Ok(s) => {
                        println!("\n{}\n✓ Target exited ({}). Stopping monitoring.", "=".repeat(60), s);
                        exit_status = Some(s);
                    }
                    Err(e) => println!("\n⚠ Error waiting on target: {}", e),
                }
                target_exited = true;
                drain_stream_for(&mut stream, tokio::time::Duration::from_millis(5000)).await;
                break;
            }
            _ = shutdown.notified() => {
                println!("\n✓ Shutdown requested. Stopping target and monitoring.");
                break;
            }
        }
    }
    if !target_exited {
        stop_child(&mut child).await;
    }
    drop(stream);
    drop(agent);

    let stdout_capture = match stdout_task {
        Some(task) => match task.await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                println!("⚠ Error capturing child stdout: {}", e);
                Vec::new()
            }
            Err(e) => {
                println!("⚠ Child stdout capture task failed: {}", e);
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    let stderr_capture = match stderr_task {
        Some(task) => match task.await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                println!("⚠ Error capturing child stderr: {}", e);
                Vec::new()
            }
            Err(e) => {
                println!("⚠ Child stderr capture task failed: {}", e);
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    if capture_cli_output {
        persist_cli_output_evidence(
            db_path_for_adapters.as_deref(),
            log_file,
            program,
            prog_args,
            child_pid,
            &comm,
            exit_status,
            &stdout_capture,
            &stderr_capture,
        )?;
    }

    print_global_http_filter_metrics();
    print_global_ssl_filter_metrics();
    run_capture_adapters(db_path_for_adapters.as_deref(), adapter)?;

    if let Some(ref db) = db_path_for_adapters {
        print_session_summary(db);
    }

    if enable_server {
        println!(
            "Recorded data remains viewable at http://127.0.0.1:{} (log: {})",
            server_port, log_file
        );
    }

    Ok(())
}

pub(crate) async fn stop_child(child: &mut tokio::process::Child) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(e) => {
            println!("⚠ Error checking target status: {}", e);
            return;
        }
    }

    match tokio::time::timeout(tokio::time::Duration::from_secs(2), child.wait()).await {
        Ok(Ok(_)) => return,
        Ok(Err(e)) => {
            println!("⚠ Error waiting for target shutdown: {}", e);
            return;
        }
        Err(_) => {}
    }

    if let Err(e) = child.kill().await {
        println!("⚠ Failed to kill target process: {}", e);
    }
}
