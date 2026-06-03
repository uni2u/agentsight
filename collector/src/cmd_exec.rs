// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use futures::stream::StreamExt;

use crate::binary_resolver::resolve_binary_path;
use crate::cli_db::run_capture_adapters;
use crate::cli_output::{SessionSummary, print_session_summary as print_summary};
use crate::cmd_trace::{
    TraceConfig, build_trace_agent, drain_stream_for, start_web_server_if_enabled,
};
use crate::framework::{
    analyzers::{print_global_http_filter_metrics, print_global_ssl_filter_metrics},
    binary_extractor::BinaryExtractor,
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
        RunnerError::from(format!(
            "failed to create session directory {}: {}",
            dir.display(),
            e
        ))
    })?;
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
    Ok(dir.join(format!("{}.db", ts)).to_string_lossy().to_string())
}

pub(crate) fn print_session_summary(db_path: &str) {
    if let Ok(summary) = SessionSummary::from_sqlite(db_path) {
        println!();
        print_summary(&summary);
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
    server_listen: &str,
    server_port: u16,
    print_summary: bool,
) -> Result<Option<String>, RunnerError> {
    let program = command.first().ok_or_else(|| {
        RunnerError::from("record requires a command to run, e.g. `agentsight record -- claude`")
    })?;
    let prog_args = &command[1..];

    // Auto-create a session database when the user didn't specify --db.
    let (db_path, adapter) = if db_path.is_some() {
        (db_path, adapter)
    } else {
        match default_session_db_path() {
            Ok(p) => {
                crate::session::cleanup_old_sessions();
                (Some(p), Some(adapter.unwrap_or("auto")))
            }
            Err(e) => {
                eprintln!(
                    "⚠ Could not create session DB ({}), continuing without it.",
                    e
                );
                (None, adapter)
            }
        }
    };

    println!("AgentSight record");
    println!("{}", "=".repeat(60));

    let binary_path = match binary_path_override {
        Some(p) => {
            println!("→ Using provided binary path: {}", p);
            p.to_string()
        }
        None => {
            let p = resolve_binary_path(program).map_err(|e| {
                RunnerError::from(format!("failed to resolve '{}': {}", program, e))
            })?;
            println!("✓ Auto-discovered binary: {}", p);
            p
        }
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
                    "sudo authentication failed. Either run as root (`sudo -E agentsight record -- ...`) \
                     or grant your user passwordless sudo for the eBPF binaries.",
                ));
            }
        }
    }

    let mut command_builder = tokio::process::Command::new("/bin/sh");
    command_builder
        .arg("-c")
        .arg("target=$1; shift; kill -STOP $$; exec \"$target\" \"$@\"")
        .arg("agentsight-target")
        .arg(program)
        .args(prog_args);
    let target_ids = target_user_ids();
    if let Some((uid, gid)) = target_ids {
        println!("✓ Dropping child to uid={} gid={}", uid, gid);
    }
    unsafe {
        command_builder.pre_exec(move || {
            if let Some((uid, gid)) = target_ids {
                if libc::setgid(gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command_builder
        .spawn()
        .map_err(|e| RunnerError::from(format!("failed to launch '{}': {}", program, e)))?;
    let child_pid = child
        .id()
        .ok_or_else(|| RunnerError::from("failed to get target child PID"))?;
    println!("✓ Run attribution session: {}", child_pid);

    let db_path_for_adapters = db_path.clone();
    let cfg = TraceConfig {
        ssl: true,
        pid: Some(child_pid),
        session_id: Some(child_pid),
        ssl_filter: vec!["data=0\\r\\n\\r\\n".to_string()],
        ssl_http: true,
        process: true,
        stdio: true,
        stdio_max_bytes: 8192,
        system: true,
        system_interval: 2,
        http_filter: vec!["request.path_prefix=/v1/rgstr | response.status_code=202 | request.method=HEAD | response.body=".to_string()],
        binary_path: Some(binary_path),
        log_file: log_file.to_string(),
        db_path,
        adapter: adapter.map(str::to_string),
        quiet: true,
        rotate_logs,
        max_log_size,
        server_listen: Some(server_listen.to_string()),
        ..Default::default()
    };

    let mut agent = build_trace_agent(binary_extractor, &cfg)?;

    let server_handle = start_web_server_if_enabled(
        enable_server,
        server_listen,
        server_port,
        log_file,
        db_path_for_adapters.as_deref(),
    )
    .await
    .map_err(|e| RunnerError::from(format!("Failed to start server: {}", e)))?;

    let mut stream = match agent.run().await {
        Ok(stream) => stream,
        Err(e) => {
            stop_child(&mut child).await;
            return Err(e);
        }
    };

    if let Some(server) = &server_handle {
        println!("Web UI: {}", server.url);
    }
    println!("▶ Launching: {}", command.join(" "));
    println!("{}", "=".repeat(60));

    tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
    if let Err(e) = continue_child(child_pid) {
        stop_child(&mut child).await;
        return Err(e);
    }

    let shutdown = crate::shutdown_notify();
    let mut target_exited = false;
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

    print_global_http_filter_metrics();
    print_global_ssl_filter_metrics();
    run_capture_adapters(db_path_for_adapters.as_deref(), adapter)?;

    if print_summary && let Some(ref db) = db_path_for_adapters {
        print_session_summary(db);
    }

    if let Some(server) = &server_handle {
        println!(
            "Recorded data remains viewable at {} (log: {})",
            server.url, log_file
        );
    }

    Ok(db_path_for_adapters)
}

fn continue_child(pid: u32) -> Result<(), RunnerError> {
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) };
    if result == 0 {
        Ok(())
    } else {
        Err(RunnerError::from(format!(
            "failed to continue target process {}: {}",
            pid,
            std::io::Error::last_os_error()
        )))
    }
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
