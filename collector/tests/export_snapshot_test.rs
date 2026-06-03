// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use rusqlite::Connection;
use serde_json::Value;
use std::process::{Command, Output};

fn agentsight_output(args: &[&str]) -> Output {
    agentsight_output_with_env(args, &[])
}

fn agentsight_output_with_env(args: &[&str], envs: &[(&str, &std::ffi::OsStr)]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_agentsight"))
        .args(args)
        .envs(envs.iter().copied())
        .output()
        .expect("agentsight command should run");
    assert!(
        output.status.success(),
        "agentsight {:?} failed\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn run_agentsight(args: &[&str]) {
    agentsight_output(args);
}

fn agentsight_stdout(args: &[&str]) -> String {
    String::from_utf8(agentsight_output(args).stdout).expect("stdout should be UTF-8")
}

fn agentsight_stdout_with_env(args: &[&str], envs: &[(&str, &std::ffi::OsStr)]) -> String {
    String::from_utf8(agentsight_output_with_env(args, envs).stdout)
        .expect("stdout should be UTF-8")
}

#[test]
fn top_level_help_surfaces_perf_strace_flow() {
    let help = agentsight_stdout(&["--help"]);
    assert!(
        help.contains("stat/top/record/report for AI agent runs"),
        "{help}"
    );
    assert!(help.contains("stat"), "{help}");
    assert!(help.contains("top"), "{help}");
    assert!(help.contains("record"), "{help}");
    assert!(help.contains("report"), "{help}");
    assert!(help.contains("prompts"), "{help}");
    assert!(help.contains("list"), "{help}");
}

#[test]
fn replay_no_adapters_skips_adapter_runs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let db = temp.path().join("record.db");
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/fixtures/sql-adapters/gemini-cli-basic/input.jsonl");

    run_agentsight(&[
        "db",
        "import",
        "--input",
        fixture.to_str().expect("fixture path"),
        "--db",
        db.to_str().expect("db path"),
        "--no-adapters",
    ]);

    let conn = Connection::open(db).expect("db should open");
    let adapter_runs: i64 = conn
        .query_row("SELECT COUNT(*) FROM adapter_runs", [], |row| row.get(0))
        .expect("adapter_runs query should work");
    let generic_tokens: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(total_tokens), 0) FROM token_usage",
            [],
            |row| row.get(0),
        )
        .expect("token query should work");

    assert_eq!(adapter_runs, 0);
    assert_eq!(generic_tokens, 15);
}

#[test]
fn replay_then_export_snapshot_for_static_web() {
    let temp = tempfile::tempdir().expect("tempdir");
    let db = temp.path().join("record.db");
    let snapshot = temp.path().join("trace.agentsight.json");
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/fixtures/sql-adapters/gemini-cli-basic/input.jsonl");

    run_agentsight(&[
        "db",
        "import",
        "--input",
        fixture.to_str().expect("fixture path"),
        "--db",
        db.to_str().expect("db path"),
        "--adapter",
        "auto",
    ]);
    run_agentsight(&[
        "db",
        "export",
        "--db",
        db.to_str().expect("db path"),
        "--output",
        snapshot.to_str().expect("snapshot path"),
    ]);

    let data: Value =
        serde_json::from_slice(&std::fs::read(&snapshot).expect("snapshot should be written"))
            .expect("snapshot should be valid JSON");

    assert_eq!(data["schema_version"], 1);
    assert_eq!(data["summary"]["source"], "sqlite");
    assert_eq!(data["summary"]["total_tokens"], 15);
    assert_eq!(data["token_summary"][0]["group"], "gemini-2.5-pro");
    assert_eq!(data["token_summary"][0]["total_tokens"], 15);
    assert_eq!(data["events"].as_array().expect("events").len(), 2);
    assert_eq!(data["sessions"][0]["agent_type"], "gemini-cli");
    assert_eq!(data["sessions"][0]["total_tokens"], 15);
    assert_eq!(data["agents"][0]["agent_type"], "gemini-cli");
    assert!(
        data["interruptions"]
            .as_array()
            .expect("interruptions")
            .is_empty()
    );
}

#[test]
fn summary_omits_tokens_when_usage_is_unobserved() {
    let temp = tempfile::tempdir().expect("tempdir");
    let db = temp.path().join("record.db");
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/fixtures/no-token-run/input.jsonl");

    run_agentsight(&[
        "db",
        "import",
        "--input",
        fixture.to_str().expect("fixture path"),
        "--db",
        db.to_str().expect("db path"),
        "--no-adapters",
    ]);

    let summary = agentsight_stdout(&["report", "--db", db.to_str().expect("db path")]);
    assert!(summary.contains("agentsight session"), "{summary}");
    assert!(summary.contains("npm(1)"), "{summary}");
    assert!(summary.contains("api.anthropic.com"), "{summary}");
    assert!(
        !summary.contains(" tokens"),
        "summary should not invent token evidence:\n{summary}"
    );
}

#[test]
fn local_summary_reads_codex_session_jsonl() {
    let temp = tempfile::tempdir().expect("tempdir");
    let session_dir = temp.path().join(".codex/sessions/2026/06/02");
    std::fs::create_dir_all(&session_dir).expect("session dir");
    std::fs::write(
        session_dir.join("rollout-test.jsonl"),
        concat!(
            "{\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\"}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":11,\"output_tokens\":4,\"total_tokens\":15}}}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"shell\"}}\n",
        ),
    )
    .expect("codex session");

    let summary =
        agentsight_stdout_with_env(&["report", "--local"], &[("HOME", temp.path().as_os_str())]);
    assert!(summary.contains("codex session"), "{summary}");
    assert!(summary.contains("gpt-5.5"), "{summary}");
    assert!(summary.contains("15 tokens"), "{summary}");
    assert!(summary.contains("shell(1)"), "{summary}");
}

#[test]
fn default_agent_run_summary_commands_are_real() {
    let temp = tempfile::tempdir().expect("tempdir");
    let db = temp.path().join("agent-run-summary.db");
    let snapshot = temp.path().join("snapshot.json");
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/fixtures/agent-run-summary/input.jsonl");

    run_agentsight(&[
        "db",
        "import",
        "--input",
        fixture.to_str().expect("fixture path"),
        "--db",
        db.to_str().expect("db path"),
        "--no-adapters",
    ]);

    let summary = agentsight_stdout(&["report", "--db", db.to_str().expect("db path")]);
    assert!(summary.contains("agentsight session"), "{summary}");
    assert!(summary.contains("claude-sonnet-4-20250514"), "{summary}");
    assert!(summary.contains("1380 tokens"), "{summary}");
    assert!(summary.contains("npm(2)"), "{summary}");
    assert!(summary.contains("node(2)"), "{summary}");
    assert!(
        summary.contains("4 process exits: failure(2), success(2)"),
        "{summary}"
    );
    assert!(summary.contains("package-lock.json"), "{summary}");
    assert!(summary.contains("api.anthropic.com"), "{summary}");
    assert!(summary.contains("registry.npmjs.org"), "{summary}");

    let stat = agentsight_stdout(&["stat", "--db", db.to_str().expect("db path")]);
    assert!(stat.contains("AgentSight stat"), "{stat}");
    assert!(stat.contains("LLM calls:"), "{stat}");
    assert!(stat.contains("1380 total"), "{stat}");
    assert!(stat.contains("process execs:"), "{stat}");
    assert!(stat.contains("network hosts:"), "{stat}");

    let top = agentsight_stdout(&[
        "top",
        "--db",
        db.to_str().expect("db path"),
        "--once",
        "--limit",
        "5",
    ]);
    assert!(top.contains("AgentSight top -"), "{top}");
    assert!(top.contains("static session"), "{top}");
    assert!(top.contains("AGENT"), "{top}");
    assert!(top.contains("TOKENS"), "{top}");
    assert!(top.contains("Hot activity"), "{top}");
    assert!(top.contains("Processes"), "{top}");
    assert!(top.contains("Files"), "{top}");
    assert!(top.contains("Network"), "{top}");
    assert!(top.contains("Models"), "{top}");
    assert!(top.contains("package-lock.json"), "{top}");
    assert!(top.contains("api.anthropic.com"), "{top}");

    let prompts = agentsight_stdout(&["prompts", "--db", db.to_str().expect("db path")]);
    assert!(prompts.contains("fix the failing API test"), "{prompts}");
    assert!(prompts.contains("claude-sonnet-4-20250514"), "{prompts}");

    let prompts_json =
        agentsight_stdout(&["prompts", "--db", db.to_str().expect("db path"), "--json"]);
    assert!(prompts_json.contains("\"request\""), "{prompts_json}");
    assert!(
        prompts_json.contains("fix the failing API test"),
        "{prompts_json}"
    );

    let process_events = agentsight_stdout(&[
        "db",
        "audit",
        "--db",
        db.to_str().expect("db path"),
        "--audit-type",
        "process",
        "--limit",
        "20",
    ]);
    assert!(process_events.contains("/usr/bin/npm"), "{process_events}");
    assert!(process_events.contains("/usr/bin/node"), "{process_events}");
    assert!(process_events.contains("success"), "{process_events}");
    assert!(process_events.contains("failure"), "{process_events}");
    assert!(process_events.contains("exit code 1"), "{process_events}");
    assert!(process_events.contains("exit code 0"), "{process_events}");

    let process_events_json = agentsight_stdout(&[
        "db",
        "audit",
        "--db",
        db.to_str().expect("db path"),
        "--audit-type",
        "process",
        "--json",
        "--limit",
        "20",
    ]);
    let process_json: Value =
        serde_json::from_str(&process_events_json).expect("process audit JSON");
    assert!(
        process_json
            .as_array()
            .expect("process events array")
            .iter()
            .any(|event| event["status"] == "failure" && event["details"]["exit_code"] == 1),
        "{process_events_json}"
    );
    assert!(
        process_json
            .as_array()
            .expect("process events array")
            .iter()
            .any(|event| event["details"]["argv"][0] == "npm"),
        "{process_events_json}"
    );

    let file_events = agentsight_stdout(&[
        "db",
        "audit",
        "--db",
        db.to_str().expect("db path"),
        "--audit-type",
        "file",
        "--json",
        "--limit",
        "20",
    ]);
    let file_json: Value = serde_json::from_str(&file_events).expect("file audit JSON");
    assert!(
        file_json
            .as_array()
            .expect("file events array")
            .iter()
            .any(|event| event["target"] == "/workspace/app/package-lock.json"),
        "{file_events}"
    );

    let token = agentsight_stdout(&[
        "db",
        "token",
        "--db",
        db.to_str().expect("db path"),
        "--json",
    ]);
    let token_json: Value = serde_json::from_str(&token).expect("token JSON");
    assert_eq!(token_json[0]["total_tokens"], 1380);

    run_agentsight(&[
        "db",
        "export",
        "--db",
        db.to_str().expect("db path"),
        "--output",
        snapshot.to_str().expect("snapshot path"),
    ]);
    let snapshot_json: Value =
        serde_json::from_slice(&std::fs::read(&snapshot).expect("snapshot should be written"))
            .expect("snapshot should be valid JSON");
    assert_eq!(snapshot_json["summary"]["total_tokens"], 1380);
    assert!(
        snapshot_json["audit_events"]
            .as_array()
            .expect("audit events")
            .iter()
            .any(|event| event["target"] == "/workspace/app/package-lock.json")
    );
}

#[test]
fn top_without_db_uses_live_process_view() {
    let top = agentsight_stdout(&["top", "--once"]);
    assert!(top.contains("AgentSight top -"), "{top}");
    assert!(top.contains("live sessions"), "{top}");
    assert!(top.contains("SESSION"), "{top}");
    assert!(top.contains("AGENT"), "{top}");
    assert!(top.contains("STATE"), "{top}");
    assert!(top.contains("AGE"), "{top}");
    assert!(top.contains("ACTIVITY"), "{top}");
    assert!(top.contains("EVIDENCE"), "{top}");
}

#[test]
fn top_discovers_agent_native_local_sessions() {
    let temp = tempfile::tempdir().expect("tempdir");
    let session_dir = temp.path().join(".codex/sessions/2026/06/02");
    std::fs::create_dir_all(&session_dir).expect("session dir");
    std::fs::write(
        session_dir.join("rollout-test.jsonl"),
        concat!(
            "{\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\"}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":11,\"output_tokens\":4,\"total_tokens\":15}}}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"shell\"}}\n",
            "{\"type\":\"message\",\"content\":\"fix the test\"}\n",
        ),
    )
    .expect("codex session");

    let top = agentsight_stdout_with_env(
        &["top", "--once", "--limit", "20"],
        &[("HOME", temp.path().as_os_str())],
    );
    assert!(top.contains("live sessions"), "{top}");
    assert!(top.contains("codex:rollout-test"), "{top}");
    assert!(top.contains("TOKENS"), "{top}");
    assert!(top.contains("ACTIVITY"), "{top}");
    assert!(top.contains("15"), "{top}");
    assert!(top.contains("1 tool"), "{top}");
    assert!(top.contains("fix the test"), "{top}");
}
