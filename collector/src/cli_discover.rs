// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::cli_output::{print_discovery, print_json};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiscoveryRow {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    pub(crate) command: &'static str,
    pub(crate) available: bool,
    pub(crate) path: Option<String>,
    pub(crate) recommended_capture: &'static str,
}

pub(crate) fn run_discover(json: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let rows = discover_rows();
    if json {
        print_json(&rows)?;
        return Ok(());
    }

    print_discovery(&rows, &crate::cli_db::count_local_sessions());
    Ok(())
}

fn discover_rows() -> Vec<DiscoveryRow> {
    vec![
        row(
            "claude-code",
            "Claude Code",
            "claude",
            "agentsight record --db record.db -- claude -p 'hello' --output-format json",
        ),
        row(
            "gemini-cli",
            "Gemini CLI",
            "gemini",
            "agentsight record --db record.db -- gemini --prompt 'hello' --json",
        ),
        row(
            "openclaw",
            "OpenClaw",
            "docker",
            "agentsight record -c node --db record.db --binary-path docker://<container>",
        ),
    ]
}

fn row(
    id: &'static str,
    name: &'static str,
    command: &'static str,
    recommended_capture: &'static str,
) -> DiscoveryRow {
    let path = find_on_path(command);
    DiscoveryRow {
        id,
        name,
        command,
        available: path.is_some(),
        path: path.map(|p| p.display().to_string()),
        recommended_capture,
    }
}

fn find_on_path(command: &str) -> Option<PathBuf> {
    if command.contains(std::path::MAIN_SEPARATOR) {
        let path = PathBuf::from(command);
        return is_executable_file(&path).then_some(path);
    }
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(command))
        .find(|candidate| is_executable_file(candidate))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.is_file()
        && path
            .metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_rows_include_supported_agent_views() {
        let rows = discover_rows();
        let ids: Vec<_> = rows.iter().map(|row| row.id).collect();
        assert!(ids.contains(&"claude-code"));
        assert!(ids.contains(&"gemini-cli"));
        assert!(ids.contains(&"openclaw"));
    }
}
