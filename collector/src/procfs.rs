// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PidSeed {
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
}

impl PidSeed {
    pub(crate) fn arg_value(self) -> String {
        format!("{}:{}", self.pid, self.ppid)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProcInfo {
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    pub(crate) session_id: u32,
    pub(crate) comm: String,
    pub(crate) command: String,
    pub(crate) ticks: u64,
    pub(crate) starttime_ticks: u64,
    pub(crate) rss_kb: u64,
    pub(crate) rss_mb: u64,
    pub(crate) vsz_kb: u64,
    pub(crate) threads: u32,
}

impl ProcInfo {
    pub(crate) fn seed(&self) -> PidSeed {
        PidSeed {
            pid: self.pid,
            ppid: self.ppid,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProcSnapshot {
    pub(crate) at: Instant,
    pub(crate) uptime_s: f64,
    pub(crate) procs: BTreeMap<u32, ProcInfo>,
}

impl ProcSnapshot {
    pub(crate) fn collect() -> io::Result<Self> {
        let page_size = page_size_bytes();
        let mut procs = BTreeMap::new();

        for entry in fs::read_dir("/proc")? {
            let Ok(entry) = entry else { continue };
            let file_name = entry.file_name();
            let Some(pid) = file_name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
                continue;
            };
            let Some(proc_info) = read_proc_info(pid, page_size) else {
                continue;
            };
            procs.insert(pid, proc_info);
        }

        Ok(Self {
            at: Instant::now(),
            uptime_s: read_uptime_s().unwrap_or_default(),
            procs,
        })
    }

    pub(crate) fn children_by_ppid(&self) -> HashMap<u32, Vec<u32>> {
        children_by_ppid(&self.procs)
    }

    pub(crate) fn process_family(&self, root: u32) -> Vec<u32> {
        process_family(root, &self.children_by_ppid(), &self.procs)
    }

    pub(crate) fn seeds_for_all(&self) -> Vec<PidSeed> {
        self.procs.values().map(ProcInfo::seed).collect()
    }

    pub(crate) fn seeds_for_pid_family(&self, root: u32) -> Vec<PidSeed> {
        self.process_family(root)
            .into_iter()
            .filter_map(|pid| self.procs.get(&pid).map(ProcInfo::seed))
            .collect()
    }

    pub(crate) fn seeds_for_session(&self, session_id: u32) -> Vec<PidSeed> {
        self.procs
            .values()
            .filter(|proc_info| proc_info.session_id == session_id)
            .map(ProcInfo::seed)
            .collect()
    }

    pub(crate) fn seeds_for_comm(&self, comm: &str) -> Vec<PidSeed> {
        let roots = self
            .procs
            .values()
            .filter(|proc_info| process_matches_comm(proc_info, comm))
            .filter(|proc_info| !matching_ancestor(proc_info, self, comm))
            .map(|proc_info| proc_info.pid)
            .collect::<Vec<_>>();

        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for pid in roots {
            for family_pid in self.process_family(pid) {
                if seen.insert(family_pid)
                    && let Some(proc_info) = self.procs.get(&family_pid)
                {
                    out.push(proc_info.seed());
                }
            }
        }
        out
    }

    pub(crate) fn pids_matching_comm(&self, comm: &str) -> Vec<u32> {
        self.procs
            .values()
            .filter(|proc_info| process_matches_comm(proc_info, comm))
            .map(|proc_info| proc_info.pid)
            .collect()
    }

    pub(crate) fn pids_in_session(&self, session_id: u32) -> Vec<u32> {
        self.procs
            .values()
            .filter(|proc_info| proc_info.session_id == session_id)
            .map(|proc_info| proc_info.pid)
            .collect()
    }
}

pub(crate) fn children_by_ppid(procs: &BTreeMap<u32, ProcInfo>) -> HashMap<u32, Vec<u32>> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for proc_info in procs.values() {
        children
            .entry(proc_info.ppid)
            .or_default()
            .push(proc_info.pid);
    }
    children
}

pub(crate) fn process_family(
    root: u32,
    children: &HashMap<u32, Vec<u32>>,
    procs: &BTreeMap<u32, ProcInfo>,
) -> Vec<u32> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    let mut seen = HashSet::new();
    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) || !procs.contains_key(&pid) {
            continue;
        }
        out.push(pid);
        if let Some(child_pids) = children.get(&pid) {
            stack.extend(child_pids.iter().copied());
        }
    }
    out
}

pub(crate) fn process_cpu_percent(
    proc_info: &ProcInfo,
    previous: Option<&ProcSnapshot>,
    sample: &ProcSnapshot,
) -> f64 {
    let ticks_per_second = ticks_per_second();
    if let Some(previous) = previous
        && let Some(prev_proc) = previous.procs.get(&proc_info.pid)
    {
        let delta_ticks = proc_info.ticks.saturating_sub(prev_proc.ticks);
        let delta_wall = sample.at.duration_since(previous.at).as_secs_f64();
        if delta_wall > 0.0 {
            return (delta_ticks as f64 / ticks_per_second) / delta_wall * 100.0;
        }
    }

    let process_start_s = proc_info.starttime_ticks as f64 / ticks_per_second;
    let elapsed_s = (sample.uptime_s - process_start_s).max(0.001);
    (proc_info.ticks as f64 / ticks_per_second) / elapsed_s * 100.0
}

pub(crate) fn process_age_s(proc_info: &ProcInfo, sample: &ProcSnapshot) -> f64 {
    let process_start_s = proc_info.starttime_ticks as f64 / ticks_per_second();
    (sample.uptime_s - process_start_s).max(0.0)
}

pub(crate) fn agent_name_from_command(comm: &str, command: &str) -> String {
    known_agent_label(comm, command)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if !comm.is_empty() && comm != "unknown" {
                comm.to_string()
            } else {
                command
                    .split_whitespace()
                    .next()
                    .unwrap_or("agent")
                    .to_string()
            }
        })
}

pub(crate) fn known_agent_label(comm: &str, command: &str) -> Option<&'static str> {
    label_from_exec_token(comm).or_else(|| label_from_command_argv(command))
}

pub(crate) fn process_matches_comm(proc_info: &ProcInfo, wanted: &str) -> bool {
    let wanted = wanted.to_ascii_lowercase();
    executable_tokens(&proc_info.command)
        .chain(std::iter::once(proc_info.comm.as_str()))
        .any(|token| token.to_ascii_lowercase().contains(&wanted))
}

fn read_proc_info(pid: u32, page_size: u64) -> Option<ProcInfo> {
    let proc_dir = format!("/proc/{pid}");
    let stat = fs::read_to_string(format!("{proc_dir}/stat")).ok()?;
    let (comm, ppid, session_id, ticks, starttime_ticks) = parse_proc_stat(&stat)?;
    let command = read_cmdline(pid).unwrap_or_else(|| comm.clone());
    let (rss_kb, rss_mb, vsz_kb) = read_statm(pid, page_size).unwrap_or_default();
    let threads = read_thread_count(pid);
    Some(ProcInfo {
        pid,
        ppid,
        session_id,
        comm,
        command,
        ticks,
        starttime_ticks,
        rss_kb,
        rss_mb,
        vsz_kb,
        threads,
    })
}

fn parse_proc_stat(stat: &str) -> Option<(String, u32, u32, u64, u64)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat[open + 1..close].to_string();
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    let ppid = fields.get(1)?.parse().ok()?;
    let session_id = fields.get(3)?.parse().ok()?;
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let starttime_ticks = fields.get(19)?.parse().ok()?;
    Some((
        comm,
        ppid,
        session_id,
        utime.saturating_add(stime),
        starttime_ticks,
    ))
}

fn read_cmdline(pid: u32) -> Option<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let command = bytes
        .split(|byte| *byte == 0)
        .filter_map(|part| std::str::from_utf8(part).ok())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!command.is_empty()).then_some(command)
}

fn read_statm(pid: u32, page_size: u64) -> Option<(u64, u64, u64)> {
    let statm = fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let mut fields = statm.split_whitespace();
    let vsz_pages: u64 = fields.next()?.parse().ok()?;
    let rss_pages: u64 = fields.next()?.parse().ok()?;
    let rss_bytes = rss_pages.saturating_mul(page_size);
    let vsz_bytes = vsz_pages.saturating_mul(page_size);
    Some((
        bytes_to_kb(rss_bytes),
        bytes_to_mb(rss_bytes),
        bytes_to_kb(vsz_bytes),
    ))
}

fn bytes_to_kb(bytes: u64) -> u64 {
    bytes / 1024
}

fn bytes_to_mb(bytes: u64) -> u64 {
    if bytes == 0 {
        0
    } else {
        bytes.div_ceil(1_048_576)
    }
}

fn read_uptime_s() -> Option<f64> {
    fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn page_size_bytes() -> u64 {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value > 0 { value as u64 } else { 4096 }
}

fn ticks_per_second() -> f64 {
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if value > 0 { value as f64 } else { 100.0 }
}

fn read_thread_count(pid: u32) -> u32 {
    fs::read_dir(format!("/proc/{pid}/task"))
        .map(|entries| entries.count() as u32)
        .unwrap_or(1)
}

fn matching_ancestor(proc_info: &ProcInfo, snapshot: &ProcSnapshot, comm: &str) -> bool {
    let mut parent_pid = proc_info.ppid;
    let mut seen = HashSet::new();
    while parent_pid > 0 && seen.insert(parent_pid) {
        let Some(parent) = snapshot.procs.get(&parent_pid) else {
            break;
        };
        if process_matches_comm(parent, comm) {
            return true;
        }
        parent_pid = parent.ppid;
    }
    false
}

fn label_from_command_argv(command: &str) -> Option<&'static str> {
    let mut args = command.split_whitespace();
    let argv0 = args.next()?;
    if let Some(label) = label_from_exec_token(argv0) {
        return Some(label);
    }

    args.filter(|arg| looks_like_exec_path(arg))
        .find_map(label_from_exec_token)
}

fn executable_tokens(command: &str) -> impl Iterator<Item = &str> {
    let mut first = true;
    command.split_whitespace().filter(move |arg| {
        let keep = first || looks_like_exec_path(arg);
        first = false;
        keep
    })
}

fn looks_like_exec_path(token: &str) -> bool {
    let token = token.trim_matches(|ch| matches!(ch, '"' | '\''));
    token.contains('/')
}

fn label_from_exec_token(token: &str) -> Option<&'static str> {
    let token = token.trim_matches(|ch| matches!(ch, '"' | '\''));
    if token.is_empty() {
        return None;
    }

    let lower = token.to_ascii_lowercase();
    let basename = Path::new(&lower)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(lower.as_str());

    label_from_exec_name(basename).or_else(|| label_from_known_package_path(&lower))
}

fn label_from_exec_name(name: &str) -> Option<&'static str> {
    match name {
        "claude" | "claude-code" => Some("claude"),
        "codex" | "codex-cli" => Some("codex"),
        "gemini" | "gemini-cli" => Some("gemini"),
        "opencode" => Some("opencode"),
        "aider" => Some("aider"),
        "goose" => Some("goose"),
        "openclaw" => Some("openclaw"),
        name if name.starts_with("openclaw-") => Some("openclaw"),
        _ => None,
    }
}

fn label_from_known_package_path(path: &str) -> Option<&'static str> {
    if path.contains("@anthropic-ai/claude-code") || path.contains("/claude-code/") {
        Some("claude")
    } else if path.contains("@openai/codex") || path.contains("/codex-linux-") {
        Some("codex")
    } else if path.contains("@google/gemini-cli") || path.contains("/gemini-cli/") {
        Some("gemini")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_agent_label_uses_executable_not_model_argument() {
        assert_eq!(
            known_agent_label(
                "agentsight",
                "agentsight top -s tokens -v all -c claude --model claude-sonnet"
            ),
            None
        );
        assert_eq!(
            known_agent_label(
                "python",
                "python benchmark_runner.py --model claude-sonnet-4-5-20250929"
            ),
            None
        );
        assert_eq!(
            known_agent_label(
                "docker",
                "docker run image bash -c claude --model claude-sonnet-4"
            ),
            None
        );
        assert_eq!(
            known_agent_label("node", "node /opt/npm/bin/codex --model gpt-5"),
            Some("codex")
        );
        assert_eq!(
            known_agent_label("node", "node /home/user/.local/bin/claude"),
            Some("claude")
        );
        assert_eq!(known_agent_label("claude", "claude"), Some("claude"));
        assert_eq!(known_agent_label("openclaw-gatewa", ""), Some("openclaw"));
    }

    #[test]
    fn process_comm_matching_uses_comm_and_executable_tokens_only() {
        let proc_info = ProcInfo {
            pid: 10,
            ppid: 1,
            session_id: 10,
            comm: "agentsight".to_string(),
            command: "agentsight top -c claude --model claude-sonnet".to_string(),
            ticks: 0,
            starttime_ticks: 0,
            rss_kb: 0,
            rss_mb: 0,
            vsz_kb: 0,
            threads: 1,
        };
        assert!(!process_matches_comm(&proc_info, "claude"));
        assert!(process_matches_comm(&proc_info, "agentsight"));
    }
}
