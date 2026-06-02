// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

/// Resolve the user's data-local base directory, respecting SUDO_USER.
pub(crate) fn data_local_base() -> Option<std::path::PathBuf> {
    std::env::var("SUDO_USER")
        .ok()
        .and_then(|user| {
            std::fs::read_to_string("/etc/passwd").ok().and_then(|p| {
                p.lines()
                    .find(|l| l.starts_with(&format!("{}:", user)))
                    .and_then(|l| l.split(':').nth(5))
                    .map(|h| std::path::PathBuf::from(h).join(".local/share"))
            })
        })
        .or_else(dirs::data_local_dir)
        .or_else(|| dirs::home_dir().map(|h| h.join(".local/share")))
}

pub(crate) fn sessions_dir() -> Option<std::path::PathBuf> {
    data_local_base().map(|b| b.join("agentsight").join("sessions"))
}

/// List .db files in the sessions dir, sorted newest-first.
pub(crate) fn sorted_session_dbs(dir: &std::path::Path) -> Vec<std::fs::DirEntry> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "db"))
        .collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.metadata().ok().and_then(|m| m.modified().ok())));
    entries
}

pub(crate) fn resolve_db_or_latest(
    db: &Option<String>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(db) = db {
        return Ok(db.clone());
    }
    latest_session_db().ok_or_else(|| {
        "No session database found. Run `agentsight record` first, or pass --db.".into()
    })
}

pub(crate) fn latest_session_db() -> Option<String> {
    let dir = sessions_dir()?;
    sorted_session_dbs(&dir)
        .first()
        .map(|e| e.path().to_string_lossy().to_string())
}

const MAX_SESSIONS: usize = 50;
const MAX_TOTAL_BYTES: u64 = 500 * 1024 * 1024; // 500 MB

pub(crate) fn cleanup_old_sessions() {
    let Some(dir) = sessions_dir() else { return };
    let entries = sorted_session_dbs(&dir); // newest first
    let mut total_bytes = 0u64;
    for (i, entry) in entries.iter().enumerate() {
        let size = entry.metadata().ok().map(|m| m.len()).unwrap_or(0);
        total_bytes += size;
        if i >= MAX_SESSIONS || total_bytes > MAX_TOTAL_BYTES {
            // Delete this DB and its WAL/SHM files
            let path = entry.path();
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(path.with_extension("db-wal"));
            let _ = std::fs::remove_file(path.with_extension("db-shm"));
        }
    }
}

pub(crate) fn run_db_list() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = sessions_dir().ok_or("cannot determine data directory")?;
    let entries = sorted_session_dbs(&dir);
    crate::cli_output::print_session_list(&dir, &entries);
    Ok(())
}
