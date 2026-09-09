use crate::log::SharedLog;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};

#[derive(Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// RFC3339 timestamp.
    pub timestamp: String,
    pub compliance_score: f32,
    pub findings_total: usize,
    pub findings_actively_exploited: usize,
}

fn history_path() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("cyberwarrior")
        .join("history.jsonl")
}

pub fn append_snapshot(snapshot: &Snapshot, log: &SharedLog) {
    let path = history_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let line = match serde_json::to_string(snapshot) {
        Ok(l) => l,
        Err(e) => {
            log.warn("History", format!("Couldn't serialize snapshot: {e}"));
            return;
        }
    };
    match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut file) => {
            let _ = writeln!(file, "{line}");
        }
        Err(e) => log.warn("History", format!("Couldn't write history file: {e}")),
    }
}

pub fn load_history() -> Vec<Snapshot> {
    let path = history_path();
    let Ok(file) = std::fs::File::open(&path) else { return Vec::new() };
    std::io::BufReader::new(file)
        .lines()
        .filter_map(|l| l.ok())
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

/// Records a snapshot at most once per calendar day, so opening the app
/// repeatedly in one day doesn't spam the history with identical points.
pub fn record_daily_snapshot_if_needed(compliance_score: f32, findings_total: usize, findings_actively_exploited: usize, log: &SharedLog) {
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let already_recorded_today = load_history()
        .last()
        .map(|s| s.timestamp.starts_with(&today))
        .unwrap_or(false);

    if !already_recorded_today {
        let snapshot = Snapshot {
            timestamp: chrono::Local::now().to_rfc3339(),
            compliance_score,
            findings_total,
            findings_actively_exploited,
        };
        append_snapshot(&snapshot, log);
    }
}
