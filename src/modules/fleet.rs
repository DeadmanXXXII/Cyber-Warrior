use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub hostname: String,
    pub timestamp: String,
    pub compliance_score: f32,
    pub findings_total: usize,
    pub findings_actively_exploited: usize,
    pub firewall_enabled: Option<bool>,
    pub antivirus_summary: String,
}

fn sanitize(name: &str) -> String {
    name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

pub fn current_hostname() -> String {
    gethostname::gethostname().to_string_lossy().to_string()
}

/// Writes this device's status as `<hostname>.status.json` in the shared
/// folder. No coordination beyond "same folder" — this is deliberately
/// simple (no server, no auth) and only as private as whatever folder you
/// point it at (a synced Dropbox/OneDrive folder, or a network share both
/// machines already have access to).
pub fn publish_status(folder: &Path, status: &DeviceStatus) -> Result<(), String> {
    std::fs::create_dir_all(folder).map_err(|e| e.to_string())?;
    let path = folder.join(format!("{}.status.json", sanitize(&status.hostname)));
    let json = serde_json::to_string_pretty(status).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())
}

/// Reads every `*.status.json` file in the folder — this device's own and
/// anyone else's who has published to the same location.
pub fn load_fleet_status(folder: &Path) -> Vec<DeviceStatus> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(folder) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    if let Ok(status) = serde_json::from_str::<DeviceStatus>(&text) {
                        out.push(status);
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    out
}
