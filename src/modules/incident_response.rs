use crate::log::SharedLog;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Lists runnable scripts inside the approved folder. This is the *only*
/// place script paths come from — there is no free-text "path to run" field
/// in the GUI, by design, so the app can never be pointed at an arbitrary
/// executable at runtime.
pub fn list_playbooks(approved_folder: &Path) -> Vec<PathBuf> {
    let mut scripts = Vec::new();
    if let Ok(entries) = std::fs::read_dir(approved_folder) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if matches!(ext, "sh" | "ps1" | "py" | "bat") {
                        scripts.push(path);
                    }
                }
            }
        }
    }
    scripts.sort();
    scripts
}

/// Runs one playbook script and returns its combined stdout/stderr.
/// `script` must be a path returned by `list_playbooks` for the same
/// approved folder — callers should not accept arbitrary paths here.
pub fn run_playbook(approved_folder: &Path, script: &Path, log: &SharedLog) -> Result<String, String> {
    // Defense in depth: refuse to run anything outside the approved folder,
    // even if a caller ever passed one in by mistake.
    let canonical_folder = approved_folder
        .canonicalize()
        .map_err(|e| format!("Cannot resolve approved folder: {e}"))?;
    let canonical_script = script
        .canonicalize()
        .map_err(|e| format!("Cannot resolve script path: {e}"))?;
    if !canonical_script.starts_with(&canonical_folder) {
        let msg = format!(
            "Refused to run {} — outside the approved scripts folder",
            script.display()
        );
        log.alert("IncidentResponse", &msg);
        return Err(msg);
    }

    log.info("IncidentResponse", format!("Running playbook: {}", script.display()));

    let output = Command::new(&canonical_script)
        .output()
        .map_err(|e| format!("Failed to execute {}: {e}", script.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    if output.status.success() {
        log.info("IncidentResponse", format!("Playbook finished OK: {}", script.display()));
    } else {
        log.alert(
            "IncidentResponse",
            format!("Playbook exited with error ({}): {}", output.status, script.display()),
        );
    }

    Ok(combined)
}
