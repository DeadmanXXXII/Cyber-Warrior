use crate::log::SharedLog;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

/// A user-registered external tool (Snort, Burp Suite CLI, etc.). Registered
/// once via the Integrations settings screen — there is no free-text "path
/// to run" field anywhere else in the app, so nothing at runtime can point
/// this at an arbitrary executable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolIntegration {
    pub name: String,
    pub executable: PathBuf,
    pub args: String,
}

pub fn launch(tool: &ToolIntegration, log: &SharedLog) -> Result<(), String> {
    log.info("Integrations", format!("Launching {}", tool.name));
    let args: Vec<&str> = tool.args.split_whitespace().collect();
    Command::new(&tool.executable)
        .args(args)
        .spawn()
        .map(|_| ())
        .map_err(|e| {
            let msg = format!("Failed to launch {}: {e}", tool.name);
            log.alert("Integrations", &msg);
            msg
        })
}
