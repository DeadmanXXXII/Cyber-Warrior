use crate::log::SharedLog;
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvKind {
    WindowsDefender,
    ClamAv,
    NotDetected,
}

pub fn detect() -> AvKind {
    if cfg!(target_os = "windows") {
        AvKind::WindowsDefender
    } else if binary_exists("clamscan") {
        AvKind::ClamAv
    } else {
        AvKind::NotDetected
    }
}

fn binary_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[derive(Clone, Debug, Default)]
pub struct AvStatus {
    pub enabled: Option<bool>,
    pub real_time_protection: Option<bool>,
    pub raw: String,
}

pub fn status(kind: AvKind, log: &SharedLog) -> AvStatus {
    match kind {
        AvKind::WindowsDefender => {
            let output = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json",
                ])
                .output();
            match output {
                Ok(out) if out.status.success() => {
                    let text = String::from_utf8_lossy(&out.stdout).to_string();
                    let lower = text.to_lowercase();
                    AvStatus {
                        enabled: Some(lower.contains("\"antivirusenabled\": true") || lower.contains("\"antivirusenabled\":true")),
                        real_time_protection: Some(
                            lower.contains("\"realtimeprotectionenabled\": true")
                                || lower.contains("\"realtimeprotectionenabled\":true"),
                        ),
                        raw: text,
                    }
                }
                _ => {
                    log.warn("Antivirus", "Could not query Windows Defender status");
                    AvStatus::default()
                }
            }
        }
        AvKind::ClamAv => {
            let version = Command::new("clamscan").arg("--version").output();
            match version {
                Ok(out) if out.status.success() => AvStatus {
                    enabled: Some(true),
                    real_time_protection: Some(false), // clamscan is on-demand, not a resident shield
                    raw: String::from_utf8_lossy(&out.stdout).to_string(),
                },
                _ => AvStatus::default(),
            }
        }
        AvKind::NotDetected => {
            log.warn("Antivirus", "No supported antivirus detected");
            AvStatus::default()
        }
    }
}

pub fn quick_scan(kind: AvKind, target: Option<&std::path::Path>, log: &SharedLog) -> Result<String, String> {
    log.info("Antivirus", "Starting quick scan");
    let output = match kind {
        AvKind::WindowsDefender => Command::new("powershell")
            .args(["-NoProfile", "-Command", "Start-MpScan -ScanType QuickScan"])
            .output(),
        AvKind::ClamAv => {
            let path = target.map(|p| p.display().to_string()).unwrap_or_else(|| ".".to_string());
            Command::new("clamscan").args(["-r", "--bell", "-i", &path]).output()
        }
        AvKind::NotDetected => return Err("No antivirus detected to scan with".to_string()),
    };
    finish(output, "Antivirus", log)
}

pub fn update_definitions(kind: AvKind, log: &SharedLog) -> Result<String, String> {
    log.info("Antivirus", "Updating signature definitions");
    let output = match kind {
        AvKind::WindowsDefender => Command::new("powershell")
            .args(["-NoProfile", "-Command", "Update-MpSignature"])
            .output(),
        AvKind::ClamAv => Command::new("pkexec").arg("freshclam").output(),
        AvKind::NotDetected => return Err("No antivirus detected".to_string()),
    };
    finish(output, "Antivirus", log)
}

/// Installs ClamAV via the OS's own trusted package manager (Windows already
/// ships Defender, so this only applies on Linux/macOS).
pub fn install_clamav(log: &SharedLog) -> Result<String, String> {
    log.info("Antivirus", "Installing ClamAV");
    let output = if cfg!(target_os = "macos") {
        Command::new("brew").args(["install", "clamav"]).output()
    } else {
        Command::new("pkexec")
            .arg("sh")
            .arg("-c")
            .arg("apt-get update && apt-get install -y clamav")
            .output()
    };
    finish(output, "Antivirus", log)
}

fn finish(output: std::io::Result<std::process::Output>, source: &str, log: &SharedLog) -> Result<String, String> {
    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            log.info(source, "Command completed successfully");
            Ok(text)
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            log.alert(source, format!("Command failed: {err}"));
            Err(err)
        }
        Err(e) => {
            log.alert(source, format!("Failed to run command: {e}"));
            Err(e.to_string())
        }
    }
}
