use crate::log::SharedLog;
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallKind {
    WindowsDefender,
    Ufw,
    Iptables,
    MacosPf,
    Unknown,
}

pub fn detect() -> FirewallKind {
    if cfg!(target_os = "windows") {
        FirewallKind::WindowsDefender
    } else if cfg!(target_os = "macos") {
        FirewallKind::MacosPf
    } else if binary_exists("ufw") {
        FirewallKind::Ufw
    } else if binary_exists("iptables") {
        FirewallKind::Iptables
    } else {
        FirewallKind::Unknown
    }
}

fn binary_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns (enabled, raw status text for display).
pub fn status(kind: FirewallKind, log: &SharedLog) -> (Option<bool>, String) {
    let output = match kind {
        FirewallKind::WindowsDefender => Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetFirewallProfile | Select-Object Name,Enabled | Format-Table -HideTableHeaders",
            ])
            .output(),
        FirewallKind::Ufw => Command::new("ufw").arg("status").output(),
        FirewallKind::Iptables => Command::new("iptables").args(["-L", "-n"]).output(),
        FirewallKind::MacosPf => Command::new("/usr/sbin/pfctl").args(["-s", "info"]).output(),
        FirewallKind::Unknown => {
            log.warn("Firewall", "No supported firewall backend detected");
            return (None, "Unknown".to_string());
        }
    };

    match output {
        Ok(out) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let enabled = match kind {
                FirewallKind::WindowsDefender => Some(text.to_lowercase().contains("true")),
                FirewallKind::Ufw => Some(text.to_lowercase().contains("active")),
                FirewallKind::Iptables => Some(!text.trim().is_empty()),
                FirewallKind::MacosPf => Some(text.to_lowercase().contains("enabled")),
                FirewallKind::Unknown => None,
            };
            (enabled, text)
        }
        Err(e) => {
            log.warn("Firewall", format!("Status check failed: {e}"));
            (None, format!("Error: {e}"))
        }
    }
}

pub fn set_enabled(kind: FirewallKind, enable: bool, log: &SharedLog) -> Result<String, String> {
    log.info("Firewall", format!("Setting firewall enabled={enable}"));
    let result = match kind {
        FirewallKind::WindowsDefender => {
            let state = if enable { "on" } else { "off" };
            Command::new("netsh")
                .args(["advfirewall", "set", "allprofiles", "state", state])
                .output()
        }
        FirewallKind::Ufw => {
            let action = if enable { "enable" } else { "disable" };
            // ufw prompts "y/n" on enable; --force skips that interactive prompt.
            Command::new("pkexec").args(["ufw", "--force", action]).output()
        }
        FirewallKind::MacosPf => {
            let state = if enable { "on" } else { "off" };
            Command::new("sudo")
                .args([
                    "/usr/libexec/ApplicationFirewall/socketfilterfw",
                    "--setglobalstate",
                    state,
                ])
                .output()
        }
        FirewallKind::Iptables => {
            return Err(
                "Direct iptables enable/disable toggle isn't supported here — install ufw for one-click control."
                    .to_string(),
            );
        }
        FirewallKind::Unknown => return Err("No supported firewall backend detected".to_string()),
    };
    run_result(result, log)
}

/// Blocks inbound traffic from a specific IP. Pairs naturally with Network
/// Monitor alerts (e.g. a "Block this IP" action next to a SYN-flood alert).
pub fn block_ip(kind: FirewallKind, ip: &str, log: &SharedLog) -> Result<String, String> {
    log.warn("Firewall", format!("Blocking inbound traffic from {ip}"));
    let rule_name = format!("CyberWarrior-Block-{ip}");

    let result = match kind {
        FirewallKind::WindowsDefender => Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={rule_name}"),
                "dir=in",
                "action=block",
                &format!("remoteip={ip}"),
            ])
            .output(),
        FirewallKind::Ufw => Command::new("pkexec").args(["ufw", "deny", "from", ip]).output(),
        FirewallKind::Iptables => Command::new("pkexec")
            .args(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            .output(),
        FirewallKind::MacosPf => {
            return Err(
                "macOS packet-filter blocking needs a pf anchor/table set up first — not automated yet."
                    .to_string(),
            );
        }
        FirewallKind::Unknown => return Err("No supported firewall backend detected".to_string()),
    };
    run_result(result, log)
}

fn run_result(result: std::io::Result<std::process::Output>, log: &SharedLog) -> Result<String, String> {
    match result {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            log.info("Firewall", "Command completed successfully");
            Ok(text)
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            log.alert("Firewall", format!("Command failed: {err}"));
            Err(err)
        }
        Err(e) => {
            log.alert("Firewall", format!("Failed to run firewall command: {e}"));
            Err(e.to_string())
        }
    }
}
