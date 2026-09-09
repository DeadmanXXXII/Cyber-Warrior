use crate::log::SharedLog;
use crate::modules::{malware_scan, secrets_scanner, vulnerability_scan};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Config for the three schedulable scans. Persisted in Settings; a copy of
/// this also lives in an `Arc<Mutex<_>>` that the background loop reads,
/// refreshed every time Settings are saved (same pattern as alert_config).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScheduleConfig {
    pub malware_scan_enabled: bool,
    pub malware_scan_interval_hours: u32,
    pub malware_scan_last_run: Option<String>,
    pub malware_root: Option<PathBuf>,
    pub malware_signatures_path: Option<PathBuf>,

    pub secrets_scan_enabled: bool,
    pub secrets_scan_interval_hours: u32,
    pub secrets_scan_last_run: Option<String>,
    pub secrets_root: Option<PathBuf>,

    pub vuln_scan_enabled: bool,
    pub vuln_scan_interval_hours: u32,
    pub vuln_scan_last_run: Option<String>,
    pub nvd_api_key: Option<String>,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            malware_scan_enabled: false,
            malware_scan_interval_hours: 24,
            malware_scan_last_run: None,
            malware_root: None,
            malware_signatures_path: None,
            secrets_scan_enabled: false,
            secrets_scan_interval_hours: 24,
            secrets_scan_last_run: None,
            secrets_root: None,
            vuln_scan_enabled: false,
            vuln_scan_interval_hours: 24,
            vuln_scan_last_run: None,
            nvd_api_key: None,
        }
    }
}

fn is_due(last_run: &Option<String>, interval_hours: u32) -> bool {
    let Some(last) = last_run else { return true };
    match DateTime::parse_from_rfc3339(last) {
        Ok(t) => Local::now().signed_duration_since(t.with_timezone(&Local)).num_hours() >= interval_hours as i64,
        Err(_) => true,
    }
}

/// Runs until the process exits. Checks every 5 minutes whether any enabled
/// scheduled scan is due, and if so runs it using the exact same module
/// functions the manual tabs use — nothing scheduler-specific about the scan
/// itself, only the "is it time yet" decision.
pub fn run_loop(config: Arc<Mutex<ScheduleConfig>>, log: SharedLog) {
    loop {
        std::thread::sleep(Duration::from_secs(300));
        let snapshot = config.lock().unwrap().clone();
        let now = Local::now().to_rfc3339();

        if snapshot.malware_scan_enabled && is_due(&snapshot.malware_scan_last_run, snapshot.malware_scan_interval_hours) {
            if let Some(root) = &snapshot.malware_root {
                log.info("Scheduler", "Running scheduled Malware Scan");
                let signatures = malware_scan::load_signatures(snapshot.malware_signatures_path.as_deref());
                let (scanned, matches) = malware_scan::scan(root, &signatures, &log);
                log.info("Scheduler", format!("Scheduled Malware Scan complete: {scanned} file(s) scanned, {matches} match(es)"));
            } else {
                log.warn("Scheduler", "Scheduled Malware Scan is enabled but no scan folder is set in Settings");
            }
            config.lock().unwrap().malware_scan_last_run = Some(now.clone());
        }

        if snapshot.secrets_scan_enabled && is_due(&snapshot.secrets_scan_last_run, snapshot.secrets_scan_interval_hours) {
            if let Some(root) = &snapshot.secrets_root {
                log.info("Scheduler", "Running scheduled Secrets Scan");
                let (scanned, findings) = secrets_scanner::scan(root, &log);
                log.info("Scheduler", format!("Scheduled Secrets Scan complete: {scanned} file(s) scanned, {} finding(s)", findings.len()));
            } else {
                log.warn("Scheduler", "Scheduled Secrets Scan is enabled but no scan folder is set in Settings");
            }
            config.lock().unwrap().secrets_scan_last_run = Some(now.clone());
        }

        if snapshot.vuln_scan_enabled && is_due(&snapshot.vuln_scan_last_run, snapshot.vuln_scan_interval_hours) {
            log.info("Scheduler", "Running scheduled Vulnerability Scan");
            let packages = vulnerability_scan::detect_installed_packages(&log);
            let matches = vulnerability_scan::scan(&packages, snapshot.nvd_api_key.as_deref(), &log);
            log.info("Scheduler", format!("Scheduled Vulnerability Scan complete: {} package(s) checked, {} match(es)", packages.len(), matches.len()));
            config.lock().unwrap().vuln_scan_last_run = Some(now.clone());
        }
    }
}
