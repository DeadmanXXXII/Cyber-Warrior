use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Settings {
    /// Only scripts inside this folder can be run by the Incident Response
    /// module. There is no "run arbitrary path" input anywhere in the GUI —
    /// this is the only way scripts get executed, by design.
    pub approved_scripts_folder: Option<PathBuf>,

    /// Root folder the local secrets scanner is allowed to scan. Always a
    /// path on this machine — the scanner has no network/target field.
    pub secrets_scan_root: Option<PathBuf>,

    pub malware_signatures_path: Option<PathBuf>,
    pub malware_scan_root: Option<PathBuf>,
    pub file_organizer_root: Option<PathBuf>,
    pub monitor_interface: Option<String>,
    pub syn_flood_threshold: u32,
    pub port_scan_target: String,
    pub port_scan_authorized: bool,

    /// Optional NVD API key. Public/unauthenticated NVD requests are capped
    /// at 5 per 30s; a free key (https://nvd.nist.gov/developers/request-an-api-key)
    /// raises that to 50 per 30s.
    pub nvd_api_key: Option<String>,

    /// If true, vulnerability matches classified as "low risk" (same major
    /// version, fix available from the OS's own trusted package manager) are
    /// patched automatically. Anything else always waits for you to click Apply.
    pub auto_apply_low_risk_patches: bool,

    #[serde(default)]
    pub tool_integrations: Vec<crate::modules::integrations::ToolIntegration>,

    #[serde(default)]
    pub alert_config: crate::modules::alerts::AlertConfig,

    #[serde(default)]
    pub scheduled_scans: crate::modules::scheduler::ScheduleConfig,

    /// Which compliance controls are checked, as "{framework}|{id}" keys, so
    /// the checklist (and the score the Trends tab plots) survives a restart.
    #[serde(default)]
    pub compliance_checked: Vec<String>,

    /// A folder both this device and others write status files to (a synced
    /// cloud folder or network share). Empty/None disables the Fleet tab's
    /// publish step.
    #[serde(default)]
    pub fleet_folder: Option<PathBuf>,

    /// If set, Scan Reports watches this folder and auto-imports any new
    /// .xml/.nessus/.json/.jsonl file dropped into it (format is
    /// auto-detected). Off (None) by default.
    #[serde(default)]
    pub scan_reports_watch_folder: Option<PathBuf>,

    /// Filenames already auto-imported from the watch folder, so restarting
    /// the app doesn't re-import everything that's already there.
    #[serde(default)]
    pub scan_reports_imported_files: Vec<String>,

    /// "owner/repo" on GitHub to check for newer releases against. Empty
    /// string means unset — nothing is assumed or guessed.
    #[serde(default)]
    pub github_repo: String,

    /// If true, Network Monitor automatically calls Firewall's block-IP
    /// action when it flags a SYN-flood-style source, instead of only
    /// logging/alerting. Off by default — auto-blocking a real IP is a more
    /// consequential action than logging one.
    #[serde(default)]
    pub auto_quarantine: bool,

    /// If true, closing the main window minimizes to the system tray instead
    /// of exiting, so Network Monitor (if running) keeps running in the
    /// background. Off by default so the app behaves like a normal window
    /// until the person opts in.
    #[serde(default)]
    pub minimize_to_tray: bool,

    /// If true, Network Monitor starts automatically on launch using the
    /// last-selected interface, instead of waiting for a manual click.
    #[serde(default)]
    pub start_monitoring_on_launch: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            approved_scripts_folder: None,
            secrets_scan_root: None,
            malware_signatures_path: None,
            malware_scan_root: None,
            file_organizer_root: None,
            monitor_interface: None,
            syn_flood_threshold: 10,
            port_scan_target: "127.0.0.1".to_string(),
            port_scan_authorized: false,
            nvd_api_key: None,
            auto_apply_low_risk_patches: true,
            tool_integrations: Vec::new(),
            alert_config: crate::modules::alerts::AlertConfig::default(),
            scheduled_scans: crate::modules::scheduler::ScheduleConfig::default(),
            compliance_checked: Vec::new(),
            fleet_folder: None,
            scan_reports_watch_folder: None,
            scan_reports_imported_files: Vec::new(),
            github_repo: String::new(),
            auto_quarantine: false,
            minimize_to_tray: false,
            start_monitoring_on_launch: false,
        }
    }
}

fn settings_path() -> PathBuf {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("cyberwarrior");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("settings.json")
}

impl Settings {
    pub fn load() -> Self {
        let path = settings_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let path = settings_path();
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }
}
