use crate::log::{SharedLog, Severity};
use crate::modules::{
    antivirus, compliance, file_organizer, firewall, history, incident_response, integrations,
    malware_scan, packet_monitor, port_scanner, scan_reports, scheduler, secrets_scanner,
    threat_intel, update_checker, vulnerability_scan,
};
use crate::settings::Settings;
use eframe::egui;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Dashboard,
    NetworkMonitor,
    MalwareScan,
    SecretsScanner,
    Compliance,
    FileOrganizer,
    IncidentResponse,
    PortScanner,
    ThreatIntel,
    VulnScan,
    Firewall,
    Antivirus,
    Integrations,
    ScanReports,
    Reporting,
    Trends,
    Fleet,
    Settings,
}

struct MalwareState {
    root: String,
    signatures_path: String,
    running: Arc<AtomicBool>,
    result: Arc<Mutex<Option<(usize, usize)>>>,
}

struct SecretsState {
    root: String,
    running: Arc<AtomicBool>,
    result: Arc<Mutex<Option<(usize, Vec<(String, String, String)>)>>>,
}

struct OrganizerState {
    root: String,
    dry_run: bool,
    running: Arc<AtomicBool>,
    result: Arc<Mutex<Option<Vec<String>>>>,
}

struct IncidentState {
    scripts: Vec<PathBuf>,
    selected: Option<usize>,
    output: String,
}

struct PortScanState {
    target: String,
    start_port: String,
    end_port: String,
    running: Arc<AtomicBool>,
    result: Arc<Mutex<Option<Result<Vec<u16>, String>>>>,
}

struct ThreatIntelState {
    running: Arc<AtomicBool>,
    result: Arc<Mutex<Option<Result<Vec<String>, String>>>>,
}

struct MonitorState {
    interfaces: Vec<String>,
    // Populated on a background thread (see CyberWarriorApp::default). pnet's
    // Windows backend depends on Npcap being installed, which most machines —
    // including Store certification test rigs — don't have. Enumerating
    // interfaces must never happen on the startup path or it can take the
    // whole app down before a window even appears.
    interfaces_ready: Arc<AtomicBool>,
    interfaces_result: Arc<Mutex<Option<Vec<String>>>>,
    selected_interface: String,
    running: bool,
    stop_flag: Option<Arc<AtomicBool>>,
}

struct VulnState {
    packages: Vec<vulnerability_scan::InstalledPackage>,
    selected: HashSet<usize>,
    filter: String,
    detecting: Arc<AtomicBool>,
    detect_result: Arc<Mutex<Option<Vec<vulnerability_scan::InstalledPackage>>>>,
    scanning: Arc<AtomicBool>,
    scan_result: Arc<Mutex<Option<Vec<vulnerability_scan::VulnMatch>>>>,
    // Keyed by "package:cve_id" -> human-readable status ("Applying…", "Applied", or an error).
    apply_status: Arc<Mutex<HashMap<String, String>>>,
    auto_apply_triggered: HashSet<String>,
    api_key_input: String,
}

pub(crate) struct FirewallState {
    pub(crate) kind: crate::modules::firewall::FirewallKind,
    pub(crate) enabled: Option<bool>,
    pub(crate) raw_status: String,
    pub(crate) block_ip_input: String,
    pub(crate) busy: Arc<AtomicBool>,
    pub(crate) message: Arc<Mutex<Option<Result<String, String>>>>,
}

pub(crate) struct AntivirusState {
    pub(crate) kind: crate::modules::antivirus::AvKind,
    pub(crate) status: Option<crate::modules::antivirus::AvStatus>,
    pub(crate) busy: Arc<AtomicBool>,
    pub(crate) message: Arc<Mutex<Option<Result<String, String>>>>,
}

pub(crate) struct IntegrationsState {
    pub(crate) name_input: String,
    pub(crate) exe_input: String,
    pub(crate) args_input: String,
}

pub(crate) struct ScanReportsState {
    pub(crate) findings: Vec<scan_reports::Finding>,
    pub(crate) import_error: Arc<Mutex<Option<String>>>,
    pub(crate) cross_referencing: Arc<AtomicBool>,
    pub(crate) kev_result: Arc<Mutex<Option<Result<HashSet<String>, String>>>>,
    pub(crate) imported_files: HashSet<String>,
    pub(crate) last_watch_check: Option<std::time::Instant>,
}

pub(crate) struct ReportingState {
    pub(crate) last_result: Option<Result<String, String>>,
}

pub struct CyberWarriorApp {
    pub(crate) log: SharedLog,
    pub(crate) settings: Settings,
    tab: Tab,
    pub(crate) malware: MalwareState,
    pub(crate) secrets: SecretsState,
    pub(crate) organizer: OrganizerState,
    pub(crate) compliance_controls: Vec<compliance::Control>,
    pub(crate) incident: IncidentState,
    pub(crate) portscan: PortScanState,
    pub(crate) threatintel: ThreatIntelState,
    pub(crate) monitor: MonitorState,
    pub(crate) vuln: VulnState,
    pub(crate) firewall: FirewallState,
    pub(crate) antivirus: AntivirusState,
    pub(crate) integrations: IntegrationsState,
    pub(crate) scan_reports: ScanReportsState,
    pub(crate) reporting: ReportingState,
    pub(crate) tray: Option<crate::tray::AppTray>,
    pub(crate) schedule_config: Arc<Mutex<scheduler::ScheduleConfig>>,
    pub(crate) update_check: Arc<Mutex<Option<Result<Option<(String, String)>, String>>>>,
    pub(crate) update_checking: Arc<AtomicBool>,
}

impl Default for CyberWarriorApp {
    fn default() -> Self {
        let settings = Settings::load();
        // Interface enumeration is deferred to a background thread (see
        // below) so a missing/broken Npcap install can never block or crash
        // startup. selected_interface falls back to the saved setting only;
        // once the background scan finishes, update() picks the first
        // interface if the user hadn't already chosen one.
        let interfaces: Vec<String> = Vec::new();
        let interfaces_ready = Arc::new(AtomicBool::new(false));
        let interfaces_result: Arc<Mutex<Option<Vec<String>>>> = Arc::new(Mutex::new(None));
        {
            let ready = interfaces_ready.clone();
            let result = interfaces_result.clone();
            std::thread::spawn(move || {
                // catch_unwind as defense-in-depth: even off the main thread,
                // a panic here should degrade to "no interfaces found"
                // rather than silently killing this thread and leaving the
                // UI waiting forever.
                let found = std::panic::catch_unwind(packet_monitor::list_interface_names)
                    .unwrap_or_default();
                *result.lock().unwrap() = Some(found);
                ready.store(true, Ordering::SeqCst);
            });
        }
        let selected_interface = settings.monitor_interface.clone().unwrap_or_default();

        let incident_scripts = settings
            .approved_scripts_folder
            .as_deref()
            .map(incident_response::list_playbooks)
            .unwrap_or_default();

        let log = SharedLog::new();
        log.set_alert_config(Some(settings.alert_config.clone()));
        let start_monitoring_on_launch = settings.start_monitoring_on_launch && !selected_interface.is_empty();

        let schedule_config = Arc::new(Mutex::new(settings.scheduled_scans.clone()));
        {
            let config = schedule_config.clone();
            let log = log.clone();
            std::thread::spawn(move || scheduler::run_loop(config, log));
        }

        let compliance_checked = settings.compliance_checked.clone();

        let mut app = Self {
            log,
            malware: MalwareState {
                root: settings
                    .malware_scan_root
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                signatures_path: settings
                    .malware_signatures_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                running: Arc::new(AtomicBool::new(false)),
                result: Arc::new(Mutex::new(None)),
            },
            secrets: SecretsState {
                root: settings
                    .secrets_scan_root
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                running: Arc::new(AtomicBool::new(false)),
                result: Arc::new(Mutex::new(None)),
            },
            organizer: OrganizerState {
                root: settings
                    .file_organizer_root
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                dry_run: true,
                running: Arc::new(AtomicBool::new(false)),
                result: Arc::new(Mutex::new(None)),
            },
            compliance_controls: compliance::default_controls(),
            incident: IncidentState {
                scripts: incident_scripts,
                selected: None,
                output: String::new(),
            },
            portscan: PortScanState {
                target: settings.port_scan_target.clone(),
                start_port: "1".to_string(),
                end_port: "1024".to_string(),
                running: Arc::new(AtomicBool::new(false)),
                result: Arc::new(Mutex::new(None)),
            },
            threatintel: ThreatIntelState {
                running: Arc::new(AtomicBool::new(false)),
                result: Arc::new(Mutex::new(None)),
            },
            monitor: MonitorState {
                interfaces,
                interfaces_ready,
                interfaces_result,
                selected_interface,
                running: false,
                stop_flag: None,
            },
            vuln: VulnState {
                packages: Vec::new(),
                selected: HashSet::new(),
                filter: String::new(),
                detecting: Arc::new(AtomicBool::new(false)),
                detect_result: Arc::new(Mutex::new(None)),
                scanning: Arc::new(AtomicBool::new(false)),
                scan_result: Arc::new(Mutex::new(None)),
                apply_status: Arc::new(Mutex::new(HashMap::new())),
                auto_apply_triggered: HashSet::new(),
                api_key_input: settings.nvd_api_key.clone().unwrap_or_default(),
            },
            firewall: FirewallState {
                kind: firewall::detect(),
                enabled: None,
                raw_status: String::new(),
                block_ip_input: String::new(),
                busy: Arc::new(AtomicBool::new(false)),
                message: Arc::new(Mutex::new(None)),
            },
            antivirus: AntivirusState {
                kind: antivirus::detect(),
                status: None,
                busy: Arc::new(AtomicBool::new(false)),
                message: Arc::new(Mutex::new(None)),
            },
            integrations: IntegrationsState {
                name_input: String::new(),
                exe_input: String::new(),
                args_input: String::new(),
            },
            scan_reports: ScanReportsState {
                findings: Vec::new(),
                import_error: Arc::new(Mutex::new(None)),
                cross_referencing: Arc::new(AtomicBool::new(false)),
                kev_result: Arc::new(Mutex::new(None)),
                imported_files: settings.scan_reports_imported_files.iter().cloned().collect(),
                last_watch_check: None,
            },
            reporting: ReportingState { last_result: None },
            tray: None,
            schedule_config,
            update_check: Arc::new(Mutex::new(None)),
            update_checking: Arc::new(AtomicBool::new(false)),
            tab: Tab::Dashboard,
            settings,
        };

        if start_monitoring_on_launch {
            let stop = Arc::new(AtomicBool::new(false));
            app.monitor.stop_flag = Some(stop.clone());
            app.monitor.running = true;
            let iface = app.monitor.selected_interface.clone();
            let threshold = app.settings.syn_flood_threshold;
            let auto_quarantine = app.settings.auto_quarantine;
            let firewall_kind = app.firewall.kind;
            let log = app.log.clone();
            std::thread::spawn(move || {
                packet_monitor::run(iface, threshold, auto_quarantine, firewall_kind, stop, log);
            });
        }

        for control in app.compliance_controls.iter_mut() {
            let key = format!("{}|{}", control.framework, control.id);
            if compliance_checked.contains(&key) {
                control.checked = true;
            }
        }

        let score = compliance::score(&app.compliance_controls);
        history::record_daily_snapshot_if_needed(score, 0, 0, &app.log);

        app
    }
}

impl eframe::App for CyberWarriorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Adopt the background interface scan's result the first time it's
        // ready. Never blocks — if it's not done yet, we just try again next
        // frame (already repainting every 400ms regardless).
        if self.monitor.interfaces_ready.swap(false, Ordering::SeqCst) {
            if let Some(found) = self.monitor.interfaces_result.lock().unwrap().take() {
                if self.monitor.selected_interface.is_empty() {
                    self.monitor.selected_interface = found.first().cloned().unwrap_or_default();
                }
                self.monitor.interfaces = found;
            }
        }

        // Lazily create the tray icon the first time it's needed, since it
        // must be built on the UI thread — and only if the person opted in.
        if self.settings.minimize_to_tray && self.tray.is_none() {
            match crate::tray::load_icon_rgba().and_then(|(rgba, w, h)| crate::tray::AppTray::new(rgba, w, h)) {
                Ok(t) => self.tray = Some(t),
                Err(e) => self.log.warn("Tray", format!("Couldn't create tray icon: {e}")),
            }
        }

        if let Some(tray) = &self.tray {
            if let Some(action) = tray.poll() {
                match action {
                    crate::tray::TrayAction::Show => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                    crate::tray::TrayAction::Quit => std::process::exit(0),
                }
            }
        }

        if self.settings.minimize_to_tray
            && self.tray.is_some()
            && ctx.input(|i| i.viewport().close_requested())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.log.info("Tray", "Minimized to tray — Network Monitor keeps running if it was active");
        }

        egui::SidePanel::left("nav").min_width(190.0).show(ctx, |ui| {
            ui.add_space(8.0);
            ui.vertical_centered(|ui| {
                ui.add(
                    egui::Image::new(egui::include_image!("../assets/icon.png"))
                        .max_width(84.0)
                        .rounding(6.0),
                );
                ui.heading("CyberWarrior");
            });
            ui.label(egui::RichText::new("Defensive security dashboard").weak());
            ui.separator();

            let tabs = [
                (Tab::Dashboard, "🏠 Dashboard / SIEM"),
                (Tab::NetworkMonitor, "📡 Network Monitor"),
                (Tab::MalwareScan, "🛡 Malware Scan"),
                (Tab::SecretsScanner, "🔑 Secrets Scanner"),
                (Tab::Compliance, "📋 Compliance"),
                (Tab::FileOrganizer, "🗂 File Organizer"),
                (Tab::IncidentResponse, "🚨 Incident Response"),
                (Tab::PortScanner, "🔍 Port Scanner"),
                (Tab::ThreatIntel, "🌐 Threat Intel"),
                (Tab::VulnScan, "🩹 Vulnerability Scan"),
                (Tab::Firewall, "🧱 Firewall"),
                (Tab::Antivirus, "🦠 Antivirus"),
                (Tab::Integrations, "🔌 Integrations"),
                (Tab::ScanReports, "📊 Scan Reports"),
                (Tab::Reporting, "🖨 Reporting"),
                (Tab::Trends, "📈 Trends"),
                (Tab::Fleet, "🖧 Fleet"),
                (Tab::Settings, "⚙ Settings"),
            ];
            for (tab, label) in tabs {
                if ui.selectable_label(self.tab == tab, label).clicked() {
                    self.tab = tab;
                }
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Dashboard => self.dashboard_tab(ui),
            Tab::NetworkMonitor => self.network_monitor_tab(ui),
            Tab::MalwareScan => self.malware_tab(ui),
            Tab::SecretsScanner => self.secrets_tab(ui),
            Tab::Compliance => self.compliance_tab(ui),
            Tab::FileOrganizer => self.organizer_tab(ui),
            Tab::IncidentResponse => self.incident_tab(ui),
            Tab::PortScanner => self.portscan_tab(ui),
            Tab::ThreatIntel => self.threatintel_tab(ui),
            Tab::VulnScan => self.vuln_tab(ui),
            Tab::Firewall => self.firewall_tab(ui),
            Tab::Antivirus => self.antivirus_tab(ui),
            Tab::Integrations => self.integrations_tab(ui),
            Tab::ScanReports => self.scan_reports_tab(ui),
            Tab::Reporting => self.reporting_tab(ui),
            Tab::Trends => self.trends_tab(ui),
            Tab::Fleet => self.fleet_tab(ui),
            Tab::Settings => self.settings_tab(ui),
        });

        // Keep polling so background-thread results show up promptly.
        ctx.request_repaint_after(std::time::Duration::from_millis(400));
    }
}

impl CyberWarriorApp {
    fn dashboard_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("SIEM Event Feed");
        ui.label(format!("Log file: {}", self.log.log_file_path().display()));
        ui.separator();
        egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
            for entry in self.log.snapshot().iter().rev().take(500) {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(entry.timestamp.as_str()).weak().small());
                    ui.colored_label(entry.severity.color(), entry.severity.label());
                    ui.label(egui::RichText::new(entry.source.as_str()).strong());
                    ui.label(entry.message.as_str());
                });
            }
        });
    }

    fn network_monitor_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Network Monitor / Lightweight IDS");
        ui.label("Watches a network interface and flags possible SYN-flood patterns.");
        ui.add_space(6.0);

        egui::ComboBox::from_label("Interface")
            .selected_text(self.monitor.selected_interface.as_str())
            .show_ui(ui, |ui| {
                for iface in &self.monitor.interfaces {
                    ui.selectable_value(&mut self.monitor.selected_interface, iface.clone(), iface.as_str());
                }
            });
        if self.monitor.interfaces.is_empty() {
            if cfg!(windows) && !packet_monitor::npcap_available() {
                ui.small("No Npcap runtime detected — install it from https://npcap.com/#download to enable Network Monitor.");
            } else {
                ui.small("Scanning for network interfaces… (requires Npcap on Windows — install it if this stays empty)");
            }
        }
        ui.add(
            egui::Slider::new(&mut self.settings.syn_flood_threshold, 3..=100)
                .text("SYN flood alert threshold (per 10s window)"),
        );
        ui.checkbox(
            &mut self.settings.auto_quarantine,
            "Auto-quarantine: automatically block a flagged source IP via the Firewall",
        );
        if self.settings.auto_quarantine {
            ui.small("⚠ This will call your OS's firewall to block an inbound IP the moment the SYN-flood threshold is hit — no confirmation prompt. Turn off if you'd rather review each one first.");
        }

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if !self.monitor.running {
                if ui.button("▶ Start monitoring").clicked() && !self.monitor.selected_interface.is_empty() {
                    let stop = Arc::new(AtomicBool::new(false));
                    self.monitor.stop_flag = Some(stop.clone());
                    self.monitor.running = true;
                    let iface = self.monitor.selected_interface.clone();
                    let threshold = self.settings.syn_flood_threshold;
                    let auto_quarantine = self.settings.auto_quarantine;
                    let firewall_kind = self.firewall.kind;
                    let log = self.log.clone();
                    std::thread::spawn(move || {
                        packet_monitor::run(iface, threshold, auto_quarantine, firewall_kind, stop, log);
                    });
                }
            } else if ui.button("⏹ Stop monitoring").clicked() {
                if let Some(stop) = &self.monitor.stop_flag {
                    stop.store(true, Ordering::Relaxed);
                }
                self.monitor.running = false;
            }
        });
        if self.monitor.running {
            ui.colored_label(egui::Color32::LIGHT_GREEN, "● Monitoring active — see the Dashboard tab for events");
        }
        ui.small("Note: packet capture typically requires running with elevated/root privileges, and requires libpcap (Linux/macOS) or Npcap (Windows) to be installed.");
    }

    fn malware_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Malware Scan");
        ui.horizontal(|ui| {
            ui.label("Folder to scan:");
            ui.text_edit_singleline(&mut self.malware.root);
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.malware.root = path.display().to_string();
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Signatures file (optional, uses built-in demo list if empty):");
            ui.text_edit_singleline(&mut self.malware.signatures_path);
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.malware.signatures_path = path.display().to_string();
                }
            }
        });

        let running = self.malware.running.load(Ordering::Relaxed);
        if ui.add_enabled(!running && !self.malware.root.is_empty(), egui::Button::new("▶ Run scan")).clicked() {
            self.malware.running.store(true, Ordering::Relaxed);
            *self.malware.result.lock().unwrap() = None;
            let root = PathBuf::from(&self.malware.root);
            let sig_path = if self.malware.signatures_path.is_empty() {
                None
            } else {
                Some(PathBuf::from(&self.malware.signatures_path))
            };
            let log = self.log.clone();
            let running_flag = self.malware.running.clone();
            let result = self.malware.result.clone();
            std::thread::spawn(move || {
                let sigs = malware_scan::load_signatures(sig_path.as_deref());
                let res = malware_scan::scan(&root, &sigs, &log);
                *result.lock().unwrap() = Some(res);
                running_flag.store(false, Ordering::Relaxed);
            });
        }
        if running {
            ui.spinner();
        }
        if let Some((scanned, flagged)) = *self.malware.result.lock().unwrap() {
            ui.add_space(6.0);
            ui.label(format!("Scanned {scanned} file(s), flagged {flagged}. Details in the Dashboard/SIEM feed."));
        }
    }

    fn secrets_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Local Secrets Scanner");
        ui.label("Scans your own files for likely exposed credentials/keys. Local filesystem only — there is no network target field here by design.");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Folder to scan:");
            ui.text_edit_singleline(&mut self.secrets.root);
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.secrets.root = path.display().to_string();
                }
            }
        });

        let running = self.secrets.running.load(Ordering::Relaxed);
        if ui.add_enabled(!running && !self.secrets.root.is_empty(), egui::Button::new("▶ Run scan")).clicked() {
            self.secrets.running.store(true, Ordering::Relaxed);
            *self.secrets.result.lock().unwrap() = None;
            let root = PathBuf::from(&self.secrets.root);
            let log = self.log.clone();
            let running_flag = self.secrets.running.clone();
            let result = self.secrets.result.clone();
            std::thread::spawn(move || {
                let res = secrets_scanner::scan(&root, &log);
                *result.lock().unwrap() = Some(res);
                running_flag.store(false, Ordering::Relaxed);
            });
        }
        if running {
            ui.spinner();
        }
        if let Some((scanned, findings)) = self.secrets.result.lock().unwrap().clone() {
            ui.add_space(6.0);
            ui.label(format!("Scanned {scanned} file(s), {} finding(s):", findings.len()));
            egui::ScrollArea::vertical().max_height(250.0).show(ui, |ui| {
                for (location, kind, snippet) in &findings {
                    ui.label(format!("[{kind}] {location} — {snippet}"));
                }
            });
        }
    }

    fn compliance_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Compliance Checklist");
        let score = compliance::score(&self.compliance_controls);
        ui.label(format!("Overall score: {score:.0}%"));
        ui.add(egui::ProgressBar::new(score / 100.0));
        ui.separator();
        let mut changed = false;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for control in &mut self.compliance_controls {
                if ui
                    .checkbox(
                        &mut control.checked,
                        format!("[{}: {}] {}", control.framework, control.id, control.description),
                    )
                    .changed()
                {
                    changed = true;
                }
            }
        });
        if changed {
            self.settings.compliance_checked = self
                .compliance_controls
                .iter()
                .filter(|c| c.checked)
                .map(|c| format!("{}|{}", c.framework, c.id))
                .collect();
            self.settings.save();
        }
    }

    fn organizer_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("File Organizer / Permissions Audit");
        ui.horizontal(|ui| {
            ui.label("Folder:");
            ui.text_edit_singleline(&mut self.organizer.root);
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.organizer.root = path.display().to_string();
                }
            }
        });
        ui.checkbox(&mut self.organizer.dry_run, "Dry run (list only, don't change permissions)");

        let running = self.organizer.running.load(Ordering::Relaxed);
        if ui.add_enabled(!running && !self.organizer.root.is_empty(), egui::Button::new("▶ Run")).clicked() {
            self.organizer.running.store(true, Ordering::Relaxed);
            *self.organizer.result.lock().unwrap() = None;
            let root = PathBuf::from(&self.organizer.root);
            let dry_run = self.organizer.dry_run;
            let log = self.log.clone();
            let running_flag = self.organizer.running.clone();
            let result = self.organizer.result.clone();
            std::thread::spawn(move || {
                let res = file_organizer::organize(&root, dry_run, &log);
                *result.lock().unwrap() = Some(res);
                running_flag.store(false, Ordering::Relaxed);
            });
        }
        if running {
            ui.spinner();
        }
        if let Some(report) = self.organizer.result.lock().unwrap().clone() {
            ui.add_space(6.0);
            ui.label(format!("{} file(s) processed:", report.len()));
            egui::ScrollArea::vertical().max_height(250.0).show(ui, |ui| {
                for line in &report {
                    ui.small(line.as_str());
                }
            });
        }
    }

    fn incident_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Incident Response Playbooks");
        match &self.settings.approved_scripts_folder {
            None => {
                ui.label("No approved scripts folder set yet — configure one in Settings. Scripts can only be run from that folder.");
            }
            Some(folder) => {
                ui.label(format!("Approved folder: {}", folder.display()));
                if ui.button("↻ Refresh list").clicked() {
                    self.incident.scripts = incident_response::list_playbooks(folder);
                }
                ui.separator();
                for (i, script) in self.incident.scripts.iter().enumerate() {
                    let name = script.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                    if ui.selectable_label(self.incident.selected == Some(i), name).clicked() {
                        self.incident.selected = Some(i);
                    }
                }
                ui.add_space(6.0);
                if let Some(i) = self.incident.selected {
                    if ui.button("▶ Run selected playbook").clicked() {
                        let script = self.incident.scripts[i].clone();
                        match incident_response::run_playbook(folder, &script, &self.log) {
                            Ok(output) => self.incident.output = output,
                            Err(e) => self.incident.output = format!("Error: {e}"),
                        }
                    }
                }
                if !self.incident.output.is_empty() {
                    ui.separator();
                    ui.label("Output:");
                    egui::ScrollArea::vertical().max_height(250.0).show(ui, |ui| {
                        ui.code(self.incident.output.as_str());
                    });
                }
            }
        }
    }

    fn portscan_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Port Scanner (self-check)");
        ui.label("Only scan devices/networks you own or are explicitly authorized to test.");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Target IP:");
            ui.text_edit_singleline(&mut self.portscan.target);
        });
        ui.horizontal(|ui| {
            ui.label("Port range:");
            ui.text_edit_singleline(&mut self.portscan.start_port);
            ui.label("to");
            ui.text_edit_singleline(&mut self.portscan.end_port);
        });
        ui.checkbox(
            &mut self.settings.port_scan_authorized,
            "I confirm I own or am authorized to test this target",
        );

        let running = self.portscan.running.load(Ordering::Relaxed);
        let can_run = !running && self.settings.port_scan_authorized && self.portscan.target.parse::<std::net::IpAddr>().is_ok();
        if ui.add_enabled(can_run, egui::Button::new("▶ Scan")).clicked() {
            let target = self.portscan.target.parse().unwrap();
            let start: u16 = self.portscan.start_port.parse().unwrap_or(1);
            let end: u16 = self.portscan.end_port.parse().unwrap_or(1024);
            self.portscan.running.store(true, Ordering::Relaxed);
            *self.portscan.result.lock().unwrap() = None;
            let authorized = self.settings.port_scan_authorized;
            let log = self.log.clone();
            let running_flag = self.portscan.running.clone();
            let result = self.portscan.result.clone();
            std::thread::spawn(move || {
                let res = port_scanner::scan(target, start, end, authorized, &log);
                *result.lock().unwrap() = Some(res);
                running_flag.store(false, Ordering::Relaxed);
            });
        }
        if running {
            ui.spinner();
        }
        if let Some(res) = self.portscan.result.lock().unwrap().clone() {
            ui.add_space(6.0);
            match res {
                Ok(ports) => ui.label(format!("Open ports: {:?}", ports)),
                Err(e) => ui.colored_label(egui::Color32::RED, e),
            };
        }
    }

    fn threatintel_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Threat Intelligence Feed");
        ui.label("Pulls CISA's Known Exploited Vulnerabilities catalog — real-world CVEs actively being exploited, so you know what to patch.");
        let running = self.threatintel.running.load(Ordering::Relaxed);
        if ui.add_enabled(!running, egui::Button::new("▶ Fetch latest")).clicked() {
            self.threatintel.running.store(true, Ordering::Relaxed);
            *self.threatintel.result.lock().unwrap() = None;
            let log = self.log.clone();
            let running_flag = self.threatintel.running.clone();
            let result = self.threatintel.result.clone();
            std::thread::spawn(move || {
                let res = threat_intel::fetch_known_exploited_vulnerabilities(&log);
                *result.lock().unwrap() = Some(res);
                running_flag.store(false, Ordering::Relaxed);
            });
        }
        if running {
            ui.spinner();
        }
        if let Some(res) = self.threatintel.result.lock().unwrap().clone() {
            match res {
                Ok(items) => {
                    egui::ScrollArea::vertical().max_height(350.0).show(ui, |ui| {
                        for item in &items {
                            ui.label(item.as_str());
                            ui.separator();
                        }
                    });
                }
                Err(e) => {
                    ui.colored_label(egui::Color32::RED, format!("Fetch failed: {e}"));
                }
            }
        }
    }

    fn vuln_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Vulnerability Scan & Patch");
        ui.label("Detects installed software, checks it against known-vulnerability databases, and patches through your OS's own trusted package manager — never a downloaded installer.");
        ui.add_space(6.0);

        let detecting = self.vuln.detecting.load(Ordering::Relaxed);
        if ui.add_enabled(!detecting, egui::Button::new("🔎 Detect installed software")).clicked() {
            self.vuln.detecting.store(true, Ordering::Relaxed);
            *self.vuln.detect_result.lock().unwrap() = None;
            let log = self.log.clone();
            let flag = self.vuln.detecting.clone();
            let result = self.vuln.detect_result.clone();
            std::thread::spawn(move || {
                let pkgs = vulnerability_scan::detect_installed_packages(&log);
                *result.lock().unwrap() = Some(pkgs);
                flag.store(false, Ordering::Relaxed);
            });
        }
        if detecting {
            ui.spinner();
        }
        if let Some(pkgs) = self.vuln.detect_result.lock().unwrap().take() {
            self.vuln.packages = pkgs;
            self.vuln.selected.clear();
        }

        if !self.vuln.packages.is_empty() {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(format!("{} package(s) detected. Filter:", self.vuln.packages.len()));
                ui.text_edit_singleline(&mut self.vuln.filter);
                if ui.button("Select all (filtered)").clicked() {
                    let filter = self.vuln.filter.to_lowercase();
                    for (i, p) in self.vuln.packages.iter().enumerate() {
                        if filter.is_empty() || p.name.to_lowercase().contains(&filter) {
                            self.vuln.selected.insert(i);
                        }
                    }
                }
                if ui.button("Clear selection").clicked() {
                    self.vuln.selected.clear();
                }
            });

            egui::ScrollArea::vertical()
                .max_height(200.0)
                .id_source("vuln_pkg_list")
                .show(ui, |ui| {
                    let filter = self.vuln.filter.to_lowercase();
                    for (i, pkg) in self.vuln.packages.iter().enumerate() {
                        if !filter.is_empty() && !pkg.name.to_lowercase().contains(&filter) {
                            continue;
                        }
                        let mut checked = self.vuln.selected.contains(&i);
                        if ui
                            .checkbox(&mut checked, format!("{} ({})", pkg.name, pkg.version))
                            .changed()
                        {
                            if checked {
                                self.vuln.selected.insert(i);
                            } else {
                                self.vuln.selected.remove(&i);
                            }
                        }
                    }
                });

            ui.add_space(6.0);
            let scanning = self.vuln.scanning.load(Ordering::Relaxed);
            let can_scan = !scanning && !self.vuln.selected.is_empty();
            let scan_label = format!("🩹 Scan {} selected for vulnerabilities", self.vuln.selected.len());
            if ui.add_enabled(can_scan, egui::Button::new(scan_label)).clicked() {
                let selected_packages: Vec<_> = self
                    .vuln
                    .selected
                    .iter()
                    .filter_map(|i| self.vuln.packages.get(*i).cloned())
                    .collect();
                self.vuln.scanning.store(true, Ordering::Relaxed);
                *self.vuln.scan_result.lock().unwrap() = None;
                self.vuln.auto_apply_triggered.clear();
                self.vuln.apply_status.lock().unwrap().clear();
                let log = self.log.clone();
                let flag = self.vuln.scanning.clone();
                let result = self.vuln.scan_result.clone();
                let api_key = self.settings.nvd_api_key.clone();
                std::thread::spawn(move || {
                    let matches = vulnerability_scan::scan(&selected_packages, api_key.as_deref(), &log);
                    *result.lock().unwrap() = Some(matches);
                    flag.store(false, Ordering::Relaxed);
                });
            }
            if scanning {
                ui.spinner();
                ui.label("Scanning — this can take a while due to vulnerability-database rate limits...");
            }
        }

        ui.separator();

        let results = self.vuln.scan_result.lock().unwrap().clone();
        if let Some(matches) = results {
            ui.label(format!("{} finding(s):", matches.len()));
            let pkg_manager = vulnerability_scan::detected_package_manager();

            // Auto-apply low-risk matches once, if the setting is on.
            if self.settings.auto_apply_low_risk_patches {
                for m in &matches {
                    let key = format!("{}:{}", m.package, m.id);
                    if m.risk == vulnerability_scan::Risk::Low && !self.vuln.auto_apply_triggered.contains(&key) {
                        self.vuln.auto_apply_triggered.insert(key.clone());
                        self.vuln.apply_status.lock().unwrap().insert(key.clone(), "Applying…".to_string());
                        let log = self.log.clone();
                        let status = self.vuln.apply_status.clone();
                        let package = m.package.clone();
                        std::thread::spawn(move || {
                            let result = vulnerability_scan::apply_patch(pkg_manager, &package, &log);
                            let msg = match result {
                                Ok(_) => "Applied ✅".to_string(),
                                Err(e) => format!("Failed: {e}"),
                            };
                            status.lock().unwrap().insert(key, msg);
                        });
                    }
                }
            }

            egui::ScrollArea::vertical()
                .max_height(400.0)
                .id_source("vuln_results")
                .show(ui, |ui| {
                    for m in &matches {
                        let key = format!("{}:{}", m.package, m.id);
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(m.id.as_str()).strong());
                                ui.label(format!("({})", m.severity));
                                ui.label(format!("— {} {}", m.package, m.installed_version));
                            });
                            ui.label(egui::RichText::new(m.summary.as_str()).small());
                            match &m.fixed_version {
                                Some(fixed) => {
                                    ui.label(format!("Fixed in: {fixed}"));
                                }
                                None => {
                                    ui.label("Fixed version: unknown — review manually");
                                }
                            }
                            ui.small(format!("Source: {}", m.source));

                            let status = self.vuln.apply_status.lock().unwrap().get(&key).cloned();
                            match (m.risk, status) {
                                (_, Some(s)) => {
                                    ui.colored_label(egui::Color32::LIGHT_GREEN, s);
                                }
                                (vulnerability_scan::Risk::Low, None) => {
                                    ui.label("Low risk — will auto-apply");
                                }
                                (vulnerability_scan::Risk::NeedsReview, None) => {
                                    if ui.button("Apply update").clicked() {
                                        self.vuln
                                            .apply_status
                                            .lock()
                                            .unwrap()
                                            .insert(key.clone(), "Applying…".to_string());
                                        let log = self.log.clone();
                                        let status_map = self.vuln.apply_status.clone();
                                        let package = m.package.clone();
                                        std::thread::spawn(move || {
                                            let result = vulnerability_scan::apply_patch(pkg_manager, &package, &log);
                                            let msg = match result {
                                                Ok(_) => "Applied ✅".to_string(),
                                                Err(e) => format!("Failed: {e}"),
                                            };
                                            status_map.lock().unwrap().insert(key, msg);
                                        });
                                    }
                                }
                            }
                        });
                    }
                });
        }
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.add_space(6.0);

        ui.label("Approved incident-response scripts folder:");
        ui.horizontal(|ui| {
            let current = self
                .settings
                .approved_scripts_folder
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(not set)".to_string());
            ui.label(current);
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.settings.approved_scripts_folder = Some(path.clone());
                    self.incident.scripts = incident_response::list_playbooks(&path);
                }
            }
        });
        ui.small("Only scripts placed directly in this folder can ever be run by Incident Response. There is no way to run a script from elsewhere in the app.");

        ui.add_space(12.0);
        ui.label("NVD API key (optional — raises the vulnerability-lookup rate limit):");
        ui.text_edit_singleline(&mut self.vuln.api_key_input);
        ui.small("Get a free key at https://nvd.nist.gov/developers/request-an-api-key. Leave blank to use the public rate limit.");

        ui.add_space(8.0);
        ui.checkbox(
            &mut self.settings.auto_apply_low_risk_patches,
            "Auto-apply low-risk patches (same major version, fix from your OS's own package manager)",
        );
        ui.small("Anything with a major version bump or an unclear fixed version always waits for you to click Apply.");

        ui.add_space(16.0);
        ui.separator();
        ui.heading("Updates");
        ui.horizontal(|ui| {
            ui.label("GitHub repo (owner/name):");
            ui.text_edit_singleline(&mut self.settings.github_repo);
        });
        ui.horizontal(|ui| {
            let busy = self.update_checking.load(Ordering::Relaxed);
            let can_check = !busy && !self.settings.github_repo.trim().is_empty();
            if ui.add_enabled(can_check, egui::Button::new("🔍 Check for updates")).clicked() {
                self.settings.save();
                self.update_checking.store(true, Ordering::Relaxed);
                let repo = self.settings.github_repo.clone();
                let current_version = env!("CARGO_PKG_VERSION").to_string();
                let log = self.log.clone();
                let result = self.update_check.clone();
                let flag = self.update_checking.clone();
                std::thread::spawn(move || {
                    let r = update_checker::check_for_update(&repo, &current_version, &log);
                    *result.lock().unwrap() = Some(r);
                    flag.store(false, Ordering::Relaxed);
                });
            }
            if busy {
                ui.spinner();
            }
        });
        if let Some(result) = self.update_check.lock().unwrap().clone() {
            match result {
                Ok(Some((version, url))) => {
                    ui.colored_label(egui::Color32::from_rgb(255, 190, 90), format!("Update available: v{version}"));
                    ui.hyperlink_to("View release", url);
                }
                Ok(None) => {
                    ui.colored_label(egui::Color32::LIGHT_GREEN, "You're on the latest version.");
                }
                Err(e) => {
                    ui.colored_label(egui::Color32::RED, format!("Check failed: {e}"));
                }
            }
        }
        ui.small("Set this once your build is actually published to a GitHub repo with releases — there's no default to guess at.");

        ui.add_space(16.0);
        ui.separator();
        ui.heading("Scheduled scans");
        ui.label("Runs the same scan a manual click would — only while the app is open, and only if a target folder/setting for it is already configured below.");

        ui.checkbox(&mut self.settings.scheduled_scans.malware_scan_enabled, "Scheduled Malware Scan");
        if self.settings.scheduled_scans.malware_scan_enabled {
            ui.add(egui::Slider::new(&mut self.settings.scheduled_scans.malware_scan_interval_hours, 1..=168).text("hours between runs"));
        }
        ui.checkbox(&mut self.settings.scheduled_scans.secrets_scan_enabled, "Scheduled Secrets Scan");
        if self.settings.scheduled_scans.secrets_scan_enabled {
            ui.add(egui::Slider::new(&mut self.settings.scheduled_scans.secrets_scan_interval_hours, 1..=168).text("hours between runs"));
        }
        ui.checkbox(&mut self.settings.scheduled_scans.vuln_scan_enabled, "Scheduled Vulnerability Scan");
        if self.settings.scheduled_scans.vuln_scan_enabled {
            ui.add(egui::Slider::new(&mut self.settings.scheduled_scans.vuln_scan_interval_hours, 1..=168).text("hours between runs"));
        }
        ui.small("Uses the folders/API key set in Malware Scan, Secrets Scanner, and Vulnerability Scan's own tabs — set those first, then Save here.");

        ui.add_space(16.0);
        ui.separator();
        ui.heading("Continuous / background mode");
        ui.checkbox(
            &mut self.settings.minimize_to_tray,
            "Minimize to system tray on close (keeps Network Monitor running in the background)",
        );
        ui.checkbox(
            &mut self.settings.start_monitoring_on_launch,
            "Start Network Monitor automatically when the app launches",
        );
        ui.small("Tray behavior is the newest, least-tested part of this app — confirm it actually appears in your OS's tray after the next build before relying on it.");

        ui.add_space(16.0);
        ui.separator();
        ui.heading("Alert delivery (email / webhook)");
        ui.label("Off by default. When on, any Alert-severity event (intrusions, actively-exploited findings, etc.) is also sent out, in addition to the local SIEM log.");

        ui.add_space(6.0);
        ui.checkbox(&mut self.settings.alert_config.email_enabled, "Send email alerts");
        if self.settings.alert_config.email_enabled {
            egui::Grid::new("email_alert_grid").num_columns(2).show(ui, |ui| {
                ui.label("SMTP server:");
                ui.text_edit_singleline(&mut self.settings.alert_config.smtp_server);
                ui.end_row();
                ui.label("SMTP port:");
                let mut port_str = self.settings.alert_config.smtp_port.to_string();
                if ui.text_edit_singleline(&mut port_str).changed() {
                    self.settings.alert_config.smtp_port = port_str.parse().unwrap_or(587);
                }
                ui.end_row();
                ui.label("Username:");
                ui.text_edit_singleline(&mut self.settings.alert_config.smtp_username);
                ui.end_row();
                ui.label("Password / app password:");
                ui.add(egui::TextEdit::singleline(&mut self.settings.alert_config.smtp_password).password(true));
                ui.end_row();
                ui.label("From address:");
                ui.text_edit_singleline(&mut self.settings.alert_config.email_from);
                ui.end_row();
                ui.label("To address:");
                ui.text_edit_singleline(&mut self.settings.alert_config.email_to);
                ui.end_row();
            });
            ui.small("The password is stored in plain text in this machine's local settings.json — use an app-specific password, not your main account password.");
        }

        ui.add_space(8.0);
        ui.checkbox(&mut self.settings.alert_config.webhook_enabled, "Send webhook alerts (Slack/Discord/Teams-compatible JSON POST)");
        if self.settings.alert_config.webhook_enabled {
            ui.horizontal(|ui| {
                ui.label("Webhook URL:");
                ui.text_edit_singleline(&mut self.settings.alert_config.webhook_url);
            });
        }

        ui.add_space(12.0);
        if ui.button("💾 Save settings").clicked() {
            self.settings.monitor_interface = Some(self.monitor.selected_interface.clone());
            self.settings.malware_scan_root = if self.malware.root.is_empty() { None } else { Some(PathBuf::from(&self.malware.root)) };
            self.settings.malware_signatures_path = if self.malware.signatures_path.is_empty() { None } else { Some(PathBuf::from(&self.malware.signatures_path)) };
            self.settings.secrets_scan_root = if self.secrets.root.is_empty() { None } else { Some(PathBuf::from(&self.secrets.root)) };
            self.settings.file_organizer_root = if self.organizer.root.is_empty() { None } else { Some(PathBuf::from(&self.organizer.root)) };
            self.settings.port_scan_target = self.portscan.target.clone();
            self.settings.nvd_api_key = if self.vuln.api_key_input.is_empty() { None } else { Some(self.vuln.api_key_input.clone()) };

            self.settings.scheduled_scans.malware_root = self.settings.malware_scan_root.clone();
            self.settings.scheduled_scans.malware_signatures_path = self.settings.malware_signatures_path.clone();
            self.settings.scheduled_scans.secrets_root = self.settings.secrets_scan_root.clone();
            self.settings.scheduled_scans.nvd_api_key = self.settings.nvd_api_key.clone();

            self.settings.save();
            self.log.set_alert_config(Some(self.settings.alert_config.clone()));
            *self.schedule_config.lock().unwrap() = self.settings.scheduled_scans.clone();
            self.log.info("Settings", "Settings saved");
        }
    }
}
