use crate::app::CyberWarriorApp;
use crate::modules::{scan_reports, threat_intel};
use eframe::egui;
use std::sync::atomic::Ordering;

impl CyberWarriorApp {
    pub(crate) fn scan_reports_tab(&mut self, ui: &mut egui::Ui) {
        self.poll_scan_reports_watch_folder();

        ui.heading("Scan Reports & Vulnerability Aggregation");
        ui.label(
            "Import result files from tools you already run elsewhere (Nmap/Nessus/OpenVAS/Burp \
             on your Kali/Commando VM, Velociraptor hunts, or another diagnostic agent's JSON \
             export) into one aggregated view. This tab only reads files you point it at — it \
             never launches a scan or attack itself.",
        );
        ui.add_space(8.0);

        ui.horizontal_wrapped(|ui| {
            if ui.button("📥 Import Nmap XML").clicked() {
                self.pick_and_import(|p, log| scan_reports::import_nmap_xml(p, log));
            }
            if ui.button("📥 Import Nessus/OpenVAS XML").clicked() {
                self.pick_and_import(|p, log| scan_reports::import_nessus_xml(p, log));
            }
            if ui.button("📥 Import Burp XML").clicked() {
                self.pick_and_import(|p, log| scan_reports::import_burp_xml(p, log));
            }
            if ui.button("📥 Import Velociraptor export (JSONL)").clicked() {
                self.pick_and_import(|p, log| scan_reports::import_velociraptor_jsonl(p, log));
            }
            if ui.button("📥 Import generic diagnostic JSON").clicked() {
                self.pick_and_import(|p, log| scan_reports::import_generic_json(p, log));
            }
        });
        ui.small(
            "\"Generic diagnostic JSON\" is a best-effort importer for agents (e.g. an Aurora-style \
             endpoint agent) whose export schema isn't one of the formats above — it looks for \
             common field names and keeps the raw JSON either way, so confirm the results look right.",
        );

        if let Some(err) = self.scan_reports.import_error.lock().unwrap().clone() {
            ui.colored_label(egui::Color32::RED, format!("Import failed: {err}"));
        }

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let current = self
                .settings
                .scan_reports_watch_folder
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(not set)".to_string());
            ui.label(format!("Watched folder (auto-import): {current}"));
            if ui.button("Set…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.settings.scan_reports_watch_folder = Some(path);
                    self.settings.save();
                }
            }
            if self.settings.scan_reports_watch_folder.is_some() && ui.button("Clear").clicked() {
                self.settings.scan_reports_watch_folder = None;
                self.settings.save();
            }
        });
        ui.small("Drop a Nmap/.nessus/OpenVAS/Burp XML export, a Velociraptor .jsonl, or a diagnostic .json in there and it's picked up automatically (checked every few seconds) — no need to click Import each time.");

        ui.separator();

        ui.horizontal(|ui| {
            let busy = self.scan_reports.cross_referencing.load(Ordering::Relaxed);
            let can_check = !busy && !self.scan_reports.findings.is_empty();
            if ui
                .add_enabled(can_check, egui::Button::new("🌐 Cross-reference against CISA KEV"))
                .clicked()
            {
                self.scan_reports.cross_referencing.store(true, Ordering::Relaxed);
                let log = self.log.clone();
                let flag = self.scan_reports.cross_referencing.clone();
                let result = self.scan_reports.kev_result.clone();
                std::thread::spawn(move || {
                    let r = threat_intel::fetch_known_exploited_cve_set(&log);
                    *result.lock().unwrap() = Some(r);
                    flag.store(false, Ordering::Relaxed);
                });
            }
            if busy {
                ui.spinner();
            }
            if !self.scan_reports.findings.is_empty() {
                ui.label(format!("{} finding(s) imported", self.scan_reports.findings.len()));
            }
        });
        ui.small(
            "This flags which of your actual detected findings CISA lists as actively exploited \
             right now — it doesn't generate a list of attacks to try. NVD (NIST) is already used \
             for version-level matching in the Vulnerability Scan tab; CISA KEV is the standard \
             reference for \"what's being exploited in the wild today.\"",
        );

        if let Some(kev_result) = self.scan_reports.kev_result.lock().unwrap().clone() {
            match kev_result {
                Ok(kev_cves) => {
                    let flagged = scan_reports::cross_reference_kev(&mut self.scan_reports.findings, &kev_cves);
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 190, 90),
                        format!("{flagged} finding(s) match CISA's actively-exploited list — prioritize these first."),
                    );
                }
                Err(e) => {
                    ui.colored_label(egui::Color32::RED, format!("KEV fetch failed: {e}"));
                }
            }
        }

        ui.separator();

        if self.scan_reports.findings.is_empty() {
            ui.label("No findings imported yet.");
            return;
        }

        // Actively-exploited findings first, then by severity string as a rough tiebreaker.
        let mut findings = self.scan_reports.findings.clone();
        findings.sort_by(|a, b| {
            b.actively_exploited
                .cmp(&a.actively_exploited)
                .then_with(|| a.severity.cmp(&b.severity))
        });

        egui::ScrollArea::vertical().max_height(450.0).id_source("scan_report_findings").show(ui, |ui| {
            for f in &findings {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        if f.actively_exploited {
                            ui.colored_label(egui::Color32::RED, "🔥 ACTIVELY EXPLOITED");
                        }
                        ui.label(egui::RichText::new(&f.name).strong());
                        ui.small(format!("[{}]", f.source));
                    });
                    ui.horizontal(|ui| {
                        ui.label(format!("Host: {}", f.host));
                        ui.label(format!("Severity: {}", f.severity));
                    });
                    if !f.cve_ids.is_empty() {
                        ui.label(format!("CVEs: {}", f.cve_ids.join(", ")));
                    }
                    if !f.detail.is_empty() {
                        egui::CollapsingHeader::new("Detail")
                            .id_source(format!("{}-{}-{}", f.source, f.host, f.name))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(&f.detail).small());
                            });
                    }
                });
            }
        });
    }

    /// Checks the watch folder (if set) at most once every 3 seconds for
    /// files not already imported, and auto-imports any it finds.
    fn poll_scan_reports_watch_folder(&mut self) {
        let Some(folder) = self.settings.scan_reports_watch_folder.clone() else { return };

        let due = match self.scan_reports.last_watch_check {
            Some(t) => t.elapsed() >= std::time::Duration::from_secs(3),
            None => true,
        };
        if !due {
            return;
        }
        self.scan_reports.last_watch_check = Some(std::time::Instant::now());

        let Ok(entries) = std::fs::read_dir(&folder) else { return };
        let mut newly_imported = false;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            if name.is_empty() || self.scan_reports.imported_files.contains(&name) {
                continue;
            }

            match scan_reports::import_auto(&path, &self.log) {
                Ok(mut findings) => {
                    let count = findings.len();
                    self.scan_reports.findings.append(&mut findings);
                    self.log.info("ScanReports", format!("Auto-imported {count} finding(s) from watched file {name}"));
                    newly_imported = true;
                }
                Err(e) => {
                    self.log.warn("ScanReports", format!("Auto-import skipped {name}: {e}"));
                }
            }
            self.scan_reports.imported_files.insert(name);
        }

        if newly_imported {
            self.settings.scan_reports_imported_files = self.scan_reports.imported_files.iter().cloned().collect();
            self.settings.save();
        }
    }

    fn pick_and_import(
        &mut self,
        parse: impl FnOnce(&std::path::Path, &crate::log::SharedLog) -> Result<Vec<scan_reports::Finding>, String>,
    ) {
        *self.scan_reports.import_error.lock().unwrap() = None;
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            match parse(&path, &self.log) {
                Ok(mut new_findings) => {
                    self.scan_reports.findings.append(&mut new_findings);
                }
                Err(e) => {
                    self.log.warn("ScanReports", format!("Import failed: {e}"));
                    *self.scan_reports.import_error.lock().unwrap() = Some(e);
                }
            }
        }
    }
}
