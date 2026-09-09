use crate::app::CyberWarriorApp;
use crate::modules::{compliance, fleet};
use eframe::egui;

impl CyberWarriorApp {
    pub(crate) fn fleet_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Fleet");
        ui.label(
            "A lightweight way to see status across a few machines: point every instance at the \
             same shared folder (a synced Dropbox/OneDrive folder, or a network share you already \
             have access to). Each one writes its own status file there and reads everyone else's \
             — no server, no accounts.",
        );
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let current = self
                .settings
                .fleet_folder
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(not set)".to_string());
            ui.label(format!("Shared folder: {current}"));
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.settings.fleet_folder = Some(path);
                    self.settings.save();
                }
            }
        });
        ui.small("This is only as private as the folder itself — don't point it at anything you wouldn't otherwise share.");

        ui.add_space(10.0);

        let can_publish = self.settings.fleet_folder.is_some();
        ui.horizontal(|ui| {
            if ui.add_enabled(can_publish, egui::Button::new("📤 Publish my status now")).clicked() {
                if let Some(folder) = self.settings.fleet_folder.clone() {
                    let score = compliance::score(&self.compliance_controls);
                    let status = fleet::DeviceStatus {
                        hostname: fleet::current_hostname(),
                        timestamp: chrono::Local::now().to_rfc3339(),
                        compliance_score: score,
                        findings_total: self.scan_reports.findings.len(),
                        findings_actively_exploited: self.scan_reports.findings.iter().filter(|f| f.actively_exploited).count(),
                        firewall_enabled: self.firewall.enabled,
                        antivirus_summary: self
                            .antivirus
                            .status
                            .as_ref()
                            .map(|s| match s.enabled {
                                Some(true) => "Enabled".to_string(),
                                Some(false) => "Disabled".to_string(),
                                None => "Unknown".to_string(),
                            })
                            .unwrap_or_else(|| "Not checked".to_string()),
                    };
                    match fleet::publish_status(&folder, &status) {
                        Ok(_) => self.log.info("Fleet", "Published status"),
                        Err(e) => self.log.warn("Fleet", format!("Publish failed: {e}")),
                    }
                }
            }
            if ui.add_enabled(can_publish, egui::Button::new("🔄 Refresh")).clicked() {
                // Nothing to do here beyond letting the table below re-read on this frame.
            }
        });

        ui.add_space(12.0);
        ui.separator();

        let Some(folder) = self.settings.fleet_folder.clone() else {
            ui.label("Set a shared folder above to see devices here.");
            return;
        };

        let devices = fleet::load_fleet_status(&folder);
        if devices.is_empty() {
            ui.label("No devices have published to this folder yet.");
            return;
        }

        egui::Grid::new("fleet_grid").striped(true).num_columns(6).show(ui, |ui| {
            ui.strong("Host");
            ui.strong("Last seen");
            ui.strong("Compliance");
            ui.strong("Findings");
            ui.strong("Exploited");
            ui.strong("Firewall");
            ui.end_row();

            for d in &devices {
                ui.label(&d.hostname);
                ui.label(&d.timestamp);
                ui.label(format!("{:.0}%", d.compliance_score));
                ui.label(d.findings_total.to_string());
                if d.findings_actively_exploited > 0 {
                    ui.colored_label(egui::Color32::from_rgb(255, 90, 90), d.findings_actively_exploited.to_string());
                } else {
                    ui.label("0");
                }
                ui.label(match d.firewall_enabled {
                    Some(true) => "On",
                    Some(false) => "Off",
                    None => "Unknown",
                });
                ui.end_row();
            }
        });
    }
}
