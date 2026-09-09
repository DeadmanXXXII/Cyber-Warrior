use crate::app::CyberWarriorApp;
use crate::modules::antivirus;
use eframe::egui;
use std::sync::atomic::Ordering;

impl CyberWarriorApp {
    pub(crate) fn antivirus_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Antivirus");
        ui.label(format!("Detected: {:?}", self.antivirus.kind));
        ui.add_space(6.0);

        if self.antivirus.kind == antivirus::AvKind::NotDetected {
            ui.colored_label(egui::Color32::YELLOW, "No antivirus detected on this system.");
            ui.label("Recommended free option: ClamAV (open-source, no license cost).");
            let busy = self.antivirus.busy.load(Ordering::Relaxed);
            if ui.add_enabled(!busy, egui::Button::new("Install ClamAV")).clicked() {
                self.antivirus.busy.store(true, Ordering::Relaxed);
                *self.antivirus.message.lock().unwrap() = None;
                let log = self.log.clone();
                let busy_flag = self.antivirus.busy.clone();
                let message = self.antivirus.message.clone();
                std::thread::spawn(move || {
                    let result = antivirus::install_clamav(&log);
                    *message.lock().unwrap() = Some(result);
                    busy_flag.store(false, Ordering::Relaxed);
                });
            }
            ui.add_space(6.0);
        }

        if ui.button("🔄 Refresh status").clicked() {
            self.antivirus.status = Some(antivirus::status(self.antivirus.kind, &self.log));
        }

        if let Some(status) = self.antivirus.status.clone() {
            ui.horizontal(|ui| {
                match status.enabled {
                    Some(true) => {
                        ui.colored_label(egui::Color32::LIGHT_GREEN, "Enabled");
                    }
                    Some(false) => {
                        ui.colored_label(egui::Color32::RED, "Disabled");
                    }
                    None => {
                        ui.label("Enabled: unknown");
                    }
                };
                match status.real_time_protection {
                    Some(true) => {
                        ui.colored_label(egui::Color32::LIGHT_GREEN, "Real-time protection ON");
                    }
                    Some(false) => {
                        ui.colored_label(egui::Color32::YELLOW, "Real-time protection OFF");
                    }
                    None => {}
                };
            });
        }

        ui.add_space(6.0);
        let busy = self.antivirus.busy.load(Ordering::Relaxed);
        ui.horizontal(|ui| {
            if ui.add_enabled(!busy, egui::Button::new("▶ Quick scan")).clicked() {
                self.antivirus.busy.store(true, Ordering::Relaxed);
                *self.antivirus.message.lock().unwrap() = None;
                let kind = self.antivirus.kind;
                let log = self.log.clone();
                let busy_flag = self.antivirus.busy.clone();
                let message = self.antivirus.message.clone();
                std::thread::spawn(move || {
                    let result = antivirus::quick_scan(kind, None, &log);
                    *message.lock().unwrap() = Some(result);
                    busy_flag.store(false, Ordering::Relaxed);
                });
            }
            if ui.add_enabled(!busy, egui::Button::new("⬇ Update definitions")).clicked() {
                self.antivirus.busy.store(true, Ordering::Relaxed);
                *self.antivirus.message.lock().unwrap() = None;
                let kind = self.antivirus.kind;
                let log = self.log.clone();
                let busy_flag = self.antivirus.busy.clone();
                let message = self.antivirus.message.clone();
                std::thread::spawn(move || {
                    let result = antivirus::update_definitions(kind, &log);
                    *message.lock().unwrap() = Some(result);
                    busy_flag.store(false, Ordering::Relaxed);
                });
            }
        });
        if busy {
            ui.spinner();
        }

        if let Some(result) = self.antivirus.message.lock().unwrap().clone() {
            match result {
                Ok(text) => {
                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .id_source("av_output")
                        .show(ui, |ui| {
                            ui.code(text.as_str());
                        });
                }
                Err(e) => {
                    ui.colored_label(egui::Color32::RED, format!("Failed: {e}"));
                }
            };
        }
    }
}
