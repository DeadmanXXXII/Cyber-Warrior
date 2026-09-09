use crate::app::CyberWarriorApp;
use crate::modules::firewall;
use eframe::egui;
use std::sync::atomic::Ordering;

impl CyberWarriorApp {
    pub(crate) fn firewall_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Firewall");
        ui.label(format!("Detected backend: {:?}", self.firewall.kind));
        ui.add_space(6.0);

        if ui.button("🔄 Refresh status").clicked() {
            let (enabled, raw) = firewall::status(self.firewall.kind, &self.log);
            self.firewall.enabled = enabled;
            self.firewall.raw_status = raw;
        }

        match self.firewall.enabled {
            Some(true) => {
                ui.colored_label(egui::Color32::LIGHT_GREEN, "● Firewall is ON");
            }
            Some(false) => {
                ui.colored_label(egui::Color32::RED, "● Firewall is OFF");
            }
            None => {
                ui.label("Status unknown — click Refresh");
            }
        };

        let busy = self.firewall.busy.load(Ordering::Relaxed);
        ui.horizontal(|ui| {
            if ui.add_enabled(!busy, egui::Button::new("Turn ON")).clicked() {
                self.run_firewall_toggle(true);
            }
            if ui.add_enabled(!busy, egui::Button::new("Turn OFF")).clicked() {
                self.run_firewall_toggle(false);
            }
        });
        if busy {
            ui.spinner();
        }

        if !self.firewall.raw_status.is_empty() {
            ui.add_space(6.0);
            egui::CollapsingHeader::new("Raw status output").show(ui, |ui| {
                ui.code(self.firewall.raw_status.as_str());
            });
        }

        ui.separator();
        ui.label("Block an IP address (adds an inbound deny rule):");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.firewall.block_ip_input);
            let ip_valid = self.firewall.block_ip_input.parse::<std::net::IpAddr>().is_ok();
            if ui.add_enabled(!busy && ip_valid, egui::Button::new("🚫 Block")).clicked() {
                let ip = self.firewall.block_ip_input.clone();
                self.firewall.busy.store(true, Ordering::Relaxed);
                *self.firewall.message.lock().unwrap() = None;
                let kind = self.firewall.kind;
                let log = self.log.clone();
                let busy_flag = self.firewall.busy.clone();
                let message = self.firewall.message.clone();
                std::thread::spawn(move || {
                    let result = firewall::block_ip(kind, &ip, &log);
                    *message.lock().unwrap() = Some(result);
                    busy_flag.store(false, Ordering::Relaxed);
                });
            }
        });

        if let Some(result) = self.firewall.message.lock().unwrap().clone() {
            match result {
                Ok(_) => {
                    ui.colored_label(egui::Color32::LIGHT_GREEN, "Action completed");
                }
                Err(e) => {
                    ui.colored_label(egui::Color32::RED, format!("Failed: {e}"));
                }
            };
        }
    }

    fn run_firewall_toggle(&mut self, enable: bool) {
        self.firewall.busy.store(true, Ordering::Relaxed);
        *self.firewall.message.lock().unwrap() = None;
        let kind = self.firewall.kind;
        let log = self.log.clone();
        let busy_flag = self.firewall.busy.clone();
        let message = self.firewall.message.clone();
        std::thread::spawn(move || {
            let result = firewall::set_enabled(kind, enable, &log);
            *message.lock().unwrap() = Some(result);
            busy_flag.store(false, Ordering::Relaxed);
        });
    }
}
