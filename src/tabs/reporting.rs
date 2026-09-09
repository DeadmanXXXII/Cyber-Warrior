use crate::app::CyberWarriorApp;
use crate::modules::reporting;
use eframe::egui;

impl CyberWarriorApp {
    pub(crate) fn reporting_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Reporting");
        ui.label("Export what's currently loaded in Scan Reports and Compliance to a file you can hand to someone else or keep for records.");
        ui.add_space(8.0);

        ui.label(format!("Findings available to export: {}", self.scan_reports.findings.len()));
        ui.label(format!("Compliance controls available to export: {}", self.compliance_controls.len()));
        ui.add_space(8.0);

        ui.horizontal_wrapped(|ui| {
            if ui.button("📄 Export findings (CSV)").clicked() {
                if let Some(path) = rfd::FileDialog::new().set_file_name("cyberwarrior_findings.csv").save_file() {
                    let result = reporting::export_findings_csv(&self.scan_reports.findings, &path)
                        .map(|_| format!("Saved to {}", path.display()));
                    self.reporting.last_result = Some(result);
                }
            }
            if ui.button("📄 Export compliance (CSV)").clicked() {
                if let Some(path) = rfd::FileDialog::new().set_file_name("cyberwarrior_compliance.csv").save_file() {
                    let result = reporting::export_compliance_csv(&self.compliance_controls, &path)
                        .map(|_| format!("Saved to {}", path.display()));
                    self.reporting.last_result = Some(result);
                }
            }
            if ui.button("🖨 Export summary report (PDF)").clicked() {
                if let Some(path) = rfd::FileDialog::new().set_file_name("cyberwarrior_report.pdf").save_file() {
                    let result = reporting::export_summary_pdf(&self.scan_reports.findings, &self.compliance_controls, &path)
                        .map(|_| format!("Saved to {}", path.display()));
                    self.reporting.last_result = Some(result);
                }
            }
        });

        if let Some(result) = &self.reporting.last_result {
            ui.add_space(8.0);
            match result {
                Ok(msg) => {
                    ui.colored_label(egui::Color32::LIGHT_GREEN, msg.as_str());
                }
                Err(e) => {
                    ui.colored_label(egui::Color32::RED, format!("Export failed: {e}"));
                }
            }
        }
    }
}
