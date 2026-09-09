use crate::app::CyberWarriorApp;
use crate::modules::{compliance, history};
use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};

impl CyberWarriorApp {
    pub(crate) fn trends_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Trends");
        ui.label("One point per day, recorded automatically while the app is open — not a substitute for scheduled scans, just a record of where things stood each day.");
        ui.add_space(8.0);

        if ui.button("📌 Record a snapshot now").clicked() {
            let score = compliance::score(&self.compliance_controls);
            let total = self.scan_reports.findings.len();
            let exploited = self.scan_reports.findings.iter().filter(|f| f.actively_exploited).count();
            history::append_snapshot(
                &history::Snapshot {
                    timestamp: chrono::Local::now().to_rfc3339(),
                    compliance_score: score,
                    findings_total: total,
                    findings_actively_exploited: exploited,
                },
                &self.log,
            );
        }

        let hist = history::load_history();
        if hist.is_empty() {
            ui.label("No history yet — it builds up automatically, or click above to add today's point now.");
            return;
        }

        ui.add_space(8.0);
        ui.label(format!("{} snapshot(s) recorded", hist.len()));

        let score_points: PlotPoints = hist
            .iter()
            .enumerate()
            .map(|(i, s)| [i as f64, s.compliance_score as f64])
            .collect();
        ui.label("Compliance score (%)");
        Plot::new("compliance_trend")
            .height(180.0)
            .include_y(0.0)
            .include_y(100.0)
            .show(ui, |plot_ui| {
                plot_ui.line(Line::new(score_points).name("Compliance score"));
            });

        ui.add_space(12.0);
        let total_points: PlotPoints = hist
            .iter()
            .enumerate()
            .map(|(i, s)| [i as f64, s.findings_total as f64])
            .collect();
        let exploited_points: PlotPoints = hist
            .iter()
            .enumerate()
            .map(|(i, s)| [i as f64, s.findings_actively_exploited as f64])
            .collect();
        ui.label("Findings (total vs. actively-exploited)");
        Plot::new("findings_trend").height(180.0).include_y(0.0).show(ui, |plot_ui| {
            plot_ui.line(Line::new(total_points).name("Total findings"));
            plot_ui.line(Line::new(exploited_points).name("Actively exploited"));
        });
    }
}
