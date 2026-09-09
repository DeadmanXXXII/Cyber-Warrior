use crate::app::CyberWarriorApp;
use crate::modules::integrations::{self, ToolIntegration};
use eframe::egui;

impl CyberWarriorApp {
    pub(crate) fn integrations_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Tool Integrations");
        ui.label(
            "Register tools you already have installed (Snort, Burp Suite CLI, etc.) once here, \
             then launch them with one click. There's no free-text \"run this path\" field \
             anywhere else in the app — this registration step is the only way an executable \
             gets tied to a button.",
        );
        ui.add_space(8.0);

        ui.label("Register a new tool:");
        ui.horizontal(|ui| {
            ui.label("Name:");
            ui.text_edit_singleline(&mut self.integrations.name_input);
        });
        ui.horizontal(|ui| {
            ui.label("Executable:");
            ui.text_edit_singleline(&mut self.integrations.exe_input);
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.integrations.exe_input = path.display().to_string();
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Arguments (optional):");
            ui.text_edit_singleline(&mut self.integrations.args_input);
        });

        let can_add = !self.integrations.name_input.is_empty() && !self.integrations.exe_input.is_empty();
        if ui.add_enabled(can_add, egui::Button::new("➕ Register tool")).clicked() {
            let tool = ToolIntegration {
                name: self.integrations.name_input.clone(),
                executable: std::path::PathBuf::from(&self.integrations.exe_input),
                args: self.integrations.args_input.clone(),
            };
            self.settings.tool_integrations.push(tool);
            self.settings.save();
            self.integrations.name_input.clear();
            self.integrations.exe_input.clear();
            self.integrations.args_input.clear();
        }

        ui.separator();
        ui.label("Registered tools:");

        let mut remove_index: Option<usize> = None;
        for (i, tool) in self.settings.tool_integrations.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(tool.name.as_str()).strong());
                ui.small(tool.executable.display().to_string());
                if ui.button("▶ Launch").clicked() {
                    let _ = integrations::launch(tool, &self.log);
                }
                if ui.button("🗑").clicked() {
                    remove_index = Some(i);
                }
            });
        }
        if let Some(i) = remove_index {
            self.settings.tool_integrations.remove(i);
            self.settings.save();
        }
    }
}
