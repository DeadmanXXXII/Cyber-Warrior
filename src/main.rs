// Suppresses the console window on Windows release builds — GUI apps
// shouldn't pop a terminal behind them. Debug builds keep it so println!
// debugging still works.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod log;
mod modules;
mod settings;
mod tabs;
mod theme;
mod tray;

use app::CyberWarriorApp;

fn main() -> eframe::Result<()> {
    let icon = tray::load_icon_rgba().ok().map(|(rgba, width, height)| {
        std::sync::Arc::new(eframe::egui::IconData { rgba, width, height })
    });

    let mut viewport = eframe::egui::ViewportBuilder::default().with_inner_size([1000.0, 700.0]);
    if let Some(icon) = icon {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "CyberWarrior — Incident Response",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(theme::cyberwarrior_visuals());
            egui_extras::install_image_loaders(&cc.egui_ctx);
            Box::new(CyberWarriorApp::default())
        }),
    )
}
