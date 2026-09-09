use eframe::egui::{self, Color32, Rounding, Stroke};

/// Dark gunmetal + molten-orange theme matching the CyberWarrior logo
/// (weathered steel helmet, orange visor glow, rust-orange gear ring).
pub fn cyberwarrior_visuals() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();

    let bg = Color32::from_rgb(18, 18, 20);
    let panel = Color32::from_rgb(26, 26, 29);
    let widget_bg = Color32::from_rgb(35, 35, 39);
    let accent = Color32::from_rgb(230, 106, 26); // molten orange, from the visor/gear
    let accent_dim = Color32::from_rgb(150, 70, 20);

    visuals.override_text_color = Some(Color32::from_rgb(225, 222, 216));
    visuals.window_fill = panel;
    visuals.panel_fill = bg;
    visuals.faint_bg_color = widget_bg;
    visuals.extreme_bg_color = Color32::from_rgb(12, 12, 13);

    visuals.widgets.noninteractive.bg_fill = panel;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(200, 197, 190));

    visuals.widgets.inactive.bg_fill = widget_bg;
    visuals.widgets.inactive.weak_bg_fill = widget_bg;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(210, 207, 200));

    visuals.widgets.hovered.bg_fill = accent_dim;
    visuals.widgets.hovered.weak_bg_fill = accent_dim;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.2_f32, Color32::WHITE);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, accent);

    visuals.widgets.active.bg_fill = accent;
    visuals.widgets.active.weak_bg_fill = accent;
    visuals.widgets.active.fg_stroke = Stroke::new(1.2_f32, Color32::from_rgb(20, 15, 10));
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, accent);

    visuals.selection.bg_fill = accent_dim;
    visuals.selection.stroke = Stroke::new(1.0_f32, accent);

    visuals.hyperlink_color = accent;
    visuals.warn_fg_color = Color32::from_rgb(255, 190, 90);
    visuals.error_fg_color = Color32::from_rgb(230, 70, 60);

    let rounding = Rounding::same(4.0);
    visuals.window_rounding = rounding;
    visuals.menu_rounding = rounding;
    visuals.widgets.noninteractive.rounding = rounding;
    visuals.widgets.inactive.rounding = rounding;
    visuals.widgets.hovered.rounding = rounding;
    visuals.widgets.active.rounding = rounding;

    visuals
}
