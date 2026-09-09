use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

pub enum TrayAction {
    Show,
    Quit,
}

/// Holds the live tray icon + its menu item IDs. Must stay alive for as long
/// as the tray icon should be visible — dropping it removes the icon.
pub struct AppTray {
    _tray: TrayIcon,
    show_id: MenuId,
    quit_id: MenuId,
}

impl AppTray {
    pub fn new(rgba: Vec<u8>, width: u32, height: u32) -> Result<Self, String> {
        let icon = Icon::from_rgba(rgba, width, height).map_err(|e| e.to_string())?;

        let menu = Menu::new();
        let show_item = MenuItem::new("Show CyberWarrior", true, None);
        let quit_item = MenuItem::new("Quit", true, None);
        menu.append(&show_item).map_err(|e| e.to_string())?;
        menu.append(&quit_item).map_err(|e| e.to_string())?;

        let show_id = show_item.id().clone();
        let quit_id = quit_item.id().clone();

        let tray = TrayIconBuilder::new()
            .with_icon(icon)
            .with_menu(Box::new(menu))
            .with_tooltip("CyberWarrior — running in the background")
            .build()
            .map_err(|e| e.to_string())?;

        Ok(Self { _tray: tray, show_id, quit_id })
    }

    /// Non-blocking check for a menu click this frame.
    pub fn poll(&self) -> Option<TrayAction> {
        if let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == self.show_id {
                return Some(TrayAction::Show);
            } else if event.id == self.quit_id {
                return Some(TrayAction::Quit);
            }
        }
        None
    }
}

/// Decodes the embedded logo once, for both the window icon and the tray icon.
pub fn load_icon_rgba() -> Result<(Vec<u8>, u32, u32), String> {
    let bytes = include_bytes!("../assets/icon.png");
    let img = image::load_from_memory(bytes).map_err(|e| e.to_string())?.into_rgba8();
    let (width, height) = img.dimensions();
    Ok((img.into_raw(), width, height))
}
