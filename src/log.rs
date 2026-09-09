use crate::modules::alerts::{self, AlertConfig};
use chrono::Local;
use eframe::egui;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Info,
    Warning,
    Alert,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Alert => "ALERT",
        }
    }

    pub fn color(&self) -> egui::Color32 {
        match self {
            Severity::Info => egui::Color32::from_rgb(150, 200, 255),
            Severity::Warning => egui::Color32::from_rgb(255, 190, 90),
            Severity::Alert => egui::Color32::from_rgb(255, 90, 90),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub timestamp: String,
    pub source: String,
    pub severity: Severity,
    pub message: String,
}

/// Central, thread-safe event log shared by every module. Every module writes
/// here instead of println!, so the GUI's SIEM tab shows one unified feed
/// (this is the direct successor of the original "Prophet" module).
#[derive(Clone)]
pub struct SharedLog {
    entries: Arc<Mutex<Vec<LogEntry>>>,
    log_file_path: std::path::PathBuf,
    alert_config: Arc<Mutex<Option<AlertConfig>>>,
}

impl SharedLog {
    pub fn new() -> Self {
        let dir = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("cyberwarrior");
        let _ = std::fs::create_dir_all(&dir);
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            log_file_path: dir.join("siem.log"),
            alert_config: Arc::new(Mutex::new(None)),
        }
    }

    /// Sets (or clears, with `None`) the alert-delivery config used for
    /// Alert-severity log entries. Called whenever Settings are loaded/saved
    /// so this always reflects the current configuration.
    pub fn set_alert_config(&self, config: Option<AlertConfig>) {
        *self.alert_config.lock().unwrap() = config;
    }

    pub fn push(&self, source: &str, severity: Severity, message: impl Into<String>) {
        let message = message.into();
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let entry = LogEntry {
            timestamp: timestamp.clone(),
            source: source.to_string(),
            severity,
            message: message.clone(),
        };

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file_path)
        {
            let _ = writeln!(
                file,
                "[{}] [{}] [{}] {}",
                timestamp,
                severity.label(),
                source,
                message
            );
        }

        if let Ok(mut entries) = self.entries.lock() {
            entries.push(entry);
            // Cap in-memory history so long-running monitors don't grow unbounded.
            let len = entries.len();
            if len > 5000 {
                entries.drain(0..len - 5000);
            }
        }

        // Fire configured alert channels (email/webhook) for Alert-severity
        // events only, on a background thread so a slow SMTP/webhook call
        // never blocks whatever just triggered the alert.
        if severity == Severity::Alert {
            if let Some(config) = self.alert_config.lock().unwrap().clone() {
                if config.email_enabled || config.webhook_enabled {
                    let log_clone = self.clone();
                    let source = source.to_string();
                    std::thread::spawn(move || {
                        alerts::dispatch(&config, &source, &message, &log_clone);
                    });
                }
            }
        }
    }

    pub fn info(&self, source: &str, message: impl Into<String>) {
        self.push(source, Severity::Info, message);
    }

    pub fn warn(&self, source: &str, message: impl Into<String>) {
        self.push(source, Severity::Warning, message);
    }

    pub fn alert(&self, source: &str, message: impl Into<String>) {
        self.push(source, Severity::Alert, message);
    }

    pub fn snapshot(&self) -> Vec<LogEntry> {
        self.entries.lock().map(|e| e.clone()).unwrap_or_default()
    }

    pub fn log_file_path(&self) -> &std::path::Path {
        &self.log_file_path
    }
}
