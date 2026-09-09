use crate::log::SharedLog;
use lettre::message::Message;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use serde::{Deserialize, Serialize};

/// Alert-delivery configuration. Every field is optional; anything left
/// unset simply isn't used. This never runs on its own — it's only invoked
/// from `SharedLog::push` when an Alert-severity event is logged, and only
/// if `enabled` is true for that channel.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AlertConfig {
    pub email_enabled: bool,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub email_from: String,
    pub email_to: String,

    pub webhook_enabled: bool,
    pub webhook_url: String,
}

pub fn send_email(config: &AlertConfig, subject: &str, body: &str) -> Result<(), String> {
    let email = Message::builder()
        .from(config.email_from.parse().map_err(|e| format!("Invalid From address: {e}"))?)
        .to(config.email_to.parse().map_err(|e| format!("Invalid To address: {e}"))?)
        .subject(subject)
        .body(body.to_string())
        .map_err(|e| e.to_string())?;

    let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());
    let mailer = SmtpTransport::relay(&config.smtp_server)
        .map_err(|e| format!("Couldn't resolve SMTP server: {e}"))?
        .port(config.smtp_port)
        .credentials(creds)
        .build();

    mailer.send(&email).map(|_| ()).map_err(|e| format!("Send failed: {e}"))
}

pub fn send_webhook(config: &AlertConfig, message: &str) -> Result<(), String> {
    let body = serde_json::json!({ "text": message, "source": "CyberWarrior" });
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(&config.webhook_url)
        .json(&body)
        .send()
        .map_err(|e| e.to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("Webhook returned HTTP {}", response.status()))
    }
}

/// Fires whichever channels are enabled for a single alert message. Errors
/// are logged locally (not propagated) so a broken webhook/SMTP config never
/// blocks the thing that triggered the alert in the first place.
pub fn dispatch(config: &AlertConfig, source: &str, message: &str, log: &SharedLog) {
    if config.email_enabled {
        let subject = format!("CyberWarrior alert — {source}");
        if let Err(e) = send_email(config, &subject, message) {
            log.warn("Alerts", format!("Email delivery failed: {e}"));
        }
    }
    if config.webhook_enabled {
        let full = format!("[{source}] {message}");
        if let Err(e) = send_webhook(config, &full) {
            log.warn("Alerts", format!("Webhook delivery failed: {e}"));
        }
    }
}
