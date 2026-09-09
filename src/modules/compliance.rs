#[derive(Clone)]
pub struct Control {
    pub framework: &'static str,
    pub id: &'static str,
    pub description: &'static str,
    pub checked: bool,
}

/// A starter checklist covering common baseline controls relevant to a home
/// or small-business environment. This isn't a substitute for a real audit,
/// but it gives an honest, user-driven score instead of a hardcoded "true".
pub fn default_controls() -> Vec<Control> {
    vec![
        Control { framework: "CIS", id: "1.1", description: "Inventory of all authorized devices maintained", checked: false },
        Control { framework: "CIS", id: "4.1", description: "Automatic OS security updates enabled", checked: false },
        Control { framework: "CIS", id: "5.1", description: "Unique, strong passwords for all accounts", checked: false },
        Control { framework: "CIS", id: "6.1", description: "Multi-factor authentication enabled where available", checked: false },
        Control { framework: "CIS", id: "10.1", description: "Anti-malware software installed and up to date", checked: false },
        Control { framework: "NIST", id: "PR.DS-1", description: "Data-at-rest is protected (disk encryption enabled)", checked: false },
        Control { framework: "NIST", id: "PR.AC-4", description: "Access permissions follow least privilege", checked: false },
        Control { framework: "NIST", id: "DE.CM-1", description: "Network is monitored for security events", checked: false },
        Control { framework: "GDPR", id: "Art.32", description: "Appropriate technical measures protect personal data", checked: false },
        Control { framework: "GDPR", id: "Art.33", description: "Breach notification process is defined", checked: false },
        Control { framework: "ISO 27001", id: "A.12.3", description: "Regular backups are taken and tested", checked: false },
        Control { framework: "ISO 27001", id: "A.9.2", description: "User access rights are reviewed periodically", checked: false },
        Control { framework: "FISMA", id: "AC-2", description: "Account management process exists (creation/review/removal)", checked: false },
        Control { framework: "FISMA", id: "IR-4", description: "Incident response capability is documented and tested", checked: false },
    ]
}

pub fn score(controls: &[Control]) -> f32 {
    if controls.is_empty() {
        return 0.0;
    }
    let checked = controls.iter().filter(|c| c.checked).count();
    (checked as f32 / controls.len() as f32) * 100.0
}
