use crate::log::SharedLog;
use regex::Regex;
use std::path::Path;
use walkdir::WalkDir;

/// Detects likely-exposed credentials/keys in the user's own files.
/// By design this module only ever takes a local filesystem path — there is
/// no host/IP/target field anywhere in this module or its GUI panel.
struct Pattern {
    name: &'static str,
    regex: Regex,
}

fn patterns() -> Vec<Pattern> {
    vec![
        Pattern { name: "AWS Access Key", regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap() },
        Pattern { name: "Private Key Block", regex: Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap() },
        Pattern { name: "Generic Password Assignment", regex: Regex::new(r#"(?i)(password|passwd|pass)\s*[:=]\s*['"][^'"]{4,}['"]"#).unwrap() },
        Pattern { name: "Slack Token", regex: Regex::new(r"xox[baprs]-[0-9A-Za-z-]{10,}").unwrap() },
        Pattern { name: "Generic API Key Assignment", regex: Regex::new(r#"(?i)(api[_-]?key)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]"#).unwrap() },
    ]
}

/// Returns (files_scanned, findings) where findings are (file, pattern name, line snippet).
pub fn scan(root: &Path, log: &SharedLog) -> (usize, Vec<(String, String, String)>) {
    log.info(
        "SecretsScanner",
        format!("Starting local secrets scan of {}", root.display()),
    );

    let pats = patterns();
    let mut scanned = 0usize;
    let mut findings = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext_ok = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| matches!(e, "txt" | "csv" | "log" | "env" | "json" | "yml" | "yaml" | "conf" | "cfg" | "ini" | "sh" | "py" | "js" | "ts" | "rs"))
            .unwrap_or(false);
        if !ext_ok {
            continue;
        }

        scanned += 1;
        if let Ok(content) = std::fs::read_to_string(path) {
            for (line_no, line) in content.lines().enumerate() {
                for pat in &pats {
                    if pat.regex.is_match(line) {
                        let snippet: String = line.chars().take(80).collect();
                        findings.push((
                            format!("{} (line {})", path.display(), line_no + 1),
                            pat.name.to_string(),
                            snippet,
                        ));
                        log.warn(
                            "SecretsScanner",
                            format!("{} found in {}:{}", pat.name, path.display(), line_no + 1),
                        );
                    }
                }
            }
        }
    }

    log.info(
        "SecretsScanner",
        format!("Scan complete: {} files scanned, {} findings", scanned, findings.len()),
    );
    (scanned, findings)
}
