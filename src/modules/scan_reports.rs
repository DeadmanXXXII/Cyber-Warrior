use crate::log::SharedLog;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

/// One normalized finding, regardless of which tool it came from. This is the
/// common shape the Scan Reports tab displays and cross-references against
/// CISA KEV. Nothing in this module runs a scan or launches a tool — it only
/// reads report files that were produced elsewhere (your Kali/Commando VM,
/// Burp, Velociraptor server, etc.) and aggregates them for review here.
#[derive(Clone, Debug)]
pub struct Finding {
    pub source: &'static str,
    pub host: String,
    pub name: String,
    pub severity: String,
    pub cve_ids: Vec<String>,
    pub detail: String,
    pub actively_exploited: bool,
}

fn cve_regex() -> Regex {
    Regex::new(r"CVE-\d{4}-\d{4,7}").unwrap()
}

fn extract_cves(text: &str, re: &Regex) -> Vec<String> {
    let mut set: Vec<String> = re
        .find_iter(text)
        .map(|m| m.as_str().to_uppercase())
        .collect();
    set.sort();
    set.dedup();
    set
}

fn read_file(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("Couldn't read {}: {e}", path.display()))
}

/// Parses an Nmap XML export (`nmap -oX`). Pulls host addresses, open
/// ports/services, and scrapes any CVE IDs mentioned in NSE script output
/// (e.g. the `vulners` or `vulscan` scripts) since Nmap's own XML schema has
/// no dedicated CVE field.
pub fn import_nmap_xml(path: &Path, log: &SharedLog) -> Result<Vec<Finding>, String> {
    let xml = read_file(path)?;
    let doc = roxmltree::Document::parse(&xml).map_err(|e| format!("Invalid Nmap XML: {e}"))?;
    let re = cve_regex();
    let mut findings = Vec::new();

    for host in doc.descendants().filter(|n| n.has_tag_name("host")) {
        let addr = host
            .children()
            .find(|n| n.has_tag_name("address"))
            .and_then(|n| n.attribute("addr"))
            .unwrap_or("unknown host")
            .to_string();

        for port in host.descendants().filter(|n| n.has_tag_name("port")) {
            let portid = port.attribute("portid").unwrap_or("?");
            let service = port
                .children()
                .find(|n| n.has_tag_name("service"))
                .and_then(|n| n.attribute("name"))
                .unwrap_or("unknown");

            let mut script_output = String::new();
            for script in port.descendants().filter(|n| n.has_tag_name("script")) {
                if let Some(out) = script.attribute("output") {
                    script_output.push_str(out);
                    script_output.push('\n');
                }
            }

            let cves = extract_cves(&script_output, &re);
            if !cves.is_empty() || !script_output.is_empty() {
                findings.push(Finding {
                    source: "Nmap",
                    host: addr.clone(),
                    name: format!("Port {portid}/{service}"),
                    severity: if cves.is_empty() { "Info".into() } else { "Needs review".into() },
                    cve_ids: cves,
                    detail: script_output.trim().to_string(),
                    actively_exploited: false,
                });
            }
        }
    }

    log.info("ScanReports", format!("Imported {} finding(s) from Nmap XML {}", findings.len(), path.display()));
    Ok(findings)
}

/// Parses a `.nessus` (Nessus) or OpenVAS XML export — both use the same
/// `ReportHost` / `ReportItem` schema with a `<cve>` child per CVE.
pub fn import_nessus_xml(path: &Path, log: &SharedLog) -> Result<Vec<Finding>, String> {
    let xml = read_file(path)?;
    let doc = roxmltree::Document::parse(&xml).map_err(|e| format!("Invalid Nessus/OpenVAS XML: {e}"))?;
    let mut findings = Vec::new();

    for report_host in doc.descendants().filter(|n| n.has_tag_name("ReportHost")) {
        let host = report_host.attribute("name").unwrap_or("unknown host").to_string();

        for item in report_host.descendants().filter(|n| n.has_tag_name("ReportItem")) {
            let plugin_name = item.attribute("pluginName").unwrap_or("Unnamed finding").to_string();
            let severity_num = item.attribute("severity").unwrap_or("0");
            let severity = match severity_num {
                "4" => "Critical",
                "3" => "High",
                "2" => "Medium",
                "1" => "Low",
                _ => "Info",
            }
            .to_string();

            let cves: Vec<String> = item
                .descendants()
                .filter(|n| n.has_tag_name("cve"))
                .filter_map(|n| n.text())
                .map(|t| t.trim().to_uppercase())
                .collect();

            let detail = item
                .descendants()
                .find(|n| n.has_tag_name("description") || n.has_tag_name("synopsis"))
                .and_then(|n| n.text())
                .unwrap_or("")
                .trim()
                .to_string();

            // Skip pure informational filler with no CVE and no real severity
            // — a .nessus export can otherwise contain hundreds of these.
            if severity == "Info" && cves.is_empty() {
                continue;
            }

            findings.push(Finding {
                source: "Nessus/OpenVAS",
                host: host.clone(),
                name: plugin_name,
                severity,
                cve_ids: cves,
                detail,
                actively_exploited: false,
            });
        }
    }

    log.info("ScanReports", format!("Imported {} finding(s) from Nessus/OpenVAS XML {}", findings.len(), path.display()));
    Ok(findings)
}

/// Parses a Burp Suite XML export (Burp's "Report → XML" scanner output).
/// Burp findings are mostly web-app classes (XSS, SQLi, etc.) rather than
/// CVE-tagged, but any CVE mentioned in the issue detail/background text is
/// still captured for cross-referencing.
pub fn import_burp_xml(path: &Path, log: &SharedLog) -> Result<Vec<Finding>, String> {
    let xml = read_file(path)?;
    let doc = roxmltree::Document::parse(&xml).map_err(|e| format!("Invalid Burp XML: {e}"))?;
    let re = cve_regex();
    let mut findings = Vec::new();

    for issue in doc.descendants().filter(|n| n.has_tag_name("issue")) {
        let name = issue
            .children()
            .find(|n| n.has_tag_name("name"))
            .and_then(|n| n.text())
            .unwrap_or("Unnamed issue")
            .to_string();
        let host = issue
            .children()
            .find(|n| n.has_tag_name("host"))
            .and_then(|n| n.text())
            .unwrap_or("unknown host")
            .to_string();
        let severity = issue
            .children()
            .find(|n| n.has_tag_name("severity"))
            .and_then(|n| n.text())
            .unwrap_or("Info")
            .to_string();

        let mut detail = String::new();
        for tag in ["issueBackground", "issueDetail", "remediationBackground"] {
            if let Some(text) = issue.children().find(|n| n.has_tag_name(tag)).and_then(|n| n.text()) {
                detail.push_str(text);
                detail.push('\n');
            }
        }

        let cves = extract_cves(&detail, &re);

        findings.push(Finding {
            source: "Burp",
            host,
            name,
            severity,
            cve_ids: cves,
            detail: detail.trim().chars().take(500).collect(),
            actively_exploited: false,
        });
    }

    log.info("ScanReports", format!("Imported {} finding(s) from Burp XML {}", findings.len(), path.display()));
    Ok(findings)
}

/// Parses a Velociraptor result export (JSONL — one JSON object per line,
/// which is what Velociraptor's "Export to JSON" produces for a hunt/flow's
/// results). Velociraptor result schemas vary a lot by artifact, so this
/// treats each line generically: pulls a host/client identifier if present
/// under common field names, scrapes any CVE mentions out of the raw JSON,
/// and keeps the rest as detail text for manual review.
pub fn import_velociraptor_jsonl(path: &Path, log: &SharedLog) -> Result<Vec<Finding>, String> {
    let text = read_file(path)?;
    let re = cve_regex();
    let mut findings = Vec::new();

    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("Line {} isn't valid JSON: {e}", i + 1))?;

        let host = ["Fqdn", "Hostname", "ClientId", "client_id"]
            .iter()
            .find_map(|k| value.get(k).and_then(|v| v.as_str()))
            .unwrap_or("unknown host")
            .to_string();

        let raw = value.to_string();
        let cves = extract_cves(&raw, &re);

        findings.push(Finding {
            source: "Velociraptor",
            host,
            name: "Endpoint diagnostic result".to_string(),
            severity: if cves.is_empty() { "Info".into() } else { "Needs review".into() },
            cve_ids: cves,
            detail: raw.chars().take(500).collect(),
            actively_exploited: false,
        });
    }

    log.info("ScanReports", format!("Imported {} row(s) from Velociraptor export {}", findings.len(), path.display()));
    Ok(findings)
}

/// Generic best-effort JSON importer for other endpoint/diagnostic agents
/// (e.g. an "Aurora agent" style tool) whose exact export schema isn't known
/// ahead of time. Expects a JSON array of objects, and heuristically looks
/// for common field names (host/hostname/device, severity/risk, description/
/// message/summary). If your tool's field names don't match, the raw JSON is
/// still kept in the detail column so nothing is silently dropped — treat
/// this one as a starting point to confirm against your tool's actual export,
/// not a guaranteed-correct parser.
pub fn import_generic_json(path: &Path, log: &SharedLog) -> Result<Vec<Finding>, String> {
    let text = read_file(path)?;
    let re = cve_regex();
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("Invalid JSON: {e}"))?;

    let items: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(a) => a,
        other => vec![other],
    };

    let mut findings = Vec::new();
    for item in items {
        let host = ["host", "hostname", "device", "endpoint", "client"]
            .iter()
            .find_map(|k| item.get(k).and_then(|v| v.as_str()))
            .unwrap_or("unknown host")
            .to_string();
        let severity = ["severity", "risk", "level"]
            .iter()
            .find_map(|k| item.get(k).and_then(|v| v.as_str()))
            .unwrap_or("Info")
            .to_string();
        let name = ["name", "title", "check"]
            .iter()
            .find_map(|k| item.get(k).and_then(|v| v.as_str()))
            .unwrap_or("Diagnostic result")
            .to_string();

        let raw = item.to_string();
        let cves = extract_cves(&raw, &re);

        findings.push(Finding {
            source: "Generic/Aurora",
            host,
            name,
            severity,
            cve_ids: cves,
            detail: raw.chars().take(500).collect(),
            actively_exploited: false,
        });
    }

    log.info("ScanReports", format!("Imported {} finding(s) from generic JSON export {}", findings.len(), path.display()));
    Ok(findings)
}

/// Auto-detects report format from extension + a peek at the content, for
/// the watched-folder auto-import feature. Falls back to an error rather
/// than guessing wrong on an ambiguous file.
pub fn import_auto(path: &Path, log: &SharedLog) -> Result<Vec<Finding>, String> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    match ext.as_str() {
        "jsonl" => import_velociraptor_jsonl(path, log),
        "json" => import_generic_json(path, log),
        "xml" | "nessus" => {
            let text = read_file(path)?;
            if text.contains("<nmaprun") {
                import_nmap_xml(path, log)
            } else if text.contains("NessusClientData") || text.contains("<ReportHost") {
                import_nessus_xml(path, log)
            } else if text.contains("<issues") || text.contains("<issue>") {
                import_burp_xml(path, log)
            } else {
                Err(format!("Couldn't tell what kind of report {} is (not Nmap/Nessus/Burp)", path.display()))
            }
        }
        other => Err(format!("Don't know how to auto-import a .{other} file")),
    }
}

/// Flags each finding whose CVE(s) appear in CISA's Known Exploited
/// Vulnerabilities catalog. This is the prioritization signal: not a list of
/// attacks to try, but a marker on your *actual* detected findings showing
/// which ones attackers are already exploiting in the wild.
pub fn cross_reference_kev(findings: &mut [Finding], kev_cves: &HashSet<String>) -> usize {
    let mut flagged = 0;
    for f in findings.iter_mut() {
        f.actively_exploited = f.cve_ids.iter().any(|c| kev_cves.contains(c));
        if f.actively_exploited {
            flagged += 1;
        }
    }
    flagged
}
