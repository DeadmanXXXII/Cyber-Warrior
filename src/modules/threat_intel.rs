use crate::log::SharedLog;
use serde::Deserialize;
use std::collections::HashSet;

const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Deserialize)]
struct KevFeed {
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Deserialize, Clone)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject")]
    vendor_project: String,
    #[serde(rename = "product")]
    product: String,
    #[serde(rename = "shortDescription")]
    short_description: String,
}

fn fetch_feed(log: &SharedLog) -> Result<KevFeed, String> {
    log.info("ThreatIntel", "Fetching CISA Known Exploited Vulnerabilities feed");
    let response = reqwest::blocking::get(CISA_KEV_URL).map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        let msg = format!("Feed request failed: HTTP {}", response.status());
        log.warn("ThreatIntel", &msg);
        return Err(msg);
    }
    response.json().map_err(|e| e.to_string())
}

/// Downloads the CISA KEV catalog and returns just the set of actively-exploited
/// CVE IDs, for cross-referencing against findings imported in the Scan Reports
/// tab (Nmap/Nessus/Burp/etc.). This is the "what should I prioritize" answer:
/// not a generated attack list, but a flag on your *actual* detected
/// vulnerabilities that says attackers are already using this one in the wild.
pub fn fetch_known_exploited_cve_set(log: &SharedLog) -> Result<HashSet<String>, String> {
    let feed = fetch_feed(log)?;
    let set: HashSet<String> = feed.vulnerabilities.into_iter().map(|v| v.cve_id).collect();
    log.info("ThreatIntel", format!("Fetched {} known-exploited CVE IDs", set.len()));
    Ok(set)
}

/// Downloads CISA's Known Exploited Vulnerabilities catalog — a defensive
/// feed ("here's what's actively being exploited, go patch it") rather than
/// an attack toolkit. Returns a short human-readable summary of the newest
/// entries.
pub fn fetch_known_exploited_vulnerabilities(log: &SharedLog) -> Result<Vec<String>, String> {
    let feed = fetch_feed(log)?;
    let total = feed.vulnerabilities.len();
    log.info("ThreatIntel", format!("Fetched {total} known-exploited CVEs"));

    let summary = feed
        .vulnerabilities
        .into_iter()
        .rev()
        .take(25)
        .map(|v| {
            format!(
                "{} — {} {} — {}",
                v.cve_id, v.vendor_project, v.product, v.short_description
            )
        })
        .collect();

    Ok(summary)
}
