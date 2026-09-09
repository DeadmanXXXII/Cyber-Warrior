use crate::modules::compliance::{self, Control};
use crate::modules::scan_reports::Finding;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

pub fn export_findings_csv(findings: &[Finding], path: &Path) -> Result<(), String> {
    let mut wtr = csv::Writer::from_path(path).map_err(|e| e.to_string())?;
    wtr.write_record(["Source", "Host", "Name", "Severity", "CVE IDs", "Actively Exploited (CISA KEV)", "Detail"])
        .map_err(|e| e.to_string())?;
    for f in findings {
        wtr.write_record([
            f.source.to_string(),
            f.host.clone(),
            f.name.clone(),
            f.severity.clone(),
            f.cve_ids.join("; "),
            f.actively_exploited.to_string(),
            f.detail.clone(),
        ])
        .map_err(|e| e.to_string())?;
    }
    wtr.flush().map_err(|e| e.to_string())
}

pub fn export_compliance_csv(controls: &[Control], path: &Path) -> Result<(), String> {
    let mut wtr = csv::Writer::from_path(path).map_err(|e| e.to_string())?;
    wtr.write_record(["Framework", "Control ID", "Description", "Met"]).map_err(|e| e.to_string())?;
    for c in controls {
        wtr.write_record([c.framework, c.id, c.description, if c.checked { "Yes" } else { "No" }])
            .map_err(|e| e.to_string())?;
    }
    wtr.flush().map_err(|e| e.to_string())
}

/// A one-page-plus summary PDF: compliance score, finding counts, and the
/// top findings (actively-exploited ones first). Meant as a printable
/// snapshot to hand to someone else, not a replacement for the live tabs.
pub fn export_summary_pdf(findings: &[Finding], controls: &[Control], path: &Path) -> Result<(), String> {
    use printpdf::{BuiltinFont, Mm, PdfDocument};

    let (doc, page1, layer1) = PdfDocument::new("CyberWarrior Security Report", Mm(210.0), Mm(297.0), "Layer 1");
    let font = doc.add_builtin_font(BuiltinFont::Helvetica).map_err(|e| e.to_string())?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).map_err(|e| e.to_string())?;
    let mut layer = doc.get_page(page1).get_layer(layer1);

    let mut y = 280.0;
    layer.use_text("CyberWarrior Security Report", 18.0, Mm(15.0), Mm(y), &font_bold);
    y -= 8.0;
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    layer.use_text(format!("Generated {timestamp}"), 9.0, Mm(15.0), Mm(y), &font);
    y -= 10.0;

    let score = compliance::score(controls);
    layer.use_text(format!("Compliance score: {score:.0}%"), 12.0, Mm(15.0), Mm(y), &font_bold);
    y -= 7.0;
    let exploited = findings.iter().filter(|f| f.actively_exploited).count();
    layer.use_text(
        format!("Findings imported: {} — {} match CISA's actively-exploited (KEV) list", findings.len(), exploited),
        11.0,
        Mm(15.0),
        Mm(y),
        &font,
    );
    y -= 12.0;

    layer.use_text("Findings (actively-exploited listed first):", 13.0, Mm(15.0), Mm(y), &font_bold);
    y -= 8.0;

    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| b.actively_exploited.cmp(&a.actively_exploited));

    for f in sorted.into_iter().take(50) {
        if y < 20.0 {
            let (page2, layer2) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
            layer = doc.get_page(page2).get_layer(layer2);
            y = 280.0;
        }
        let flag = if f.actively_exploited { "[EXPLOITED] " } else { "" };
        let cves = if f.cve_ids.is_empty() { String::new() } else { format!(" ({})", f.cve_ids.join(", ")) };
        let line = format!("{flag}{} — {} [{}, {}]{}", f.name, f.host, f.source, f.severity, cves);
        layer.use_text(line, 9.0, Mm(15.0), Mm(y), &font);
        y -= 5.5;
    }

    layer.use_text("Compliance checklist:", 13.0, Mm(15.0), Mm(y - 6.0), &font_bold);
    y -= 14.0;
    for c in controls {
        if y < 20.0 {
            let (page2, layer2) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
            layer = doc.get_page(page2).get_layer(layer2);
            y = 280.0;
        }
        let mark = if c.checked { "[x]" } else { "[ ]" };
        let line = format!("{mark} {} {} — {}", c.framework, c.id, c.description);
        layer.use_text(line, 9.0, Mm(15.0), Mm(y), &font);
        y -= 5.5;
    }

    let file = File::create(path).map_err(|e| e.to_string())?;
    doc.save(&mut BufWriter::new(file)).map_err(|e| e.to_string())
}
