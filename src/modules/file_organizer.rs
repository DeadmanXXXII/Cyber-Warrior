use crate::log::SharedLog;
use std::path::Path;
use walkdir::WalkDir;

/// Walks `root`, sorted by last-modified time, and (unless `dry_run`) sets
/// files to owner-read/write + group/other-read (0o644). `dry_run` defaults
/// to true in the GUI so nothing changes until the user reviews the list.
pub fn organize(root: &Path, dry_run: bool, log: &SharedLog) -> Vec<String> {
    log.info(
        "FileOrganizer",
        format!("{} scan of {}", if dry_run { "Dry-run" } else { "Applying" }, root.display()),
    );

    let mut entries: Vec<_> = WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    entries.sort_by_key(|e| {
        e.metadata()
            .ok()
            .and_then(|m| m.modified().ok())
    });

    let mut report = Vec::new();
    for entry in entries {
        let path = entry.path();
        report.push(format!("{}", path.display()));

        if !dry_run {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(path) {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o644);
                    if std::fs::set_permissions(path, perms).is_err() {
                        log.warn("FileOrganizer", format!("Could not set permissions on {}", path.display()));
                    }
                }
            }
        }
    }

    log.info("FileOrganizer", format!("Processed {} file(s)", report.len()));
    report
}
