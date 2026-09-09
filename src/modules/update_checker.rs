use crate::log::SharedLog;
use serde::Deserialize;

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
}

/// Returns `Ok(Some((version, url)))` if `repo`'s latest GitHub release is
/// newer than `current_version`, `Ok(None)` if already current, or `Err` if
/// the check itself failed (network, bad repo, no releases yet, etc).
///
/// `repo` is `"owner/name"`, e.g. `"anthropic/cyberwarrior"` — there's no
/// default baked in since guessing a repo that doesn't exist would just
/// produce a confusing 404 every time.
pub fn check_for_update(repo: &str, current_version: &str, log: &SharedLog) -> Result<Option<(String, String)>, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let client = reqwest::blocking::Client::builder()
        .user_agent("CyberWarrior-update-checker")
        .build()
        .map_err(|e| e.to_string())?;

    let response = client.get(&url).send().map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("GitHub API returned HTTP {} — check the repo name and that it has a release", response.status()));
    }

    let release: GithubRelease = response.json().map_err(|e| e.to_string())?;
    let latest = release.tag_name.trim_start_matches('v').to_string();
    log.info("UpdateChecker", format!("Latest release is {latest} (this build is {current_version})"));

    if latest != current_version {
        Ok(Some((latest, release.html_url)))
    } else {
        Ok(None)
    }
}
