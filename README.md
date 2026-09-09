# CyberWarrior

A defensive security dashboard for home and small-business systems, built as a
native desktop app (Rust + egui). This is a rework of the original CyberWarrior
CLI modules into one GUI, with the offensive/OSINT components removed or
re-scoped to defense only (see "What changed from the original" below).

## Building via GitHub Actions (recommended — no local Rust toolchain needed)

1. Push this folder to a new GitHub repository (create one on GitHub, then
   from inside this folder):
   ```bash
   git init
   git add .
   git commit -m "Initial CyberWarrior GUI"
   git branch -M main
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   git push -u origin main
   ```
2. GitHub Actions picks up `.github/workflows/build.yml` automatically and
   builds Linux, Windows, and macOS binaries on every push to `main`.
3. Go to the **Actions** tab on your repo → click the latest run → download
   the `cyberwarrior-linux-x86_64`, `cyberwarrior-windows-x86_64.exe`, or
   `cyberwarrior-macos-x86_64` artifact under **Artifacts**.
4. To get a proper GitHub **Release** with attached binaries instead of just
   build artifacts, push a tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
   The `release` job in the workflow will attach all three binaries to a
   GitHub Release automatically.

If a build fails, open the failed job in the Actions tab and check the
compile error at the bottom of the log — Rust's error messages point at the
exact file/line. Paste that error back to me and I'll fix it; I can't run a
Rust compiler in this chat to pre-verify every line, so the first CI run is
the real test.

## Building locally instead

```bash
# Linux (Debian/Ubuntu)
sudo apt install libpcap-dev libgtk-3-dev
cargo build --release

# macOS
cargo build --release

# Windows — also requires the Npcap SDK for linking; see the workflow file
# for the exact steps, or install packet capture support via WinPcap/Npcap.
cargo build --release
```

The binary will be at `target/release/cyberwarrior` (or `.exe` on Windows).

**To actually capture packets at runtime** (Network Monitor tab), you also
need the Npcap (Windows) or libpcap (Linux/macOS, usually preinstalled)
runtime installed, and the app typically needs elevated/admin privileges.

## Modules

| Tab | What it does |
|---|---|
| Dashboard / SIEM | Unified live event feed — every module logs here, plus to `siem.log` |
| Network Monitor | Watches a chosen interface, flags SYN-flood-style patterns |
| Malware Scan | Signature-based scan of a folder you choose |
| Secrets Scanner | Scans your own local files for likely exposed credentials/keys — filesystem path only, no network target field |
| Compliance | Editable checklist against CIS/NIST/GDPR/ISO baseline controls with a live score |
| File Organizer | Lists files by last-modified time; "dry run" by default before touching permissions |
| Incident Response | Runs scripts, but **only** from a folder you designate in Settings — there's no free-text path field anywhere else |
| Port Scanner | Self-check for open ports; requires an explicit "I'm authorized" checkbox before it will run |
| Threat Intel | Pulls CISA's real Known Exploited Vulnerabilities feed |
| Vulnerability Scan & Patch | Detects installed software, cross-checks it against OSV.dev (Linux) or NVD (Windows/macOS), and patches through your OS's own package manager. Same-major-version fixes auto-apply; anything bigger waits for you to click Apply |
| Firewall | Check/toggle your OS's native firewall, block a specific IP inbound |
| Antivirus | Status, quick scan, and definition updates for Windows Defender (built-in) or ClamAV (free, installable from here on Linux/macOS) |
| Integrations | Register tools you already have (Snort, Burp CLI, etc.) once, then launch them with one click |
| Scan Reports | Import Nmap/Nessus/OpenVAS/Burp XML, Velociraptor JSONL, or generic diagnostic JSON exports into one aggregated findings view; cross-reference CVEs against CISA's Known Exploited Vulnerabilities list to see which ones to prioritize |
| Reporting | Export findings/compliance to CSV, or a combined summary to PDF |
| Settings | Configure the approved scripts folder, NVD API key, auto-patch policy, alert delivery, background mode, and persisted defaults |

## What changed from the original CyberWarrior repo

Removed entirely:
- **Infinite Blue** (a working SMB/EternalBlue-style exploit module)
- **Illumination** / **ComShark** (facial recognition + cross-platform
  social/email/phone lookup — a de-anonymization/doxxing tool)
- **backend.rs**'s automated Metasploit/Nessus invocation against a target

Re-scoped to defense-only:
- Recon-style secret harvesting → **local-only** secrets scanner (no network
  target input exists in this module)
- Threat intel downloader → pulls real CVE/IOC feeds (CISA KEV) instead of
  the Exploit-DB archive and a password-cracking wordlist
- "Battle suit" arbitrary script execution → **Incident Response**, which can
  only run scripts placed in a folder you explicitly designate in Settings
- The open-port scanner now requires an explicit authorization checkbox
  before it will run, and defaults to `127.0.0.1`

## Vulnerability Scan & Patch — how the risk tiers work

- **Low risk (auto-applies):** the fixed version has the same major version
  as what's installed, *and* the fix comes from your OS's own trusted
  package manager (`apt`, `winget`, or `brew` — never a downloaded binary).
- **Needs review (always asks):** a major version bump, an unclear fixed
  version, or an NVD keyword match (which is approximate — NVD doesn't give
  a clean "installed version affected" signal the way OSV does, so these are
  flagged for you to confirm relevance before applying).
- Applying a patch always goes through the real package manager
  (`apt-get install --only-upgrade`, `winget upgrade`, `brew upgrade`).
  Elevation, when required, goes through the OS's own prompt (`pkexec` /
  UAC) — this app never bypasses that.
- Linux detection currently supports Debian/Ubuntu (`dpkg`) with OSV.dev
  lookups, which is accurate and version-range-aware. Windows/macOS use a
  best-effort NVD keyword search, which is coarser — treat those results as
  a starting point for research, not a definitive match.

## Firewall, Antivirus, and elevation prompts

Toggling the firewall, blocking an IP, updating AV definitions, and applying
patches all shell out to the OS's own trusted tools (`netsh`, `ufw`,
`pfctl`, PowerShell's Defender cmdlets, `apt`/`winget`/`brew`). Several need
elevated privileges — Linux uses `pkexec` (a graphical polkit prompt),
Windows shows a UAC prompt, macOS uses `sudo` (which may need the app
launched from a terminal the first time, since macOS has no GUI sudo prompt
by default). The app never bypasses these or elevates itself silently.

## Scheduled scans

Malware Scan, Secrets Scan, and Vulnerability Scan can each run on a timer
(hours between runs, configurable) instead of only on manual click. All off
by default. This only runs while the app is open — there's no OS-level
background service — and reuses the exact same functions the manual tabs
call, just triggered by a clock check every 5 minutes instead of a button.

## Trends

Records one snapshot per day (compliance score, total findings, actively-
exploited findings) and plots them. The compliance checklist itself now
persists across restarts too — it didn't before, which would have made the
score plot meaningless (always resetting to 0% on relaunch).

## Fleet

For seeing status across more than one machine without standing up a server:
point every instance at the same shared folder (synced cloud folder or
network share), and each one writes a `<hostname>.status.json` file there
that every other instance reads. No accounts, no coordination beyond "same
folder" — which also means it's exactly as private as that folder is.
Publishing is manual (a button) in this version, not automatic on an
interval yet.

## Watched-folder auto-import (Scan Reports)

Point Scan Reports at a folder and it's checked every few seconds; any new
Nmap/.nessus/OpenVAS/Burp XML, Velociraptor `.jsonl`, or diagnostic `.json`
dropped in there is auto-imported (format auto-detected by peeking at the
content). Already-imported filenames are remembered across restarts so
nothing gets re-imported on relaunch.

## Update checker

Checks a GitHub repo's latest release against the running version.
Deliberately has no default repo baked in — set `owner/repo` in Settings
once this is actually published somewhere with releases.

## First CI run results (2026-08-30)

All three platforms compiled cleanly on the very first Actions run — including the riskiest pieces (tray-icon integration, printpdf, lettre, the Npcap SDK step on Windows). Downloading and inspecting the actual artifacts surfaced two real bugs, now fixed in this version:

- **Linux binary failed to launch** with `libxdo.so.3: cannot open shared object file`. egui's clipboard support (via `arboard`) links against it; it happened to be present on the Ubuntu CI runner but isn't guaranteed on an end user's machine. Fixed by bundling the `.so` in the tarball alongside a small launcher script that points `LD_LIBRARY_PATH` at it — no `apt install` required by whoever downloads it.
- **Windows `.exe` was a console subsystem binary**, meaning a terminal window would flash up behind the GUI on launch. Fixed with `#![windows_subsystem = "windows"]` on release builds (debug builds keep the console for `println!` debugging).

Neither would have been obvious from the build log alone — both only showed up by actually running the shipped binaries.

## Microsoft Store packaging (.appxbundle)

CI now also builds an unsigned `CyberWarrior.appxbundle` on every Windows run, packaged as a Desktop Bridge app (the exe wrapped with Store-required manifest + icon assets, no UWP rewrite needed). See `packaging/appx/README.md` for the full flow: reserving the app name in Partner Center, setting the identity as repo variables so CI stops using placeholder values, testing locally via the included self-signed-cert script, and what still needs filling in on Partner Center's side (age rating, screenshots, etc. — not something a CI step can do for you).

## Reporting

Exports whatever's currently loaded in Scan Reports / Compliance:
- CSV export of findings, and a separate CSV export of the compliance checklist
- A combined summary PDF (compliance score, finding counts, actively-exploited
  findings listed first, full compliance checklist) — built with `printpdf`
  (pure Rust, no system PDF toolchain needed)

## Alert delivery, auto-quarantine, and background mode

Three additions on top of the local SIEM log, all off by default in Settings:

- **Email/webhook alerts** — any Alert-severity event (intrusions, actively-
  exploited findings) is also sent via SMTP and/or a JSON webhook
  (Slack/Discord/Teams-compatible), not just written to the local log.
- **Auto-quarantine** — when on, Network Monitor's SYN-flood detection calls
  Firewall's block-IP action automatically instead of only alerting. Off by
  default since auto-blocking a real address is more consequential than
  logging one; when on, the auto-action is itself logged as an Alert (which
  can then also go out over email/webhook).
- **Background/tray mode** — "minimize to tray on close" keeps Network
  Monitor running after the window closes, with a tray menu to reopen or
  quit; "start monitoring on launch" skips the manual start click. This is
  the newest, least battle-tested part of the app (see caveat below).

## Branding

The window/taskbar icon, the system tray icon, and the sidebar logo all use
`assets/icon.png` (the CyberWarrior helmet logo). The macOS packaging step
also builds a proper multi-resolution `.icns` from that same source file.

## Build & packaging

`.github/workflows/build.yml` builds all three platforms on every push and
uploads:
- **macOS** — an actual `.app` bundle (double-click to launch, proper Dock
  icon). It's unsigned, so first launch needs right-click → Open past
  Gatekeeper until it's signed with a paid Apple Developer ID.
- **Windows** — a `.zip` with the `.exe`. Network Monitor's packet capture
  needs the free Npcap *runtime* driver installed on the machine running the
  app (separate from the Npcap SDK the build itself needs — see the workflow
  comments); a real installer could bundle that, this zip doesn't.
- **Linux** — a `.tar.gz` with the binary and a `.desktop` file for the
  applications menu.

None of these are Microsoft Store / notarized-macOS-app polished yet — that's
a real additional step (code signing certificates, store submission) worth
treating as its own follow-up rather than assuming it falls out of CI for
free. Same goes for a proper Windows MSI installer (e.g. via `cargo-wix`):
deliberately not added here, since it needs the WiX toolset set up in CI and
a broken installer step is worse than an honest zip.

## Integrations — the safe version of "run any program"

Rather than a free-text "path to executable" field anywhere in the app
(an arbitrary-execution risk), tools are registered once on the
Integrations screen — name, executable, optional arguments — and only then
do they show up as a Launch button. Same "no arbitrary path from elsewhere
in the app" guarantee Incident Response has, but for tools like Snort or
Burp Suite's CLI that you already run yourself.

## Scan Reports — bringing in results from Kali/Commando VMs, Velociraptor, etc.

The gap this closes: scanning tools like Nmap, Nessus/OpenVAS, and Burp are
normally run from a separate pentest environment (Kali, Commando VM) or your
own workstation, not from inside CyberWarrior — this app has no scanner or
exploit engine of its own by design. What it *can* do is read the report
files those tools already produce and give you one aggregated view:

- **Nmap** — `nmap -oX output.xml`, imported here. CVE IDs are pulled from
  NSE script output (e.g. `vulners`/`vulscan`) if you ran those scripts.
- **Nessus/OpenVAS** — the native `.nessus`/OpenVAS XML export, including
  each finding's CVE list and severity.
- **Burp Suite** — Report → XML from the scanner. Burp findings are mostly
  web-app classes (XSS, SQLi, etc.) rather than CVE-tagged, but any CVE
  mentioned in an issue's detail text is still picked up.
- **Velociraptor** — a hunt/flow's "Export to JSON" (JSONL) output. Schemas
  vary a lot by artifact, so this is read generically: host/client ID if
  present, plus any CVE mentions, with the full raw row kept for review.
- **Generic diagnostic JSON** — a best-effort importer for other agents
  (e.g. an Aurora-style endpoint agent) with an unknown export schema. It
  looks for common field names (host, severity, description) and always
  keeps the raw JSON too, so nothing is silently dropped — treat it as a
  starting point to confirm against your tool's actual output, not a
  guaranteed-correct parser tuned to a specific product.

**Prioritization**: "Cross-reference against CISA KEV" checks every
imported finding's CVE(s) against CISA's real Known Exploited
Vulnerabilities catalog and flags matches. That's the safe, standard answer
to "what should I test/patch first" — a marker on your *actual* detected
findings showing which ones attackers are already using in the wild, not a
generated list of attacks to run. NVD (NIST) is already used the same way
in the Vulnerability Scan tab for version-level matching. NCSC UK and
Interpol don't publish an equivalent machine-readable "actively exploited"
feed, so CISA KEV + NVD is the closest fit; happy to add a specific feed if
you find one with a public API.

