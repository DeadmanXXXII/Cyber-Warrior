# Microsoft Store packaging (.appxbundle)

CI already builds `CyberWarrior.appxbundle` on every Windows run (see the
"Build .appxbundle (Store package)" step in `.github/workflows/build.yml`
and download it as the `CyberWarrior-appxbundle` artifact). What's left is
identity — the two things only Partner Center can give you.

## 1. Reserve the app name in Partner Center

If you haven't already: [Partner Center](https://partner.microsoft.com/dashboard)
→ Apps and games → New product → reserve "CyberWarrior" (or whatever name
you want listed).

## 2. Copy your identity values

After reserving, go to that app's **App identity** page. You'll see three
values that MUST exactly match what goes in the manifest:
- **Package/Identity Name** (looks like `12345YourAccount.CyberWarrior`)
- **Publisher ID** (looks like `CN=A1B2C3D4-...`)
- **Publisher display name** (your account's display name)

## 3. Set them as repository variables

In your GitHub repo: Settings → Secrets and variables → Actions →
**Variables** tab (not Secrets — these aren't sensitive) → add:
- `APPX_IDENTITY_NAME`
- `APPX_PUBLISHER`
- `APPX_PUBLISHER_DISPLAY_NAME`

Push again (or re-run the workflow) and the `.appxbundle` will build with
your real identity instead of the placeholder. Without these set, CI still
builds successfully — it just uses a placeholder identity that's fine for
sideload testing but Partner Center will reject on upload.

## 4. Test it locally before submitting (optional but recommended)

The `.appxbundle` CI produces is unsigned. Partner Center signs it for you
on ingestion, so this step is only for testing on your own machine first:

```powershell
.\packaging\appx\create-test-cert-and-install.ps1 -AppxBundlePath .\CyberWarrior.appxbundle -Publisher "CN=your-publisher-id-from-step-2"
```

This creates a throwaway local certificate, signs the bundle with it just
well enough for your own machine to trust it, and installs it via
`Add-AppxPackage`. It is **not** the certificate or signature that goes to
the Store — don't reuse it for anything beyond your own testing.

## 5. Upload to Partner Center

Dashboard → your app → Packages → upload `CyberWarrior.appxbundle` →
fill out the rest of the listing (screenshots, description, age rating,
etc. — the mockup Claude generated can inform the screenshots) → submit
for certification.

## Known gaps in this packaging (fix if certification flags them)

- **Age rating / content questionnaire** isn't filled out anywhere here —
  that's a Partner Center step, not a CI one.
- **Capabilities**: this manifest only declares `runFullTrust` (required
  for any Desktop Bridge Win32 app). If Store certification flags a
  missing capability for something specific this app does (firewall
  control, packet capture), that's worth checking against the
  [capability list](https://learn.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations)
  — most likely none needed beyond `runFullTrust` since this isn't a
  sandboxed UWP app, but Store review is the actual authority here, not
  this note.
- **Version numbering** uses the GitHub Actions run number as a stand-in
  (`1.0.<run_number>.0`) — replace with real semantic versioning tied to
  your release process once you have one.
