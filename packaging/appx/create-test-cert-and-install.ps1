# Run this LOCALLY on a Windows test machine, not in CI, and not for the
# Store submission itself — Partner Center signs the package it ingests.
# This script only lets you install + launch the .appxbundle yourself
# first, to confirm it actually works before uploading anywhere.
#
# Usage (run as Administrator):
#   .\create-test-cert-and-install.ps1 -AppxBundlePath .\CyberWarrior.appxbundle -Publisher "CN=YourTestPublisher"
#
# -Publisher MUST exactly match the Publisher value baked into the
# .appxbundle's AppxManifest.xml (the APPX_PUBLISHER repo variable used
# when it was built), or Windows will refuse to install it.

param(
    [Parameter(Mandatory=$true)][string]$AppxBundlePath,
    [Parameter(Mandatory=$true)][string]$Publisher
)

$cert = New-SelfSignedCertificate `
    -Type Custom `
    -Subject $Publisher `
    -KeyUsage DigitalSignature `
    -FriendlyName "CyberWarrior test cert (local sideload only)" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")

$pwd = ConvertTo-SecureString -String "cyberwarrior-test" -Force -AsPlainText
$pfxPath = "$env:TEMP\cyberwarrior-test-cert.pfx"
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwd | Out-Null

Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\TrustedPeople -Password $pwd | Out-Null

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" |
    Where-Object { $_.FullName -match "x64" } | Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) {
    Write-Error "signtool.exe not found — install the Windows SDK first."
    exit 1
}

& $signtool sign /fd SHA256 /a /f $pfxPath /p "cyberwarrior-test" $AppxBundlePath
Add-AppxPackage -Path $AppxBundlePath

Write-Host "Installed. Launch CyberWarrior from the Start menu to test."
Write-Host "Remove the test cert afterwards with: Remove-Item Cert:\LocalMachine\TrustedPeople\$($cert.Thumbprint)"
