# build-bundle.ps1 — Build self-contained ClawShield Windows bundle
# Usage: powershell -ExecutionPolicy Bypass -File scripts/build-bundle.ps1
#
# Prerequisites on build machine: Go 1.24+, GCC (for CGO builds)
# The bundle itself requires NO prerequisites on the target machine.

param(
    [string]$Version = "1.0.0",
    [string]$NodeVersion = "22.14.0",
    [string]$OpenclawVersion = "2026.2.9",
    [string]$OutputDir = "."
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "=== ClawShield Bundle Builder ===" -ForegroundColor Cyan
Write-Host "  Bundle version:  $Version"
Write-Host "  Node.js version: $NodeVersion"
Write-Host "  OpenClaw target: $OpenclawVersion"
Write-Host ""

$BundleDir = Join-Path $env:TEMP "clawshield-bundle-win-x64"
if (Test-Path $BundleDir) { Remove-Item -Recurse -Force $BundleDir }
New-Item -ItemType Directory -Path $BundleDir | Out-Null
New-Item -ItemType Directory -Path "$BundleDir\bin" | Out-Null

# --- Step 1: Build Go binaries ---
Write-Host "[1/5] Building Go binaries..." -ForegroundColor Yellow

# Setup binary (CGO_ENABLED=0 — no sqlite dependency)
Write-Host "  Building clawshield-setup.exe (CGO_ENABLED=0)..."
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
Push-Location $RepoRoot
go build -ldflags "-s -w" -o "$BundleDir\clawshield-setup.exe" ./proxy/cmd/clawshield-setup/
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "Failed to build clawshield-setup" }
Pop-Location

# Proxy binary (CGO_ENABLED=1 — needs sqlite)
Write-Host "  Building clawshield-proxy.exe (CGO_ENABLED=1)..."
$env:CGO_ENABLED = "1"
Push-Location $RepoRoot
go build -ldflags "-s -w" -o "$BundleDir\bin\clawshield-proxy.exe" ./proxy/cmd/clawshield-proxy/
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "Failed to build clawshield-proxy" }
Pop-Location

# Audit binary (CGO_ENABLED=1 — needs sqlite)
Write-Host "  Building clawshield-audit.exe (CGO_ENABLED=1)..."
Push-Location $RepoRoot
go build -ldflags "-s -w" -o "$BundleDir\bin\clawshield-audit.exe" ./proxy/cmd/clawshield-audit/
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Warning: clawshield-audit build failed (non-fatal)" -ForegroundColor DarkYellow
} else {
    Write-Host "  OK" -ForegroundColor Green
}
Pop-Location

# Remove CGO env override
Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host "  OK - all binaries built" -ForegroundColor Green

# --- Step 2: Download portable Node.js ---
Write-Host "[2/5] Downloading Node.js $NodeVersion portable..." -ForegroundColor Yellow

$NodeZipName = "node-v$NodeVersion-win-x64.zip"
$NodeUrl = "https://nodejs.org/dist/v$NodeVersion/$NodeZipName"
$NodeZipPath = Join-Path $env:TEMP $NodeZipName

if (-not (Test-Path $NodeZipPath)) {
    Write-Host "  Downloading from $NodeUrl..."
    Invoke-WebRequest -Uri $NodeUrl -OutFile $NodeZipPath -UseBasicParsing
} else {
    Write-Host "  Using cached download: $NodeZipPath"
}

Write-Host "  Extracting..."
$NodeExtractDir = Join-Path $env:TEMP "node-extract"
if (Test-Path $NodeExtractDir) { Remove-Item -Recurse -Force $NodeExtractDir }
Expand-Archive -Path $NodeZipPath -DestinationPath $NodeExtractDir

# Move contents into bundle node/ directory
$NodeSrcDir = Join-Path $NodeExtractDir "node-v$NodeVersion-win-x64"
$NodeDestDir = Join-Path $BundleDir "node"
Move-Item -Path $NodeSrcDir -Destination $NodeDestDir

Write-Host "  OK - Node.js extracted to node/" -ForegroundColor Green

# --- Step 3: Copy policy examples ---
Write-Host "[3/5] Copying policy files..." -ForegroundColor Yellow

$PolicySrc = Join-Path $RepoRoot "policy\examples"
$PolicyDest = Join-Path $BundleDir "policy"
New-Item -ItemType Directory -Path $PolicyDest | Out-Null

if (Test-Path $PolicySrc) {
    Copy-Item -Path "$PolicySrc\*" -Destination $PolicyDest -Recurse
    Write-Host "  OK - copied policy examples" -ForegroundColor Green
} else {
    Write-Host "  Warning: no policy/examples/ found, creating empty policy dir" -ForegroundColor DarkYellow
}

# --- Step 4: Generate bundle.json manifest ---
Write-Host "[4/5] Generating bundle.json..." -ForegroundColor Yellow

$Manifest = @{
    version = $Version
    platform = "windows-x64"
    created = (Get-Date -Format "o")
    openclaw_version = $OpenclawVersion
    node_version = $NodeVersion
    contents = @{
        setup = "clawshield-setup.exe"
        proxy = "bin/clawshield-proxy.exe"
        audit = "bin/clawshield-audit.exe"
        node_dir = "node"
        policy_dir = "policy"
    }
} | ConvertTo-Json -Depth 3

$Manifest | Out-File -FilePath "$BundleDir\bundle.json" -Encoding utf8NoBOM
Write-Host "  OK" -ForegroundColor Green

# --- Step 4b: Generate README.txt ---

$Readme = @"
ClawShield Bundle v$Version (Windows x64)
==========================================

Self-contained bundle — no prerequisites required.

Quick Start
-----------
1. Unzip this folder anywhere
2. Double-click clawshield-setup.exe (or run from terminal)
3. Follow the interactive wizard
4. Internet is needed only for: npm install openclaw (~200 MB)

What's Included
---------------
- clawshield-setup.exe   Setup wizard (interactive or --non-interactive)
- bin/clawshield-proxy.exe   Security proxy (pre-built)
- bin/clawshield-audit.exe   Audit log viewer (pre-built)
- node/                      Portable Node.js $NodeVersion (no install needed)
- policy/                    Example security policies

The wizard will:
- Detect bundled Node.js and binaries automatically
- Install OpenClaw via the bundled npm
- Generate configuration, agent directories, and start scripts
- Skip Go/GCC dependency checks (binaries are pre-built)

For more information: https://github.com/SleuthCo/clawshield
"@

$Readme | Out-File -FilePath "$BundleDir\README.txt" -Encoding utf8NoBOM

# --- Step 5: Create zip ---
Write-Host "[5/5] Creating zip archive..." -ForegroundColor Yellow

$ZipName = "clawshield-bundle-win-x64-$Version.zip"
$ZipPath = Join-Path (Resolve-Path $OutputDir) $ZipName

if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
Compress-Archive -Path "$BundleDir\*" -DestinationPath $ZipPath

# Clean up temp dir
Remove-Item -Recurse -Force $BundleDir
Remove-Item -Recurse -Force $NodeExtractDir -ErrorAction SilentlyContinue

$ZipSize = [math]::Round((Get-Item $ZipPath).Length / 1MB, 1)
Write-Host ""
Write-Host "=== Bundle complete ===" -ForegroundColor Green
Write-Host "  Output: $ZipPath"
Write-Host "  Size:   $ZipSize MB"
Write-Host ""
Write-Host "  To test: unzip into Windows Sandbox, run clawshield-setup.exe"
Write-Host ""
