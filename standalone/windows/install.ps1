# ClawShield Standalone — Windows Installer
# Run: powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "  ClawShield — Windows Setup" -ForegroundColor Cyan
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host ""

# Check Node.js
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    Write-Host "ERROR: Node.js not found." -ForegroundColor Red
    Write-Host "Install Node.js 20+ from https://nodejs.org/"
    exit 1
}
$nodeVer = (node --version).TrimStart('v')
$major = [int]($nodeVer.Split('.')[0])
if ($major -lt 20) {
    Write-Host "WARNING: Node.js $nodeVer detected. Node.js 20+ recommended." -ForegroundColor Yellow
}
Write-Host "  Node.js: $nodeVer" -ForegroundColor Green

# Check Go (for building from source)
$go = Get-Command go -ErrorAction SilentlyContinue
if ($go) {
    Write-Host "  Go: $(go version)" -ForegroundColor Green
}

# Install OpenClaw
$openclaw = Get-Command openclaw -ErrorAction SilentlyContinue
if (-not $openclaw) {
    Write-Host "Installing OpenClaw v2026.2.9..." -ForegroundColor Yellow
    npm install -g openclaw@2026.2.9
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install OpenClaw." -ForegroundColor Red
        exit 1
    }
    Write-Host "  OpenClaw installed." -ForegroundColor Green
} else {
    Write-Host "  OpenClaw: already installed" -ForegroundColor Green
}

# Create config directory
$configDir = Join-Path $env:USERPROFILE ".clawshield"
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir | Out-Null
    Write-Host "  Created config directory: $configDir" -ForegroundColor Green
}

# Copy config files
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$parentDir = Split-Path -Parent $scriptDir

$configSrc = Join-Path $parentDir "config"
if (Test-Path $configSrc) {
    $files = @("openclaw.json", "policy.yaml")
    foreach ($f in $files) {
        $dest = Join-Path $configDir $f
        if (-not (Test-Path $dest)) {
            Copy-Item (Join-Path $configSrc $f) $dest
            Write-Host "  Copied: $f" -ForegroundColor Green
        }
    }
}

# Copy agents
$agentsSrc = Join-Path $parentDir "agents"
$agentsDest = Join-Path $configDir "agents"
if ((Test-Path $agentsSrc) -and -not (Test-Path $agentsDest)) {
    Copy-Item -Recurse $agentsSrc $agentsDest
    Write-Host "  Copied agent definitions" -ForegroundColor Green
}

# Build ClawShield binary if Go is available and source exists
$binaryPath = Join-Path $scriptDir "clawshield-proxy.exe"
$goModPath = Join-Path (Split-Path -Parent $parentDir) "go.mod"
if ($go -and (Test-Path $goModPath) -and -not (Test-Path $binaryPath)) {
    Write-Host "Building ClawShield proxy..." -ForegroundColor Yellow
    $repoRoot = Split-Path -Parent $parentDir
    Push-Location $repoRoot
    go build -o $binaryPath ./proxy/cmd/clawshield-proxy/
    Pop-Location
    if (Test-Path $binaryPath) {
        Write-Host "  Built: $binaryPath" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: Build failed. Place clawshield-proxy.exe in $scriptDir" -ForegroundColor Yellow
    }
}

# Create Desktop shortcut
$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopPath "ClawShield.lnk"
if (-not (Test-Path $shortcutPath)) {
    $startBat = Join-Path $scriptDir "start.bat"
    if (Test-Path $startBat) {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $startBat
        $shortcut.WorkingDirectory = $scriptDir
        $shortcut.Description = "ClawShield AI Security Gateway"
        $shortcut.Save()
        Write-Host "  Desktop shortcut created" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "  Setup complete!" -ForegroundColor Cyan
Write-Host ""
Write-Host "  To start ClawShield:" -ForegroundColor White
Write-Host "    1. Set ANTHROPIC_API_KEY environment variable (or create .env file)" -ForegroundColor Gray
Write-Host "    2. Run start.bat (or double-click Desktop shortcut)" -ForegroundColor Gray
Write-Host "    3. Open http://localhost:18789" -ForegroundColor Gray
Write-Host ""
