@echo off
setlocal enabledelayedexpansion
title ClawShield Standalone

echo.
echo   ========================================
echo   ClawShield — AI Security Gateway
echo   ========================================
echo.

:: Check prerequisites
where node >nul 2>nul
if errorlevel 1 (
    echo ERROR: Node.js not found. Install from https://nodejs.org/
    echo Requires Node.js 20 or later.
    pause
    exit /b 1
)

:: Check if openclaw is installed
where openclaw >nul 2>nul
if errorlevel 1 (
    echo OpenClaw not found, installing...
    call npm install -g openclaw@2026.2.9
    if errorlevel 1 (
        echo ERROR: Failed to install OpenClaw.
        pause
        exit /b 1
    )
    echo OpenClaw installed successfully.
)

:: Check API key
if "%ANTHROPIC_API_KEY%"=="" (
    if exist "%~dp0.env" (
        for /f "usebackq tokens=1,* delims==" %%a in ("%~dp0.env") do (
            if "%%a"=="ANTHROPIC_API_KEY" set "ANTHROPIC_API_KEY=%%b"
        )
    )
)
if "%ANTHROPIC_API_KEY%"=="" (
    echo ERROR: ANTHROPIC_API_KEY not set.
    echo Set it as an environment variable or create a .env file in this directory.
    pause
    exit /b 1
)

:: Set up config directory
set "CONFIG_DIR=%USERPROFILE%\.clawshield"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"

:: Copy config files if they don't exist
if not exist "%CONFIG_DIR%\openclaw.json" (
    if exist "%~dp0..\config\openclaw.json" (
        copy "%~dp0..\config\openclaw.json" "%CONFIG_DIR%\openclaw.json" >nul
        echo Copied default gateway config.
    )
)
if not exist "%CONFIG_DIR%\policy.yaml" (
    if exist "%~dp0..\config\policy.yaml" (
        copy "%~dp0..\config\policy.yaml" "%CONFIG_DIR%\policy.yaml" >nul
        echo Copied default security policy.
    )
)

:: Copy agents if not present
if not exist "%CONFIG_DIR%\agents" (
    if exist "%~dp0..\agents" (
        xcopy /E /I /Q "%~dp0..\agents" "%CONFIG_DIR%\agents" >nul
        echo Copied agent definitions.
    )
)

:: Check for ClawShield binary
set "CS_BIN=%~dp0clawshield-proxy.exe"
if not exist "%CS_BIN%" (
    set "CS_BIN=%~dp0..\clawshield-proxy.exe"
)
if not exist "%CS_BIN%" (
    echo ERROR: clawshield-proxy.exe not found.
    echo Build it with: go build -o clawshield-proxy.exe ./proxy/cmd/clawshield-proxy/
    pause
    exit /b 1
)

echo Starting OpenClaw gateway on :18790...
cd /d "%CONFIG_DIR%"
start /b "OpenClaw Gateway" cmd /c "openclaw gateway 2>&1 | findstr /v /c:""" >nul 2>&1
timeout /t 3 /nobreak >nul

:: Wait for gateway health
echo Waiting for gateway...
set TRIES=0
:waitloop
if !TRIES! geq 20 (
    echo WARNING: Gateway health check timed out. Starting proxy anyway.
    goto startproxy
)
curl -s -o nul http://127.0.0.1:18790/health 2>nul
if not errorlevel 1 (
    echo Gateway ready.
    goto startproxy
)
set /a TRIES+=1
timeout /t 1 /nobreak >nul
goto waitloop

:startproxy
echo Starting ClawShield proxy on :18789...
echo.
echo   Dashboard: http://localhost:18789
echo.
start http://localhost:18789

"%CS_BIN%" --standalone --policy "%CONFIG_DIR%\policy.yaml" --gateway-url http://127.0.0.1:18790 --gateway-token clawshield --listen :18789 --audit-db "%CONFIG_DIR%\audit.db"

echo.
echo ClawShield stopped. Cleaning up...
taskkill /f /fi "WINDOWTITLE eq OpenClaw Gateway" >nul 2>&1
