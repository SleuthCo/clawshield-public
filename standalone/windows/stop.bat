@echo off
echo Stopping ClawShield...

:: Kill ClawShield proxy
taskkill /f /im clawshield-proxy.exe >nul 2>&1

:: Kill OpenClaw gateway (node process running openclaw)
taskkill /f /fi "WINDOWTITLE eq OpenClaw Gateway" >nul 2>&1

echo ClawShield stopped.
