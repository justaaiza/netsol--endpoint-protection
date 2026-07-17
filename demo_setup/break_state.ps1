# =============================================================================
# DEMO SETUP: break_state.ps1
# =============================================================================
# PURPOSE  : Intentionally misconfigures the 4 security parameters so the
#            AI Endpoint Security Hardening tool has real vulnerabilities to
#            detect during a live demo.
#
# WARNING  : This script WEAKENS your system's security posture.
#            Run it ONLY on a test/lab machine.
#            Run restore_state.ps1 immediately after the demo to undo all changes.
#
# USAGE    : Run as Administrator in PowerShell:
#              .\demo_setup\break_state.ps1
#
# RESET    : .\demo_setup\restore_state.ps1
# =============================================================================

#Requires -RunAsAdministrator

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "  DEMO SETUP: Intentionally Breaking Security Settings" -ForegroundColor Yellow
Write-Host "  This script weakens security for demonstration only." -ForegroundColor Yellow
Write-Host "  Run restore_state.ps1 when done to undo all changes." -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

# =============================================================================
# BREAK #1 — Firewall Rules: Add an inbound-allow rule with RemoteAddress=Any
# =============================================================================
# This creates a new firewall rule that allows all inbound TCP traffic on port
# 8888 from ANY remote address. In a real environment this would expose port 8888
# to the internet. The tool should detect it because RemoteAddress = "Any".
Write-Host "[1/4] Creating insecure inbound firewall rule (Any remote address)..." -ForegroundColor Cyan

$existingRule = Get-NetFirewallRule -DisplayName "DEMO_INSECURE_ANY_REMOTE" -ErrorAction SilentlyContinue
if ($existingRule) {
    Write-Host "      Rule already exists — skipping creation." -ForegroundColor DarkGray
} else {
    New-NetFirewallRule `
        -DisplayName "DEMO_INSECURE_ANY_REMOTE" `
        -Name "DEMO_INSECURE_ANY_REMOTE" `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 8888 `
        -RemoteAddress Any `
        -Enabled True `
        -Description "DEMO ONLY — created by break_state.ps1 for security tool demo" | Out-Null
    Write-Host "      Created rule: DEMO_INSECURE_ANY_REMOTE (TCP/8888, Any source)" -ForegroundColor Green
}

# =============================================================================
# BREAK #2 — Firewall Profiles: Disable the Public profile
# =============================================================================
# Disabling the Public profile removes firewall protection on untrusted networks
# (e.g., coffee shop WiFi). This is a high-severity misconfiguration.
Write-Host "[2/4] Disabling Public firewall profile..." -ForegroundColor Cyan

Set-NetFirewallProfile -Profile Public -Enabled False
Write-Host "      Public firewall profile is now DISABLED." -ForegroundColor Green

# =============================================================================
# BREAK #3 — Password Policy: Set minimum password length to 0
# =============================================================================
# Setting minimum length to 0 means Windows will accept blank passwords.
# This is a critical policy violation per NIST and CIS benchmarks.
Write-Host "[3/4] Setting minimum password length to 0..." -ForegroundColor Cyan

net accounts /minpwlen:0 | Out-Null
Write-Host "      Minimum password length is now 0 (no minimum)." -ForegroundColor Green

# =============================================================================
# BREAK #4 — Audit Policy: Disable Logon auditing entirely
# =============================================================================
# Disabling logon auditing means failed and successful login attempts are not
# recorded in the Security event log, creating a blind spot for attack detection.
Write-Host "[4/4] Disabling Logon audit policy..." -ForegroundColor Cyan

auditpol /set /subcategory:"Logon" /success:disable /failure:disable | Out-Null
Write-Host "      Logon auditing is now DISABLED (No Auditing)." -ForegroundColor Green

Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "  All 4 security misconfigurations applied." -ForegroundColor Yellow
Write-Host "  You can now run the hardening tool to detect and fix them." -ForegroundColor Yellow
Write-Host "  Remember to run restore_state.ps1 after the demo!" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
