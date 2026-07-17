# =============================================================================
# DEMO RESET: restore_state.ps1
# =============================================================================
# PURPOSE  : Undoes all changes made by break_state.ps1, restoring the 4
#            security parameters to safe/hardened defaults.
#
# USAGE    : Run as Administrator in PowerShell AFTER your demo:
#              .\demo_setup\restore_state.ps1
# =============================================================================

#Requires -RunAsAdministrator

Write-Host "============================================================" -ForegroundColor Green
Write-Host "  DEMO RESET: Restoring Secure Security Settings" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

# =============================================================================
# RESTORE #1 — Remove the demo insecure firewall rule
# =============================================================================
Write-Host "[1/4] Removing insecure demo firewall rule..." -ForegroundColor Cyan

$rule = Get-NetFirewallRule -DisplayName "DEMO_INSECURE_ANY_REMOTE" -ErrorAction SilentlyContinue
if ($rule) {
    Remove-NetFirewallRule -DisplayName "DEMO_INSECURE_ANY_REMOTE"
    Write-Host "      Removed rule: DEMO_INSECURE_ANY_REMOTE" -ForegroundColor Green
} else {
    Write-Host "      Rule not found — already removed or never created." -ForegroundColor DarkGray
}

# =============================================================================
# RESTORE #2 — Re-enable the Public firewall profile
# =============================================================================
Write-Host "[2/4] Re-enabling Public firewall profile..." -ForegroundColor Cyan

Set-NetFirewallProfile -Profile Public -Enabled True
Write-Host "      Public firewall profile is now ENABLED." -ForegroundColor Green

# =============================================================================
# RESTORE #3 — Set minimum password length back to 14 (CIS baseline)
# =============================================================================
Write-Host "[3/4] Restoring minimum password length to 14..." -ForegroundColor Cyan

net accounts /minpwlen:14 | Out-Null
Write-Host "      Minimum password length is now 14 characters." -ForegroundColor Green

# =============================================================================
# RESTORE #4 — Re-enable Logon auditing (Success and Failure)
# =============================================================================
Write-Host "[4/4] Restoring Logon audit policy (Success and Failure)..." -ForegroundColor Cyan

auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
Write-Host "      Logon auditing: Success and Failure ENABLED." -ForegroundColor Green

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  All security settings restored to secure defaults." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
