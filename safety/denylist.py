"""
Safety Denylist — command validation layer between LLM output and execution.

Design decisions:
- Pattern matching is case-insensitive because PowerShell is case-insensitive.
- We match on the *raw command string* before any shell interpretation.
- The denylist is intentionally broad — false positives (blocking safe commands) are
  preferable to false negatives (executing dangerous commands).
- This check CANNOT be bypassed. Even if a human approves a command, execution is
  blocked if this layer rejects it.

Each entry is a tuple of (pattern_string, human_readable_reason).
"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Denylist patterns
# Each tuple: (regex_pattern, reason_shown_to_user)
# ---------------------------------------------------------------------------
_DENYLIST: list[tuple[str, str]] = [
    # Destructive file/disk operations
    (r"\bRemove-Item\b",            "Deletes files or registry keys (Remove-Item)"),
    (r"\bri\b",                     "Alias for Remove-Item (ri)"),
    (r"\bdel\b",                    "Deletes files (del)"),
    (r"\brd\b",                     "Removes directories (rd)"),
    (r"\brmdir\b",                  "Removes directories (rmdir)"),
    (r"\brm\s+-rf\b",               "Force-deletes files recursively (rm -rf)"),
    (r"\bFormat-Volume\b",          "Formats a disk volume"),
    (r"\bFormat-",                  "Format-* cmdlets can destroy disk data"),
    (r"\bClear-Disk\b",             "Wipes a disk"),

    # System shutdown / restart
    (r"\bshutdown\b",               "Shuts down or restarts the system"),
    (r"\bRestart-Computer\b",       "Restarts the computer"),
    (r"\bStop-Computer\b",          "Shuts down the computer"),

    # Code execution from untrusted strings
    (r"\bInvoke-Expression\b",      "Executes arbitrary strings as code (Invoke-Expression / iex)"),
    (r"\biex\b",                    "Alias for Invoke-Expression"),
    (r"\bInvoke-Command\b",         "Runs commands on local/remote systems"),
    (r"\bStart-Process\b",          "Launches a new process"),

    # Firewall complete disable (we allow profile-specific enables, not wholesale disabling)
    (r"allprofiles state off",      "Disables all firewall profiles entirely"),
    (r"Set-NetFirewallProfile.*-Enabled False", "Disables a firewall profile"),

    # Disabling Windows Defender / AV
    (r"DisableRealtimeMonitoring",  "Disables Windows Defender real-time monitoring"),
    (r"Set-MpPreference.*-Disable", "Modifies Windows Defender preferences to disable features"),

    # Stopping critical services
    (r"\bStop-Service\b",           "Stops a Windows service"),
    (r"\bsc\s+stop\b",              "Stops a Windows service via sc.exe"),
    (r"\bnet\s+stop\b",             "Stops a Windows service via net.exe"),

    # Downloading files from the internet
    (r"\bInvoke-WebRequest\b",      "Downloads content from the internet"),
    (r"\bwget\b",                   "Downloads content from the internet"),
    (r"\bcurl\b",                   "Downloads content from the internet"),
    (r"\bStart-BitsTransfer\b",     "Downloads content using BITS"),

    # Modifying user accounts in dangerous ways
    (r"\bRemove-LocalUser\b",       "Deletes a local user account"),
    (r"\bDisable-LocalUser\b",      "Disables a local user account"),

    # Registry mass-delete
    (r"\bRemove-Item.*HKLM\b",      "Deletes registry keys from HKLM"),
    (r"\bRemove-Item.*HKCU\b",      "Deletes registry keys from HKCU"),
]

# Pre-compile all patterns for performance
_COMPILED_DENYLIST: list[tuple[re.Pattern, str]] = [
    (re.compile(pattern, re.IGNORECASE), reason)
    for pattern, reason in _DENYLIST
]


def validate_command(command: str) -> tuple[bool, Optional[str]]:
    """
    Check whether a proposed PowerShell command is safe to execute.

    Args:
        command: The exact PowerShell command string to validate.

    Returns:
        (True, None)          — Command passed all checks; safe to present for approval.
        (False, reason_str)   — Command matched a denylist pattern; reason describes why.
    """
    if not command or not command.strip():
        return False, "Empty command — nothing to execute."

    for pattern, reason in _COMPILED_DENYLIST:
        if pattern.search(command):
            return False, f"Blocked by safety denylist: {reason}"

    return True, None
