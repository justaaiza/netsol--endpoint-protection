"""
Inspector: Windows Firewall Profile Enabled State

PowerShell strategy:
  Get-NetFirewallProfile returns Domain, Private, and Public profile objects.
  We capture the Name and Enabled fields for each.

The inspector never raises; it returns {"error": "..."} so the UI always renders.
"""

import json
from execution.executor import run_powershell

_PS_COMMAND = r"""
Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress
"""


def inspect() -> dict:
    """
    Returns a structured dict describing the enabled state of each firewall profile.

    Return schema:
    {
        "parameter": "firewall_profiles",
        "profiles": {
            "Domain":  {"enabled": true | false},
            "Private": {"enabled": true | false},
            "Public":  {"enabled": true | false}
        },
        "disabled_profiles": ["Domain", ...],
        "raw_output": "<stdout>",
        "error": null | "<error message>"
    }
    """
    result = run_powershell(_PS_COMMAND)

    if result.get("error"):
        return {
            "parameter": "firewall_profiles",
            "profiles": {},
            "disabled_profiles": [],
            "raw_output": result.get("stdout", ""),
            "error": result["error"],
        }

    stdout = result.get("stdout", "").strip()

    try:
        parsed = json.loads(stdout) if stdout else []
        # Single profile returns object, multiple return array
        if isinstance(parsed, dict):
            parsed = [parsed]
    except json.JSONDecodeError as exc:
        return {
            "parameter": "firewall_profiles",
            "profiles": {},
            "disabled_profiles": [],
            "raw_output": stdout,
            "error": f"JSON parse error: {exc}",
        }

    profiles = {}
    disabled = []
    for item in parsed:
        name = item.get("Name", "Unknown")
        # PowerShell returns True/False as JSON booleans; also handle string "True"/"False"
        enabled_raw = item.get("Enabled", False)
        if isinstance(enabled_raw, str):
            enabled = enabled_raw.lower() == "true"
        else:
            enabled = bool(enabled_raw)

        profiles[name] = {"enabled": enabled}
        if not enabled:
            disabled.append(name)

    return {
        "parameter": "firewall_profiles",
        "profiles": profiles,
        "disabled_profiles": disabled,
        "raw_output": stdout,
        "error": None,
    }
