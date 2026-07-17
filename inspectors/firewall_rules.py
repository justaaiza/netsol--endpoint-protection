"""
Inspector: Firewall Inbound Rules with RemoteAddress == "Any"

PowerShell strategy:
  Get-NetFirewallRule enumerates rules.
  Get-NetFirewallAddressFilter retrieves the address filter for each rule.
  We join on AssociatedNetFirewallRule to find rules whose RemoteAddress is "Any".

The inspector never raises; it returns {"error": "..."} so the UI always renders.
"""

import json
from execution.executor import run_powershell

# ---------------------------------------------------------------------------
# PowerShell command
# We format the output as JSON so Python can parse it without fragile text parsing.
# ---------------------------------------------------------------------------
_PS_COMMAND = r"""
$rules = Get-NetFirewallRule | Where-Object {
    $_.Enabled -eq 'True' -and
    $_.Direction -eq 'Inbound' -and
    $_.Action -eq 'Allow'
}

$results = foreach ($rule in $rules) {
    $addrFilter = $rule | Get-NetFirewallAddressFilter
    if ($addrFilter.RemoteAddress -eq 'Any') {
        [PSCustomObject]@{
            Name         = $rule.Name
            DisplayName  = $rule.DisplayName
            Profile      = $rule.Profile.ToString()
            RemoteAddress = $addrFilter.RemoteAddress.ToString()
            Enabled      = $rule.Enabled.ToString()
            Action       = $rule.Action.ToString()
            Direction    = $rule.Direction.ToString()
        }
    }
}

if ($null -eq $results) {
    ConvertTo-Json @() -Compress
} else {
    $results | ConvertTo-Json -Compress
}
"""


def inspect() -> dict:
    """
    Returns a structured dict describing inbound firewall rules that allow
    traffic from ANY remote address.

    Return schema:
    {
        "parameter": "firewall_rules",
        "rules_any_remote": [
            {
                "Name": "...",
                "DisplayName": "...",
                "Profile": "...",
                "RemoteAddress": "Any",
                "Enabled": "True",
                "Action": "Allow",
                "Direction": "Inbound"
            },
            ...
        ],
        "count": <int>,
        "raw_output": "<stdout>",
        "error": null | "<error message>"
    }
    """
    result = run_powershell(_PS_COMMAND)

    if result.get("error"):
        return {
            "parameter": "firewall_rules",
            "rules_any_remote": [],
            "count": 0,
            "raw_output": result.get("stdout", ""),
            "error": result["error"],
        }

    stdout = result.get("stdout", "").strip()

    # Parse the JSON array returned by ConvertTo-Json
    try:
        parsed = json.loads(stdout) if stdout else []
        # ConvertTo-Json returns an object (not array) when there's exactly one item
        if isinstance(parsed, dict):
            parsed = [parsed]
    except json.JSONDecodeError as exc:
        return {
            "parameter": "firewall_rules",
            "rules_any_remote": [],
            "count": 0,
            "raw_output": stdout,
            "error": f"JSON parse error: {exc}",
        }

    return {
        "parameter": "firewall_rules",
        "rules_any_remote": parsed,
        "count": len(parsed),
        "raw_output": stdout,
        "error": None,
    }
