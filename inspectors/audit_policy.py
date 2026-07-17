"""
Inspector: Audit Policy — Logon Auditing (Success / Failure)

PowerShell strategy:
  `auditpol /get /subcategory:"Logon"` prints the current audit setting for the
  Logon subcategory. We parse the output line for "Logon" and extract the setting
  string (e.g., "Success and Failure", "Success", "Failure", "No Auditing").

The inspector never raises; it returns {"error": "..."} so the UI always renders.
"""

import re
from execution.executor import run_powershell

_PS_COMMAND = 'auditpol /get /subcategory:"Logon"'

# auditpol output looks like:
#   System audit policy
#   Category/Subcategory                      Setting
#     Logon/Logoff
#       Logon                                 Success and Failure
# We match the line that starts with whitespace followed by "Logon" (the subcategory)
_SETTING_PATTERN = re.compile(
    r"^\s+Logon\s+(.+)$", re.IGNORECASE | re.MULTILINE
)


def inspect() -> dict:
    """
    Returns the current Logon audit policy setting.

    Return schema:
    {
        "parameter": "audit_policy",
        "logon_auditing": "<setting string>",   # e.g. "Success and Failure"
        "success_audited": true | false,
        "failure_audited": true | false,
        "raw_output": "<stdout>",
        "error": null | "<error message>"
    }
    """
    result = run_powershell(_PS_COMMAND)

    if result.get("error"):
        return {
            "parameter": "audit_policy",
            "logon_auditing": None,
            "success_audited": False,
            "failure_audited": False,
            "raw_output": result.get("stdout", ""),
            "error": result["error"],
        }

    stdout = result.get("stdout", "")

    match = _SETTING_PATTERN.search(stdout)
    if not match:
        return {
            "parameter": "audit_policy",
            "logon_auditing": None,
            "success_audited": False,
            "failure_audited": False,
            "raw_output": stdout,
            "error": "Could not parse Logon audit setting from auditpol output.",
        }

    setting = match.group(1).strip()
    setting_lower = setting.lower()
    success_audited = "success" in setting_lower
    failure_audited = "failure" in setting_lower

    return {
        "parameter": "audit_policy",
        "logon_auditing": setting,
        "success_audited": success_audited,
        "failure_audited": failure_audited,
        "raw_output": stdout,
        "error": None,
    }
