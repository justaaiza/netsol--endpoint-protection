"""
Inspector: Local Security Policy — Minimum Password Length

PowerShell strategy:
  We call `net accounts` and parse the line containing "Minimum password length".
  This avoids secedit /export which requires more privileges and produces a complex
  INF file. `net accounts` is simpler and sufficient for this PoC.

The inspector never raises; it returns {"error": "..."} so the UI always renders.
"""

import re
from execution.executor import run_powershell

# net accounts outputs plain text; we parse it with regex
_PS_COMMAND = "net accounts"

# Regex to capture the minimum password length value
# Line looks like:  "Minimum password length:                    0"
_LENGTH_PATTERN = re.compile(
    r"Minimum password length\s*:\s*(\d+)", re.IGNORECASE
)


def inspect() -> dict:
    """
    Returns the current minimum password length setting.

    Return schema:
    {
        "parameter": "password_policy",
        "minimum_password_length": <int>,
        "raw_output": "<stdout>",
        "error": null | "<error message>"
    }
    """
    result = run_powershell(_PS_COMMAND)

    if result.get("error"):
        return {
            "parameter": "password_policy",
            "minimum_password_length": None,
            "raw_output": result.get("stdout", ""),
            "error": result["error"],
        }

    stdout = result.get("stdout", "")

    match = _LENGTH_PATTERN.search(stdout)
    if not match:
        return {
            "parameter": "password_policy",
            "minimum_password_length": None,
            "raw_output": stdout,
            "error": "Could not parse 'Minimum password length' from net accounts output.",
        }

    length = int(match.group(1))

    return {
        "parameter": "password_policy",
        "minimum_password_length": length,
        "raw_output": stdout,
        "error": None,
    }
