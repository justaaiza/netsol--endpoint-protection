"""
LLM Remediation Prompts — second stage of the pipeline (only for vulnerable parameters).

Design decisions:
- This prompt is only called AFTER a confirmed vulnerable analysis result.
  The analysis dict is passed in so the LLM has full context for its proposed fix.
- The prompt explicitly instructs the model to produce a SINGLE PowerShell command
  (not a script block with multiple lines) to keep the safety denylist validation
  deterministic and the UI display clean.
- We ask for verification_method as a separate field so the UI can display it and
  the app can optionally use it as the verify step.
- The system prompt includes a "safety contract" section instructing the LLM NOT to
  propose dangerous commands — this is defense-in-depth alongside the denylist.
"""

import json
from llm.client import call, LLMError

# ---------------------------------------------------------------------------
# JSON schema that the LLM must return for the remediation stage
# ---------------------------------------------------------------------------
_REMEDIATION_SCHEMA = {
    "remediation_command": (
        "string — a single PowerShell command that remediates the vulnerability. "
        "Must be a one-liner, not a multi-line script."
    ),
    "explanation": "string — what this command does and why it fixes the vulnerability",
    "possible_impact": (
        "string — what could change or break as a side effect of applying this fix"
    ),
    "verification_method": (
        "string — the PowerShell command or expected output value that confirms "
        "the fix was applied successfully"
    ),
}


def build_remediation_messages(
    parameter: str,
    inspection_data: dict,
    analysis_result: dict,
) -> list[dict]:
    """
    Build the message list for the LLM remediation call.

    Args:
        parameter:       One of the 4 parameter keys.
        inspection_data: The dict returned by the corresponding inspector.
        analysis_result: The dict returned by run_analysis() for this parameter.

    Returns:
        List of {"role": ..., "content": ...} messages ready for llm.client.call().
    """
    system_prompt = f"""You are a Windows endpoint security hardening specialist.
Your job is to propose a safe, targeted PowerShell remediation command for a confirmed security vulnerability.

SAFETY CONTRACT (mandatory):
- Propose ONLY hardening/configuration commands. Never propose commands that:
  * Delete files, registry keys, or system objects
  * Shut down or restart the system
  * Disable Windows Defender or any antivirus
  * Download or execute code from the internet
  * Create new user accounts or change passwords
  * Disable firewall profiles entirely
  * Use Invoke-Expression or similar code-injection patterns
- The command must be a single PowerShell one-liner (no &&, no semicolons joining destructive steps)
- Prefer built-in Windows cmdlets (Set-NetFirewallProfile, Set-LocalUser, auditpol, net accounts)
- The fix should be the MINIMUM change needed to address the specific vulnerability

You MUST respond with a single JSON object matching EXACTLY this schema:
{json.dumps(_REMEDIATION_SCHEMA, indent=2)}

Rules:
- remediation_command must be a single executable line
- Do NOT include markdown, code fences, or any text outside the JSON object
- explanation should be 2-3 sentences, technical but readable by a security analyst
- possible_impact should be honest — if there is no impact, say "Minimal impact expected."
- verification_method should be a concrete command or expected value, not vague instructions"""

    user_message = f"""Propose a remediation for the following vulnerability:

PARAMETER: {parameter}

INSPECTION DATA:
{json.dumps(inspection_data, indent=2, default=str)}

VULNERABILITY ANALYSIS:
{json.dumps(analysis_result, indent=2, default=str)}

Provide a safe, single-line PowerShell command to fix this issue and return it as JSON."""

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]


def run_remediation(
    parameter: str,
    inspection_data: dict,
    analysis_result: dict,
) -> dict:
    """
    Call the LLM to propose a remediation and return a validated remediation dict.

    Returns the parsed remediation dict, or raises LLMError on failure.
    The caller (app.py) is responsible for catching LLMError and logging it.
    """
    messages = build_remediation_messages(parameter, inspection_data, analysis_result)
    result = call(messages)

    # Basic schema validation
    required_keys = {
        "remediation_command",
        "explanation",
        "possible_impact",
        "verification_method",
    }
    missing = required_keys - set(result.keys())
    if missing:
        raise LLMError(
            f"LLM remediation response missing required fields: {missing}. "
            f"Got: {list(result.keys())}"
        )

    # Ensure remediation_command is a non-empty string
    cmd = str(result.get("remediation_command", "")).strip()
    if not cmd:
        raise LLMError("LLM returned an empty remediation_command.")
    result["remediation_command"] = cmd

    return result
