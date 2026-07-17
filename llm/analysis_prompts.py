"""
LLM Analysis Prompts — first stage of the pipeline.

Design decisions:
- Each parameter has a BASELINE string that describes what the SECURE state looks like.
  This is passed into the system prompt so the LLM has a concrete reference to evaluate
  against. The application code does not hard-code "if X then vulnerable" logic —
  the LLM does that reasoning from the baseline description.
- The system prompt enforces a strict JSON schema and forbids markdown formatting so
  Groq's JSON mode can parse the output reliably.
- Severity levels are constrained to exactly: low | medium | high | critical.
"""

import json
from llm.client import call, LLMError

# ---------------------------------------------------------------------------
# Security baselines for each parameter
# These are the "ground truth" descriptions of a secure configuration.
# They are injected into the LLM prompt — not used as code logic.
# ---------------------------------------------------------------------------
_BASELINES = {
    "firewall_rules": (
        "Secure baseline: No enabled inbound-allow firewall rules should have "
        "'Any' as the remote address scope, as this allows connections from all "
        "IP addresses on the internet. Rules with RemoteAddress='Any' should "
        "either be removed, scoped to specific trusted IP ranges, or changed to "
        "block action. Exceptions may exist for well-known services (e.g. HTTPS "
        "on port 443) but should still be documented and minimized."
    ),
    "firewall_profiles": (
        "Secure baseline: All three Windows Firewall profiles (Domain, Private, "
        "and Public) should be enabled (Enabled=True). Disabling any profile "
        "removes a layer of host-based defense. The Public profile is the most "
        "critical as it applies to untrusted networks. Domain profile is important "
        "for corporate environments. All profiles should be active simultaneously."
    ),
    "password_policy": (
        "Secure baseline: The minimum password length should be at least 14 "
        "characters per NIST SP 800-63B and CIS Benchmark recommendations. "
        "A length of 0 or fewer than 8 characters is critical severity. "
        "8-11 characters is high severity. 12-13 characters is medium severity. "
        "14 or more characters meets the baseline."
    ),
    "audit_policy": (
        "Secure baseline: The Logon audit subcategory should audit BOTH Success "
        "and Failure events. Auditing only Success misses failed login attempts "
        "(brute force, credential stuffing). Auditing only Failure misses "
        "successful unauthorized logins. 'No Auditing' is critical severity as "
        "it creates a blind spot for detecting authentication attacks."
    ),
}

# ---------------------------------------------------------------------------
# JSON schema that the LLM must return for the analysis stage
# ---------------------------------------------------------------------------
_ANALYSIS_SCHEMA = {
    "parameter": "string — name of the security parameter",
    "current_state": "string — concise one-sentence description of the current state",
    "is_vulnerable": "boolean — true if the current state deviates from the secure baseline",
    "severity": "string — exactly one of: low, medium, high, critical (or 'none' if not vulnerable)",
    "explanation": "string — plain-English explanation of the risk and why it matters",
}


def build_analysis_messages(parameter: str, inspection_data: dict) -> list[dict]:
    """
    Build the message list for the LLM analysis call.

    Args:
        parameter:       One of the 4 parameter keys (e.g. "firewall_rules").
        inspection_data: The dict returned by the corresponding inspector.

    Returns:
        List of {"role": ..., "content": ...} messages ready for llm.client.call().
    """
    baseline = _BASELINES.get(parameter, "No baseline defined for this parameter.")

    system_prompt = f"""You are a Windows endpoint security analyst.
Your job is to evaluate the current system state against a defined security baseline and report findings as structured JSON.

SECURITY BASELINE FOR THIS PARAMETER:
{baseline}

You MUST respond with a single JSON object matching EXACTLY this schema:
{json.dumps(_ANALYSIS_SCHEMA, indent=2)}

Rules:
- severity must be exactly one of: low, medium, high, critical, none
- if is_vulnerable is false, set severity to "none"
- Do NOT include markdown, code fences, or any text outside the JSON object
- current_state should be one clear sentence describing what you found
- explanation should be 2-4 sentences suitable for a security analyst"""

    user_message = f"""Evaluate the following inspection data for parameter: {parameter}

INSPECTION DATA:
{json.dumps(inspection_data, indent=2, default=str)}

Analyze whether this state is compliant with the security baseline and return your findings as JSON."""

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]


def run_analysis(parameter: str, inspection_data: dict) -> dict:
    """
    Call the LLM to analyze inspection data and return a validated analysis dict.

    Returns the parsed analysis dict, or raises LLMError on failure.
    The caller (app.py) is responsible for catching LLMError and logging it.
    """
    messages = build_analysis_messages(parameter, inspection_data)
    result = call(messages)

    # Basic schema validation — ensure required keys are present
    required_keys = {"parameter", "current_state", "is_vulnerable", "severity", "explanation"}
    missing = required_keys - set(result.keys())
    if missing:
        raise LLMError(
            f"LLM analysis response missing required fields: {missing}. "
            f"Got: {list(result.keys())}"
        )

    # Normalize severity to lowercase
    result["severity"] = str(result.get("severity", "none")).lower()
    valid_severities = {"low", "medium", "high", "critical", "none"}
    if result["severity"] not in valid_severities:
        result["severity"] = "unknown"

    # Ensure is_vulnerable is a bool
    result["is_vulnerable"] = bool(result.get("is_vulnerable", False))

    return result
