"""
Audit Logger — append-only JSONL event log.

Design decisions:
- One JSON object per line (JSONL format) for easy streaming / grep / analysis.
- Every write is an atomic append so concurrent Streamlit rerenders don't corrupt the file.
- We use importlib to avoid the stdlib 'logging' name collision; this module lives in
  the project's `logging/` package but is imported as `logging.audit_logger`.
- If the log directory or file cannot be written, we print a warning but never crash
  the main application — audit failure should not block security operations.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

# Resolve the log file path relative to the project root (two levels up from this file)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = _PROJECT_ROOT / "logs" / "audit_log.jsonl"


def _ensure_log_file() -> None:
    """Create the logs directory and file if they don't exist."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not LOG_FILE.exists():
        LOG_FILE.touch()


def log_event(
    parameter: str,
    stage: str,
    result: str,
    extra: dict | None = None,
) -> None:
    """
    Append one JSON record to the audit log.

    Args:
        parameter: Which of the 4 security parameters this event relates to.
                   e.g. "firewall_rules", "firewall_profiles", "password_policy", "audit_policy"
        stage:     The pipeline stage that produced this event.
                   e.g. "inspect", "llm_analysis", "llm_remediation", "safety_check",
                        "human_decision", "execute", "verify"
        result:    Short summary of what happened.
                   e.g. "vulnerable", "approved", "rejected", "verified", "error"
        extra:     Optional dict of additional structured data (raw output, commands, etc.)
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "parameter": parameter,
        "stage": stage,
        "result": result,
    }
    if extra:
        # Merge extra fields but don't let them overwrite the core fields
        for key, value in extra.items():
            if key not in event:
                event[key] = value

    try:
        _ensure_log_file()
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError as exc:
        # Audit failure is non-fatal — warn but continue
        print(f"[AUDIT WARNING] Could not write to {LOG_FILE}: {exc}")


def read_events(max_entries: int = 200) -> list[dict]:
    """
    Read up to `max_entries` events from the log, most recent first.

    Returns an empty list if the file doesn't exist or can't be read.
    """
    try:
        _ensure_log_file()
        lines = LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
        events = []
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # Skip corrupted lines
            if len(events) >= max_entries:
                break
        return events
    except OSError:
        return []
