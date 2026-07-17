"""
AI-Powered Endpoint Security Hardening Tool — Streamlit Dashboard
=================================================================
Entry point: streamlit run app.py  (must be run as Administrator)

Pipeline per parameter (run independently):
  Inspect → LLM Analysis → Safety Check → Human Approval → Execute → Verify → Log

Architecture notes:
- All parameter state is stored in st.session_state as a dict keyed by parameter id.
- Each pipeline stage is a separate function that updates state and logs immediately.
- The UI renders from state — it never drives the pipeline directly.
- Errors at any stage are caught, displayed, and logged without crashing the app.
"""

import sys
import json
import traceback
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# CRITICAL: Fix stdlib 'logging' collision BEFORE any third-party imports.
#
# This project has a `logging/` folder per the project spec, which shadows the
# Python stdlib `logging` module. We load the real stdlib logging by absolute
# path and register it in sys.modules so dotenv, streamlit, groq, etc. all
# find the correct module when they do `import logging`.
# ---------------------------------------------------------------------------
import importlib.util as _ilu_boot
import sysconfig as _sc_boot
_stdlib_dir = _sc_boot.get_paths()["stdlib"]
_log_spec = _ilu_boot.spec_from_file_location(
    "logging",
    f"{_stdlib_dir}/logging/__init__.py",
    submodule_search_locations=[f"{_stdlib_dir}/logging"],
)
_real_logging = _ilu_boot.module_from_spec(_log_spec)
_log_spec.loader.exec_module(_real_logging)
sys.modules["logging"] = _real_logging
# Also pre-load logging.handlers to avoid any lazy-load issues
try:
    _h_spec = _ilu_boot.spec_from_file_location(
        "logging.handlers", f"{_stdlib_dir}/logging/handlers.py"
    )
    _h_mod = _ilu_boot.module_from_spec(_h_spec)
    _h_spec.loader.exec_module(_h_mod)
    sys.modules["logging.handlers"] = _h_mod
    _real_logging.handlers = _h_mod
except Exception:
    pass
del _ilu_boot, _sc_boot, _stdlib_dir, _log_spec, _real_logging

import streamlit as st

# ---------------------------------------------------------------------------
# Path setup — ensure project root is importable regardless of cwd
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------
from execution.executor import is_elevated, run_powershell
from safety.denylist import validate_command
from llm.analysis_prompts import run_analysis
from llm.remediation_prompts import run_remediation
from llm.client import LLMError

# Import audit_logger from the project logging package
# We use importlib to sidestep the stdlib 'logging' name collision
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location(
    "audit_logger",
    PROJECT_ROOT / "logging" / "audit_logger.py",
)
_audit_logger_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_audit_logger_mod)
log_event = _audit_logger_mod.log_event
read_events = _audit_logger_mod.read_events

# Inspector modules
import inspectors.firewall_rules as _insp_fw_rules
import inspectors.firewall_profiles as _insp_fw_profiles
import inspectors.password_policy as _insp_pw_policy
import inspectors.audit_policy as _insp_audit

# ---------------------------------------------------------------------------
# Parameter registry — single source of truth for the 4 parameters
# ---------------------------------------------------------------------------
PARAMETERS = [
    {
        "id": "firewall_rules",
        "label": "Firewall Rules",
        "description": "Inbound rules allowing traffic from Any remote address",
        "inspector": _insp_fw_rules.inspect,
    },
    {
        "id": "firewall_profiles",
        "label": "Firewall Profiles",
        "description": "Domain / Private / Public profile enabled state",
        "inspector": _insp_fw_profiles.inspect,
    },
    {
        "id": "password_policy",
        "label": "Password Policy",
        "description": "Minimum password length (net accounts)",
        "inspector": _insp_pw_policy.inspect,
    },
    {
        "id": "audit_policy",
        "label": "Audit Policy",
        "description": "Logon Success / Failure auditing (auditpol)",
        "inspector": _insp_audit.inspect,
    },
]

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Endpoint Security Hardening",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS — terminal aesthetic (phosphor green on pitch black)
# ---------------------------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');

/* ── Global reset ─────────────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace !important;
    background-color: #000000 !important;
    color: #4ADE80 !important;
}

/* ── Main container ──────────────────────────────────────── */
.main .block-container {
    background-color: #000000;
    padding-top: 1rem;
    max-width: 100%;
}

/* ── Sidebar ─────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background-color: #021105 !important;
    border-right: 1px dashed #1a5c2a !important;
}
[data-testid="stSidebar"] * {
    color: #4ADE80 !important;
}

/* ── Headers ─────────────────────────────────────────────── */
h1, h2, h3, h4 {
    color: #4ADE80 !important;
    font-family: 'JetBrains Mono', monospace !important;
    letter-spacing: 0.05em;
}
h1 { font-size: 1.6rem !important; font-weight: 700 !important; }
h2 { font-size: 1.2rem !important; font-weight: 600 !important; }
h3 { font-size: 1rem !important; font-weight: 500 !important; }

/* ── Streamlit metric labels ─────────────────────────────── */
[data-testid="stMetricLabel"] { color: #4ADE80 !important; }
[data-testid="stMetricValue"] { color: #4ADE80 !important; }

/* ── Cards / panels ──────────────────────────────────────── */
.terminal-card {
    background-color: #021105;
    border: 1px dashed #1a5c2a;
    border-radius: 12px;
    padding: 1rem 1.2rem;
    margin-bottom: 1rem;
}
.terminal-card-elevated {
    background-color: #05260D;
    border: 1px dashed #2a8c42;
    border-radius: 12px;
    padding: 1rem 1.2rem;
    margin-bottom: 1rem;
}
.approval-panel {
    background-color: #05260D;
    border: 1px solid #4ADE80;
    border-radius: 12px;
    padding: 1.2rem;
    margin: 0.8rem 0;
}

/* ── Status badges ───────────────────────────────────────── */
.badge {
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.05em;
}
.badge-not-checked  { background: #111; color: #666; border: 1px dashed #333; }
.badge-secure       { background: #012210; color: #4ADE80; border: 1px solid #4ADE80; }
.badge-vulnerable   { background: #2a0a00; color: #f97316; border: 1px solid #f97316; }
.badge-error        { background: #1a0000; color: #ef4444; border: 1px solid #ef4444; }
.badge-running      { background: #05260D; color: #86efac; border: 1px dashed #4ADE80; }
.badge-critical     { background: #3b0000; color: #ef4444; border: 1px solid #ef4444; }
.badge-high         { background: #2a1000; color: #f97316; border: 1px solid #f97316; }
.badge-medium       { background: #1a1a00; color: #FBBF24; border: 1px solid #FBBF24; }
.badge-low          { background: #001a1a; color: #22d3ee; border: 1px solid #22d3ee; }

/* ── Code blocks ─────────────────────────────────────────── */
code, pre {
    background-color: #010d04 !important;
    color: #86efac !important;
    border: 1px dashed #1a5c2a !important;
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.85rem !important;
}

/* ── Buttons ─────────────────────────────────────────────── */
.stButton > button {
    background-color: #021105 !important;
    color: #4ADE80 !important;
    border: 1px solid #4ADE80 !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.85rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.08em !important;
    padding: 0.4rem 1rem !important;
    transition: all 0.15s ease !important;
}
.stButton > button:hover {
    background-color: #4ADE80 !important;
    color: #000000 !important;
}
.stButton > button:hover * {
    color: #000000 !important;
}
.stButton > button:disabled {
    opacity: 0.35 !important;
    cursor: not-allowed !important;
}

/* ── Approve button override ─────────────────────────────── */
.approve-btn > button {
    border-color: #4ADE80 !important;
    color: #4ADE80 !important;
}
.approve-btn > button:hover {
    background-color: #4ADE80 !important;
    color: #000000 !important;
}
.approve-btn > button:hover * {
    color: #000000 !important;
}

/* ── Reject button override ──────────────────────────────── */
.reject-btn > button {
    border-color: #ef4444 !important;
    color: #ef4444 !important;
}
.reject-btn > button:hover {
    background-color: #ef4444 !important;
    color: #ffffff !important;
}
.reject-btn > button:hover * {
    color: #ffffff !important;
}

/* ── Tables (audit log) ──────────────────────────────────── */
[data-testid="stDataFrame"] {
    background-color: #021105 !important;
}
.dataframe {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.75rem !important;
}

/* ── Expander ────────────────────────────────────────────── */
[data-testid="stExpander"] {
    background-color: #021105 !important;
    border: 1px dashed #1a5c2a !important;
    border-radius: 8px !important;
}

/* ── Dividers ────────────────────────────────────────────── */
hr {
    border-color: #1a5c2a !important;
    border-style: dashed !important;
}

/* ── Text / labels ───────────────────────────────────────── */
p, label, span { color: #4ADE80; }
.dim { color: rgba(74, 222, 128, 0.5) !important; }

/* ── Sidebar parameter card ──────────────────────────────── */
.sidebar-card {
    background: #010d04;
    border: 1px dashed #1a5c2a;
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
    margin-bottom: 0.5rem;
    cursor: pointer;
}
.sidebar-card.active {
    border-color: #4ADE80;
    background: #021105;
}

/* ── Scrollbar ───────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #000; }
::-webkit-scrollbar-thumb { background: #1a5c2a; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session state initialisation
# ---------------------------------------------------------------------------
def _init_state():
    """Initialise per-parameter state dicts if they don't exist yet."""
    if "param_states" not in st.session_state:
        st.session_state.param_states = {}

    if "selected_param" not in st.session_state:
        st.session_state.selected_param = PARAMETERS[0]["id"]

    for p in PARAMETERS:
        pid = p["id"]
        if pid not in st.session_state.param_states:
            st.session_state.param_states[pid] = {
                "status": "not_checked",    # not_checked | running | secure | vulnerable | error
                "inspection": None,
                "analysis": None,
                "remediation": None,
                "safety": None,             # {"passed": bool, "reason": str | None}
                "execution": None,
                "verification": None,
                "human_decision": None,     # "approved" | "rejected" | None
                "error": None,
            }


_init_state()


# ---------------------------------------------------------------------------
# Helper: severity badge HTML
# ---------------------------------------------------------------------------
def _severity_badge(severity: str) -> str:
    cls_map = {
        "critical": "badge-critical",
        "high": "badge-high",
        "medium": "badge-medium",
        "low": "badge-low",
        "none": "badge-secure",
    }
    cls = cls_map.get(severity.lower(), "badge-not-checked")
    return f'<span class="badge {cls}">{severity.upper()}</span>'


def _status_badge(status: str) -> str:
    label_map = {
        "not_checked": "NOT CHECKED",
        "running": "RUNNING...",
        "secure": "SECURE",
        "vulnerable": "VULNERABLE",
        "error": "ERROR",
    }
    cls_map = {
        "not_checked": "badge-not-checked",
        "running": "badge-running",
        "secure": "badge-secure",
        "vulnerable": "badge-vulnerable",
        "error": "badge-error",
    }
    label = label_map.get(status, status.upper())
    cls = cls_map.get(status, "badge-not-checked")
    return f'<span class="badge {cls}">{label}</span>'


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

def stage_inspect(param: dict) -> None:
    """Run the inspector for the given parameter and update session state."""
    pid = param["id"]
    pstate = st.session_state.param_states[pid]

    pstate["status"] = "running"
    pstate["inspection"] = None
    pstate["analysis"] = None
    pstate["remediation"] = None
    pstate["safety"] = None
    pstate["execution"] = None
    pstate["verification"] = None
    pstate["human_decision"] = None
    pstate["error"] = None

    try:
        data = param["inspector"]()
    except Exception as exc:
        error_msg = f"Inspector raised an unexpected exception: {exc}"
        pstate["status"] = "error"
        pstate["error"] = error_msg
        log_event(pid, "inspect", "error", {"error": error_msg, "traceback": traceback.format_exc()})
        return

    pstate["inspection"] = data
    log_event(pid, "inspect", "success", {"inspection_data": data})

    if data.get("error"):
        pstate["status"] = "error"
        pstate["error"] = data["error"]
        log_event(pid, "inspect", "error", {"error": data["error"]})


def stage_analysis(param: dict) -> None:
    """Call LLM for vulnerability analysis and update session state."""
    pid = param["id"]
    pstate = st.session_state.param_states[pid]
    inspection_data = pstate.get("inspection")

    if not inspection_data:
        pstate["status"] = "error"
        pstate["error"] = "Cannot run analysis: no inspection data."
        return

    try:
        analysis = run_analysis(pid, inspection_data)
    except LLMError as exc:
        error_msg = f"LLM analysis failed: {exc}"
        pstate["status"] = "error"
        pstate["error"] = error_msg
        log_event(pid, "llm_analysis", "error", {"error": error_msg})
        return

    pstate["analysis"] = analysis
    is_vuln = analysis.get("is_vulnerable", False)
    pstate["status"] = "vulnerable" if is_vuln else "secure"
    log_event(pid, "llm_analysis", "vulnerable" if is_vuln else "secure", {"analysis": analysis})


def stage_remediation(param: dict) -> None:
    """Call LLM for remediation proposal, run safety check, update state."""
    pid = param["id"]
    pstate = st.session_state.param_states[pid]
    inspection_data = pstate.get("inspection")
    analysis = pstate.get("analysis")

    if not inspection_data or not analysis:
        pstate["error"] = "Cannot generate fix: missing inspection or analysis data."
        return

    # --- LLM Remediation call ---
    try:
        remediation = run_remediation(pid, inspection_data, analysis)
    except LLMError as exc:
        error_msg = f"LLM remediation failed: {exc}"
        pstate["error"] = error_msg
        log_event(pid, "llm_remediation", "error", {"error": error_msg})
        return

    pstate["remediation"] = remediation
    log_event(pid, "llm_remediation", "proposed", {"remediation": remediation})

    # --- Safety denylist check (mandatory, cannot be bypassed) ---
    cmd = remediation.get("remediation_command", "")
    passed, deny_reason = validate_command(cmd)
    pstate["safety"] = {"passed": passed, "reason": deny_reason}

    if passed:
        log_event(pid, "safety_check", "passed", {"command": cmd})
    else:
        log_event(pid, "safety_check", "blocked", {"command": cmd, "reason": deny_reason})


def stage_execute(param: dict) -> None:
    """Execute the approved command and immediately run verification."""
    pid = param["id"]
    pstate = st.session_state.param_states[pid]
    remediation = pstate.get("remediation")

    if not remediation:
        pstate["error"] = "Cannot execute: no remediation data."
        return

    cmd = remediation.get("remediation_command", "")

    if not is_elevated():
        error_msg = (
            "Execution blocked: this process is not running with Administrator "
            "privileges. Restart PowerShell/Streamlit as Administrator and retry."
        )
        pstate["status"] = "error"
        pstate["error"] = error_msg
        pstate["execution"] = {
            "stdout": "", "stderr": "", "returncode": -1, "error": error_msg,
        }
        log_event(pid, "execute", "blocked", {"command": cmd, "reason": error_msg})
        return

    log_event(pid, "execute", "started", {"command": cmd})

    exec_result = run_powershell(cmd)
    pstate["execution"] = exec_result

    if exec_result.get("error"):
        log_event(pid, "execute", "error", {"command": cmd, "result": exec_result})
    else:
        log_event(pid, "execute", "completed", {
            "command": cmd,
            "returncode": exec_result.get("returncode"),
            "stdout": exec_result.get("stdout", "")[:500],
        })

    # --- Verify ---
    stage_verify(param)


def stage_verify(param: dict) -> None:
    """Re-run the inspector and compare against the analysis to confirm the fix.

    Combines the existing LLM re-analysis (authoritative "verified" signal, kept
    fully dynamic per the project's no-hardcoded-logic requirement) with a new
    deterministic cross-check: the LLM-authored `verification_method` command from
    the remediation stage is executed (after passing the same mandatory safety
    denylist as the remediation command itself) and its raw output is surfaced to
    the operator alongside the LLM's verdict, for visual cross-reference.
    """
    pid = param["id"]
    pstate = st.session_state.param_states[pid]
    remediation = pstate.get("remediation")

    # Re-inspect
    try:
        new_data = param["inspector"]()
    except Exception as exc:
        pstate["verification"] = {"verified": False, "reason": f"Re-inspection failed: {exc}"}
        log_event(pid, "verify", "error", {"error": str(exc)})
        return

    # Run a new LLM analysis on the fresh data
    try:
        new_analysis = run_analysis(pid, new_data)
    except LLMError as exc:
        pstate["verification"] = {
            "verified": False,
            "reason": f"LLM re-analysis failed: {exc}",
            "new_inspection": new_data,
        }
        log_event(pid, "verify", "error", {"error": str(exc)})
        return

    still_vulnerable = new_analysis.get("is_vulnerable", True)
    verified = not still_vulnerable

    # --- Deterministic cross-check: execute the LLM's own verification_method ---
    deterministic_check = None
    verify_cmd = (remediation or {}).get("verification_method", "").strip()
    if verify_cmd:
        passed, deny_reason = validate_command(verify_cmd)
        if not passed:
            deterministic_check = {"skipped": True, "reason": deny_reason}
            log_event(pid, "deterministic_verify", "blocked", {
                "command": verify_cmd, "reason": deny_reason,
            })
        else:
            result = run_powershell(verify_cmd)
            deterministic_check = {
                "skipped": False,
                "command": verify_cmd,
                "stdout": result.get("stdout", "")[:500],
                "stderr": result.get("stderr", "")[:500],
                "returncode": result.get("returncode"),
                "error": result.get("error"),
            }
            log_event(pid, "deterministic_verify", "executed", {
                "command": verify_cmd,
                "returncode": result.get("returncode"),
                "stdout": result.get("stdout", "")[:500],
                "error": result.get("error"),
            })

    pstate["verification"] = {
        "verified": verified,
        "reason": new_analysis.get("current_state", ""),
        "new_inspection": new_data,
        "new_analysis": new_analysis,
        "deterministic_check": deterministic_check,
    }

    if verified:
        pstate["status"] = "secure"
        log_event(pid, "verify", "verified", {"new_analysis": new_analysis})
    else:
        pstate["status"] = "vulnerable"
        log_event(pid, "verify", "not_verified", {"new_analysis": new_analysis})


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
def render_sidebar():
    with st.sidebar:
        st.markdown("## 🛡 Parameters")
        st.markdown("---")

        for p in PARAMETERS:
            pid = p["id"]
            pstate = st.session_state.param_states[pid]
            status = pstate["status"]
            is_selected = st.session_state.selected_param == pid

            badge_html = _status_badge(status)
            card_class = "sidebar-card active" if is_selected else "sidebar-card"

            st.markdown(
                f'<div class="{card_class}">'
                f'<span style="font-size:0.8rem;font-weight:600;">{p["label"]}</span><br>'
                f'{badge_html}'
                f'</div>',
                unsafe_allow_html=True,
            )

            if st.button(f"Select {p['label']}", key=f"select_{pid}", use_container_width=True):
                st.session_state.selected_param = pid
                st.rerun()

        st.markdown("---")

        # Elevation indicator
        elevated = is_elevated()
        if elevated:
            st.markdown(
                '<span class="badge badge-secure">⚡ ADMINISTRATOR</span>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<span class="badge badge-error">⚠ NOT ELEVATED</span>',
                unsafe_allow_html=True,
            )
            st.caption("PowerShell commands require Administrator privileges.")


# ---------------------------------------------------------------------------
# Main panel
# ---------------------------------------------------------------------------
def render_header():
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown("# 🛡 AI Endpoint Security Hardening")
        st.markdown(
            '<span class="dim">Inspect → Analyse → Propose → Approve → Execute → Verify → Log</span>',
            unsafe_allow_html=True,
        )
    with col2:
        elevated = is_elevated()
        if elevated:
            st.markdown(
                '<div style="text-align:right;margin-top:1rem;">'
                '<span class="badge badge-secure">⚡ Administrator</span>'
                '</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div style="text-align:right;margin-top:1rem;">'
                '<span class="badge badge-error">⚠ Not Elevated</span>'
                '</div>',
                unsafe_allow_html=True,
            )
    st.markdown("---")


def render_parameter_panel(param: dict):
    pid = param["id"]
    pstate = st.session_state.param_states[pid]
    status = pstate["status"]

    # ── Card header ─────────────────────────────────────────────────────────
    st.markdown(
        f'<div class="terminal-card">'
        f'<span style="font-size:1.1rem;font-weight:700;">{param["label"]}</span>&nbsp;&nbsp;'
        f'{_status_badge(status)}<br>'
        f'<span class="dim" style="font-size:0.8rem;">{param["description"]}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ── Error state ──────────────────────────────────────────────────────────
    if pstate["error"] and status == "error":
        st.error(f"❌ Error: {pstate['error']}")
        st.markdown("---")

    # ── Inspect button ───────────────────────────────────────────────────────
    col_inspect, _ = st.columns([2, 5])
    with col_inspect:
        if st.button("▶ Run Inspection", key=f"inspect_{pid}", use_container_width=True):
            with st.spinner("Inspecting system state..."):
                stage_inspect(param)
            if st.session_state.param_states[pid]["status"] not in ("error",):
                with st.spinner("Analysing with AI..."):
                    stage_analysis(param)
            st.rerun()

    # ── Inspection results ───────────────────────────────────────────────────
    inspection = pstate.get("inspection")
    if inspection and not inspection.get("error"):
        with st.expander("🔍 Raw Inspection Data", expanded=False):
            st.code(
                json.dumps(inspection, indent=2, default=str),
                language="json",
            )

    # ── Analysis results ─────────────────────────────────────────────────────
    analysis = pstate.get("analysis")
    if analysis:
        sev = analysis.get("severity", "none")
        st.markdown(
            f'<div class="terminal-card-elevated">'
            f'<span style="font-weight:600;">AI Analysis</span>&nbsp;&nbsp;'
            f'{_severity_badge(sev)}<br><br>'
            f'<span class="dim">Current state: </span>{analysis.get("current_state", "")}<br><br>'
            f'<b>Explanation:</b><br>{analysis.get("explanation", "")}'
            f'</div>',
            unsafe_allow_html=True,
        )

        # ── Generate Fix button (only if vulnerable) ─────────────────────────
        if analysis.get("is_vulnerable") and pstate.get("remediation") is None:
            col_fix, _ = st.columns([2, 5])
            with col_fix:
                if st.button("🔧 Generate Fix", key=f"fix_{pid}", use_container_width=True):
                    with st.spinner("Generating AI remediation proposal..."):
                        stage_remediation(param)
                    st.rerun()

    # ── Remediation proposal ─────────────────────────────────────────────────
    remediation = pstate.get("remediation")
    safety = pstate.get("safety")

    if remediation:
        cmd = remediation.get("remediation_command", "")
        safety_passed = safety and safety.get("passed", False)
        deny_reason = safety.get("reason") if safety else None

        if not safety_passed:
            # Safety check failed — show error, do NOT offer approval
            st.markdown(
                f'<div class="terminal-card" style="border-color:#ef4444;">'
                f'<span style="color:#ef4444;font-weight:600;">🚫 SAFETY CHECK FAILED — Execution Blocked</span><br><br>'
                f'<span class="dim">Reason: </span>{deny_reason}<br><br>'
                f'<span class="dim">Proposed command:</span><br>'
                f'<code>{cmd}</code>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            # Safety passed — show approval panel
            human_decision = pstate.get("human_decision")

            if human_decision is None:
                # Pending approval
                st.markdown(
                    '<div class="approval-panel">'
                    '<span style="font-weight:700;font-size:1rem;">⏳ PENDING APPROVAL</span><br><br>',
                    unsafe_allow_html=True,
                )

                st.markdown("**Proposed command:**")
                st.code(cmd, language="powershell")

                col_exp, col_imp = st.columns(2)
                with col_exp:
                    st.markdown("**What it does:**")
                    st.markdown(
                        f'<span style="font-size:0.85rem;">{remediation.get("explanation", "")}</span>',
                        unsafe_allow_html=True,
                    )
                with col_imp:
                    st.markdown("**Possible impact:**")
                    st.markdown(
                        f'<span style="font-size:0.85rem;color:#FBBF24;">'
                        f'{remediation.get("possible_impact", "")}</span>',
                        unsafe_allow_html=True,
                    )

                st.markdown("**Verification method:**")
                st.code(remediation.get("verification_method", ""), language="powershell")

                st.markdown("</div>", unsafe_allow_html=True)
                st.markdown("")

                col_approve, col_reject, _ = st.columns([1, 1, 3])
                with col_approve:
                    if st.button("**[Y] Approve & Apply**", key=f"approve_{pid}", use_container_width=True):
                        pstate["human_decision"] = "approved"
                        log_event(pid, "human_decision", "approved", {"command": cmd})
                        with st.spinner("Executing fix..."):
                            stage_execute(param)
                        st.rerun()
                with col_reject:
                    if st.button("**[N] Reject**", key=f"reject_{pid}", use_container_width=True):
                        pstate["human_decision"] = "rejected"
                        pstate["status"] = "vulnerable"
                        log_event(pid, "human_decision", "rejected", {"command": cmd})
                        st.rerun()

            elif human_decision == "rejected":
                st.warning("❌ Fix rejected. No changes were made to the system.")
                # Allow re-generating
                if st.button("🔄 Re-generate Fix", key=f"regen_{pid}"):
                    pstate["remediation"] = None
                    pstate["safety"] = None
                    pstate["human_decision"] = None
                    st.rerun()

    # ── Execution result ─────────────────────────────────────────────────────
    execution = pstate.get("execution")
    if execution and pstate.get("human_decision") == "approved":
        with st.expander("📋 Execution Output", expanded=True):
            rc = execution.get("returncode", -1)
            if rc == 0:
                st.success(f"✅ Command exited with code {rc}")
            else:
                st.error(f"❌ Command exited with code {rc}")

            if execution.get("stdout"):
                st.markdown("**stdout:**")
                st.code(execution["stdout"], language="text")
            if execution.get("stderr"):
                st.markdown("**stderr:**")
                st.code(execution["stderr"], language="text")
            if execution.get("error"):
                st.error(f"Subprocess error: {execution['error']}")

    # ── Verification badge ───────────────────────────────────────────────────
    verification = pstate.get("verification")
    if verification:
        if verification.get("verified"):
            st.markdown(
                '<div style="margin:0.5rem 0;">'
                '<span class="badge badge-secure" style="font-size:0.9rem;">✅ VERIFIED — Fix confirmed</span>'
                '</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div style="margin:0.5rem 0;">'
                '<span class="badge badge-error" style="font-size:0.9rem;">❌ NOT VERIFIED — Manual review needed</span>'
                '</div>',
                unsafe_allow_html=True,
            )
        reason = verification.get("reason", "")
        if reason:
            st.caption(f"Re-check: {reason}")

        det_check = verification.get("deterministic_check")
        if det_check:
            with st.expander("🔬 Deterministic Cross-Check", expanded=False):
                if det_check.get("skipped"):
                    st.warning(
                        f"Skipped — verification_method blocked by safety denylist: "
                        f"{det_check.get('reason')}"
                    )
                else:
                    st.markdown("**Command:**")
                    st.code(det_check.get("command", ""), language="powershell")
                    if det_check.get("stdout"):
                        st.markdown("**Output:**")
                        st.code(det_check["stdout"], language="text")
                    if det_check.get("stderr"):
                        st.markdown("**stderr:**")
                        st.code(det_check["stderr"], language="text")
                    if det_check.get("error"):
                        st.error(f"Subprocess error: {det_check['error']}")


# ---------------------------------------------------------------------------
# Audit log panel
# ---------------------------------------------------------------------------
def render_audit_log():
    st.markdown("---")
    with st.expander("📜 Live Audit Log", expanded=False):
        events = read_events(max_entries=100)

        if not events:
            st.markdown('<span class="dim">No audit events yet.</span>', unsafe_allow_html=True)
            return

        # Build display table
        rows = []
        for ev in events:
            ts = ev.get("timestamp", "")
            if ts:
                try:
                    # Format as local time for readability
                    from datetime import timezone
                    dt = datetime.fromisoformat(ts)
                    ts = dt.strftime("%H:%M:%S")
                except Exception:
                    ts = ts[:19]

            rows.append({
                "Time": ts,
                "Parameter": ev.get("parameter", "—"),
                "Stage": ev.get("stage", "—"),
                "Result": ev.get("result", "—"),
            })

        # Display as a simple HTML table for monospace styling
        header = "| Time | Parameter | Stage | Result |"
        divider = "|------|-----------|-------|--------|"
        table_rows = "\n".join(
            f"| {r['Time']} | {r['Parameter']} | {r['Stage']} | {r['Result']} |"
            for r in rows
        )
        st.markdown(
            f"```\n{header}\n{divider}\n{table_rows}\n```",
        )

        st.caption(f"Showing {len(events)} most recent entries. Full log: logs/audit_log.jsonl")


# ---------------------------------------------------------------------------
# Main layout
# ---------------------------------------------------------------------------
def main():
    render_sidebar()
    render_header()

    # Find the currently selected parameter
    selected_id = st.session_state.get("selected_param", PARAMETERS[0]["id"])
    selected_param = next((p for p in PARAMETERS if p["id"] == selected_id), PARAMETERS[0])

    render_parameter_panel(selected_param)
    render_audit_log()


if __name__ == "__main__":
    main()
