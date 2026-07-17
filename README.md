# 🛡 AI-Powered Endpoint Security Hardening Tool

> A Proof-of-Concept defensive hardening tool for Windows endpoints.  
> Inspects system security settings, uses an LLM to diagnose vulnerabilities and propose remediations, requires explicit human approval before any change, executes the approved fix, verifies it, and logs every step.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Streamlit Dashboard (app.py)                  │
│  Sidebar: 4 parameter cards + elevation status                       │
│  Main panel: Inspect → Analysis → Approval Gate → Execute → Verify   │
│  Bottom: Collapsible live audit log (logs/audit_log.jsonl)           │
└────────────────────────────┬────────────────────────────────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
   ┌───────────┐      ┌───────────┐      ┌───────────────┐
   │inspectors/│      │   llm/    │      │   safety/     │
   │  4 modules│      │ client.py │      │ denylist.py   │
   │ each runs │      │ analysis_ │      │ Pattern-based │
   │PowerShell │      │ prompts.py│      │ regex filter  │
   │ via subpr.│      │ remediat_ │      │ (mandatory,   │
   └─────┬─────┘      │ prompts.py│      │ unbypassable) │
         │            └─────┬─────┘      └───────────────┘
         │                  │
         ▼                  ▼
   ┌───────────┐      ┌───────────┐
   │execution/ │      │ logging/  │
   │executor.py│      │audit_log  │
   │subprocess │      │ger.py     │
   │+ elevation│      │JSONL file │
   │  check    │      │one line/  │
   └───────────┘      │  event    │
                      └───────────┘
```

### Pipeline (per parameter)

```
1. Inspect      PowerShell reads raw system state → structured dict
2. LLM Analysis Send state + baseline to Groq → {is_vulnerable, severity, explanation}
3. LLM Fix      If vulnerable, ask Groq for remediation → {command, explanation, impact, verify}
4. Safety Check Regex denylist validates command (mandatory, cannot be bypassed)
5. Human Gate   Display everything in UI → operator clicks [Y] Approve or [N] Reject
6. Execute      subprocess.run(powershell ...) on Approve only
7. Verify       Re-inspect + re-analyse → Verified / Not Verified badge
8. Log          Append JSON to logs/audit_log.jsonl after EVERY stage
```

---

## The 4 Inspected Parameters

| # | Parameter | Why it matters |
|---|-----------|----------------|
| 1 | **Firewall Rules — Any remote address** | An enabled inbound-allow rule with `RemoteAddress=Any` exposes a port to the entire internet. Even "harmless" services become attack surface. |
| 2 | **Firewall Profiles — Enabled state** | Disabling the Public or Domain profile removes the host-based firewall entirely for that network type, defeating a critical defence layer. |
| 3 | **Password Policy — Minimum length** | A minimum of 0 allows blank passwords; below 14 characters enables offline brute-force in seconds on modern hardware. CIS/NIST require ≥14. |
| 4 | **Audit Policy — Logon auditing** | Without both Success and Failure auditing, the Security event log is blind to credential attacks (brute force, pass-the-hash, account takeover). |

---

## Setup

### Prerequisites

- Windows 10/11 or Windows Server 2019+
- Python 3.11+
- PowerShell 5.1+ (built into Windows)
- A [Groq API key](https://console.groq.com/keys) (free tier is sufficient)

### 1 — Clone and install dependencies

```powershell
git clone <your-repo-url>
cd security-hardening-poc
pip install -r requirements.txt
```

### 2 — Configure your API key

```powershell
Copy-Item .env.example .env
# Open .env in any editor and set:
#   GROQ_API_KEY=gsk_...your_key_here...
```

### 3 — Run as Administrator

**This is required** — PowerShell commands that read/write firewall rules and audit policy need elevation.

```powershell
# Right-click PowerShell → "Run as Administrator", then:
streamlit run app.py
```

The UI shows a `⚡ ADMINISTRATOR` badge in the header and sidebar when elevated correctly. If you see `⚠ NOT ELEVATED`, restart the terminal as Administrator.

---

## Live Demo Guide

### Step 1 — Break the settings (creates real vulnerabilities)

```powershell
# As Administrator:
.\demo_setup\break_state.ps1
```

This script intentionally:
- Creates an inbound firewall rule with `RemoteAddress=Any` on TCP/8888
- Disables the Public firewall profile
- Sets minimum password length to 0
- Disables Logon auditing entirely

### Step 2 — Run the tool

```powershell
streamlit run app.py
```

Walk through each of the 4 parameter cards:
1. Click **▶ Run Inspection** — the tool inspects and the AI analyses in real time.
2. If vulnerable, click **🔧 Generate Fix** — the AI proposes a PowerShell command.
3. Review the command, explanation, and possible impact.
4. Click **[Y] Approve & Apply** to execute — or **[N] Reject** to log without applying.
5. The tool re-inspects and shows a **✅ VERIFIED** or **❌ NOT VERIFIED** badge.

### Step 3 — Reset after demo

```powershell
.\demo_setup\restore_state.ps1
```

This restores all 4 settings to secure defaults.

---

## Project Structure

```
security-hardening-poc/
├── app.py                          # Streamlit entrypoint, UI + pipeline orchestration
├── inspectors/
│   ├── firewall_rules.py           # Get-NetFirewallRule + address filter
│   ├── firewall_profiles.py        # Get-NetFirewallProfile
│   ├── password_policy.py          # net accounts → min password length
│   └── audit_policy.py             # auditpol /get /subcategory:"Logon"
├── llm/
│   ├── client.py                   # Groq API adapter (swap provider here)
│   ├── analysis_prompts.py         # Stage 1: is it vulnerable + severity
│   └── remediation_prompts.py      # Stage 2: propose the fix command
├── safety/
│   └── denylist.py                 # Mandatory regex denylist (unbypassable)
├── execution/
│   └── executor.py                 # subprocess wrapper + elevation check
├── logging/
│   └── audit_logger.py             # Append-only JSONL event logger
├── demo_setup/
│   ├── break_state.ps1             # Intentional misconfigurations (demo only)
│   └── restore_state.ps1           # Restore to secure state after demo
├── logs/
│   └── audit_log.jsonl             # Runtime-generated audit log
├── .env.example                    # API key template
├── requirements.txt
└── README.md
```

---

## Key Design Decisions

### No hardcoded remediation logic

The application code contains **zero** hardcoded mappings from "vulnerability X → fix command Y". The inspectors collect raw system state; the LLM is given a description of the secure baseline and decides at runtime whether the state is vulnerable and what the exact fix command should be.

This means:
- The tool adapts to system-specific state (e.g., which exact firewall rule to address)
- The reasoning is transparent and auditable (the LLM explains its findings)
- Swapping to a different/better model (GPT-4o, Claude, local Llama) requires changing one env var

### Two-stage LLM calls (Analysis then Remediation)

We deliberately split these into two calls with different schemas:
- **Analysis** — smaller, faster, focused on: is it vulnerable and how severe?
- **Remediation** — called only if vulnerable, focused on: what exact command fixes it?

This keeps each schema small and validation deterministic. It also means a "not vulnerable" result never wastes tokens on remediation.

### Mandatory safety denylist

The denylist in `safety/denylist.py` runs between LLM output and execution. It uses case-insensitive regex to block patterns like `Remove-Item`, `Format-`, `shutdown`, `Restart-Computer`, `Invoke-Expression`, wholesale firewall disable, and others.

This layer **cannot be bypassed** — not by a human approver, not by restarting the app, not by the LLM. If a command trips the denylist, execution is blocked and the reason is shown and logged.

### Audit log design

Every pipeline stage appends one JSON line to `logs/audit_log.jsonl`:
- Timestamp (ISO-8601 UTC)
- Parameter name
- Stage name
- Result string
- Optional extra fields (inspection data, commands, LLM responses, error messages)

This creates a complete forensic trail even for failed or rejected operations.

---

## Switching the LLM Provider

The `llm/client.py` module is the only place that touches the Groq SDK. To swap providers:

1. Install the new SDK (`pip install openai`, `pip install anthropic`, etc.)
2. Replace the `_get_client()` and `call()` functions in `llm/client.py`
3. Keep the same return contract: `call(messages) -> dict`

The prompts, schema validation, and rest of the pipeline are provider-agnostic.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `⚠ NOT ELEVATED` badge | Restart PowerShell as Administrator and re-run `streamlit run app.py` |
| `GROQ_API_KEY is not set` | Ensure `.env` exists (copied from `.env.example`) with a valid key |
| `powershell.exe not found` | Ensure you're running on Windows with PowerShell in your PATH |
| LLM returns `Analysis failed` | Usually a transient API error — click Run Inspection again to retry |
| Audit log empty | Check that `logs/` directory exists and the process has write permission |
