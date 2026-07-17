"""
Execution layer — PowerShell subprocess wrapper and elevation check.

Design decisions:
- All PowerShell is run with -NonInteractive so it never prompts for input.
- stdout and stderr are captured separately; the caller sees both.
- We never raise from run_powershell; errors are returned in the dict
  so callers can log them consistently without scattered try/except.
- is_elevated() uses ctypes on Windows; on other platforms it returns False
  with a warning (the tool only makes sense on Windows anyway).
"""

import subprocess
import ctypes
import sys


def is_elevated() -> bool:
    """
    Return True if the current process is running with Administrator privileges.
    Only meaningful on Windows; returns False on other platforms.
    """
    if sys.platform != "win32":
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_powershell(command: str, timeout: int = 60) -> dict:
    """
    Execute a PowerShell command and return structured results.

    Args:
        command: The PowerShell command string (or script block) to run.
        timeout: Maximum seconds to wait before forcibly killing the process.

    Returns a dict with keys:
        stdout     (str)  : Captured standard output
        stderr     (str)  : Captured standard error
        returncode (int)  : Process exit code (0 = success)
        error      (str | None) : Human-readable error if subprocess itself failed
                                  (not if the PowerShell command failed).
    """
    # Build the PowerShell invocation.
    # -NonInteractive: prevents prompts that would hang the process.
    # -NoProfile:      faster startup, avoids user profile side-effects.
    # -ExecutionPolicy Bypass: allows inline scripts without system-level policy changes.
    ps_args = [
        "powershell",
        "-NonInteractive",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", command,
    ]

    try:
        proc = subprocess.run(
            ps_args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",   # avoid codec errors from unusual output
        )
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "",
            "returncode": -1,
            "error": f"PowerShell command timed out after {timeout}s.",
        }
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": "",
            "returncode": -1,
            "error": (
                "powershell.exe not found. "
                "This tool must run on a Windows system with PowerShell installed."
            ),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "stdout": "",
            "stderr": "",
            "returncode": -1,
            "error": f"Unexpected subprocess error: {exc}",
        }
