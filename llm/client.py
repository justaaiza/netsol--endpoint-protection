"""
LLM Client — Groq API adapter.

Design decisions:
- Exposes a single `call(messages, schema_name)` function; callers never touch the
  Groq SDK directly. This makes swapping the provider a one-file change.
- Uses Groq's JSON mode (`response_format={"type": "json_object"}`) to guarantee
  structured output. We never free-text-parse the model's response.
- Retry-once on JSON decode errors, then raise LLMError so the UI can show a
  graceful "Analysis failed" state without crashing.
- The model name is read from GROQ_MODEL env var so it can be overridden without
  code changes (useful for testing with smaller/faster models).
"""

import json
import os
from dotenv import load_dotenv

# Load .env from project root (two levels up from this file)
from pathlib import Path
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH)


class LLMError(Exception):
    """Raised when the LLM call fails or returns unparseable output."""


def _get_client():
    """Lazily instantiate the Groq client so import-time errors are surfaced cleanly."""
    try:
        from groq import Groq  # noqa: PLC0415
    except ImportError as exc:
        raise LLMError(
            "groq package not installed. Run: pip install groq"
        ) from exc

    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        raise LLMError(
            "GROQ_API_KEY is not set. "
            "Copy .env.example to .env and add your key."
        )
    return Groq(api_key=api_key)


# Default model — Llama 3.3 70B Versatile is the primary choice per spec.
_DEFAULT_MODEL = "llama-3.3-70b-versatile"


def call(messages: list[dict], max_tokens: int = 1024) -> dict:
    """
    Send a chat-completion request to the Groq API and return a parsed JSON dict.

    Args:
        messages:   OpenAI-style list of {"role": "...", "content": "..."} dicts.
        max_tokens: Maximum tokens in the completion.

    Returns:
        Parsed dict from the model's JSON response.

    Raises:
        LLMError: If the API call fails, times out, or returns non-JSON output
                  after one retry.
    """
    model = os.getenv("GROQ_MODEL", _DEFAULT_MODEL).strip()
    client = _get_client()

    def _attempt() -> dict:
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                # JSON mode guarantees the model returns valid JSON
                response_format={"type": "json_object"},
                temperature=0.1,   # Low temperature for deterministic, consistent output
            )
            raw = response.choices[0].message.content
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LLMError(f"LLM returned non-JSON output: {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            # Catch Groq API errors (rate limits, network, auth) and surface cleanly
            raise LLMError(f"Groq API error: {exc}") from exc

    # First attempt
    try:
        return _attempt()
    except LLMError:
        pass  # Fall through to retry

    # One retry
    try:
        return _attempt()
    except LLMError as exc:
        raise LLMError(
            f"LLM call failed after retry. Manual review required. Detail: {exc}"
        ) from exc
