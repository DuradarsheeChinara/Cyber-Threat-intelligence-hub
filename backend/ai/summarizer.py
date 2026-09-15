"""Gemini-powered threat summarization service."""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google import genai
from google.genai import types

logger = logging.getLogger(__name__)

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "summary.txt"
DEFAULT_GEMINI_MODEL = "gemini-3.6-flash"
REQUEST_TIMEOUT_MILLISECONDS = 60_000
RETIRED_GEMINI_MODELS = {
    "gemini-2.5-flash",
    "gemini-1.5-flash",
    "gemini-1.5-flash-latest",
    "gemini-1.5-pro",
    "gemini-1.5-pro-latest",
}
DEFAULT_SUMMARY_PROMPT = (
    "Summarize the following cyber threat for a security analyst. "
    "Keep it concise, factual, and focused on impact, exploitation, "
    "affected technology, and urgency."
)

_client: genai.Client | None = None
_client_api_key: str | None = None
_client_lock = threading.Lock()
_prompt_template: str | None = None
_prompt_lock = threading.Lock()


class SummarizationError(RuntimeError):
    """Raised when Gemini cannot generate a threat summary."""


def _load_prompt() -> str:
    """Load and cache the analyst summary prompt from disk."""
    global _prompt_template

    if _prompt_template is None:
        with _prompt_lock:
            if _prompt_template is None:
                try:
                    prompt = PROMPT_PATH.read_text(encoding="utf-8").strip()
                except OSError as exc:
                    logger.warning(
                        "Unable to read summary prompt from %s: %s",
                        PROMPT_PATH,
                        exc,
                    )
                    prompt = ""

                _prompt_template = prompt or DEFAULT_SUMMARY_PROMPT

    return _prompt_template


def _format_threat(threat: dict[str, Any]) -> str:
    """Convert a threat object into compact text for the model."""
    fields = {
        "ID": threat.get("id", "Unknown"),
        "Title": threat.get("title", "Unknown"),
        "Vendor": threat.get("vendor", "Unknown"),
        "Product": threat.get("product", "Unknown"),
        "Description": threat.get("description", "No description provided."),
        "CVSS": threat.get("cvss", "Unknown"),
        "Known Exploited Vulnerability": threat.get("kev", False),
        "Published": threat.get("published", "Unknown"),
    }
    return "\n".join(f"{label}: {value}" for label, value in fields.items())


def _build_prompt(threat: dict[str, Any]) -> str:
    """Build the final Gemini prompt using the configured template."""
    return f"{_load_prompt()}\n\nThreat details:\n{_format_threat(threat)}"


def _create_client(api_key: str) -> genai.Client:
    """Create and cache a Gemini client using the configured API key."""
    global _client, _client_api_key

    if _client is None or _client_api_key != api_key:
        with _client_lock:
            if _client is None or _client_api_key != api_key:
                logger.info("Initializing Gemini client.")
                _client = genai.Client(
                    api_key=api_key,
                    http_options=types.HttpOptions(
                        timeout=REQUEST_TIMEOUT_MILLISECONDS,
                    ),
                )
                _client_api_key = api_key

    return _client


def _resolve_model() -> str:
    """Resolve the Gemini model, avoiding retired model names."""
    configured_model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)

    if configured_model in RETIRED_GEMINI_MODELS:
        logger.warning(
            "Configured Gemini model %s is retired; using %s instead.",
            configured_model,
            DEFAULT_GEMINI_MODEL,
        )
        return DEFAULT_GEMINI_MODEL

    return configured_model


def _extract_summary(response: Any) -> str:
    """Extract generated summary text from a Gemini response."""
    summary = getattr(response, "text", None)

    if not isinstance(summary, str) or not summary.strip():
        raise SummarizationError("Gemini response did not include summary text.")

    return summary.strip()


def summarize(threat: dict[str, Any]) -> str:
    """Return a concise cybersecurity analyst summary for a threat object.

    The Gemini API key is loaded from the ``GEMINI_API_KEY`` environment
    variable. A model can optionally be configured with ``GEMINI_MODEL``.
    """
    load_dotenv()

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        logger.error("GEMINI_API_KEY is not configured.")
        return "Summary unavailable: Gemini API key is not configured."

    model = _resolve_model()
    threat_id = threat.get("id", "unknown")

    try:
        logger.info("Starting summary generation for threat %s.", threat_id)
        client = _create_client(api_key)
        response = client.models.generate_content(
            model=model,
            contents=_build_prompt(threat),
        )
        summary = _extract_summary(response)
        logger.info("Summary generated for threat %s.", threat_id)
        return summary
    except SummarizationError as exc:
        logger.exception("Gemini response parsing failed: %s", exc)
    except Exception as exc:
        logger.exception(
            "Gemini summarization failed for threat %s: %s",
            threat_id,
            exc,
        )

    return "Summary unavailable: Gemini API request failed."
