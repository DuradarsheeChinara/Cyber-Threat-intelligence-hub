"""Zero-shot vulnerability classification service."""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Protocol, cast

from dotenv import load_dotenv
from transformers import pipeline

logger = logging.getLogger(__name__)

CATEGORIES = [
    "Remote Code Execution",
    "SQL Injection",
    "Cross Site Scripting",
    "Privilege Escalation",
    "Denial of Service",
    "Information Disclosure",
    "Authentication Bypass",
    "Buffer Overflow",
    "Malware",
    "Other",
]
DEFAULT_CLASSIFICATION_MODEL = "facebook/bart-large-mnli"
DEFAULT_CLASSIFICATION = {"category": "Other", "confidence": 0.0}

_classifier: "ZeroShotClassifier | None" = None
_classifier_lock = threading.Lock()


class ZeroShotClassifier(Protocol):
    """Protocol for the Hugging Face zero-shot classification pipeline."""

    def __call__(
        self,
        sequences: str,
        candidate_labels: list[str],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Classify text against candidate labels."""


def _get_classifier() -> ZeroShotClassifier:
    """Load and cache the zero-shot classification model safely."""
    global _classifier

    if _classifier is None:
        with _classifier_lock:
            if _classifier is None:
                load_dotenv()
                model_name = os.getenv(
                    "CLASSIFICATION_MODEL",
                    DEFAULT_CLASSIFICATION_MODEL,
                )
                logger.info(
                    "Loading zero-shot classification model: %s",
                    model_name,
                )
                _classifier = cast(
                    ZeroShotClassifier,
                    pipeline("zero-shot-classification", model=model_name),
                )

    return _classifier


def classify(summary: str) -> dict[str, float | str]:
    """Classify a threat summary into a cybersecurity attack category."""
    if not summary or not summary.strip():
        logger.warning("Received empty summary for classification.")
        return DEFAULT_CLASSIFICATION.copy()

    try:
        logger.info("Starting threat classification.")
        result = _get_classifier()(
            summary,
            candidate_labels=CATEGORIES,
            multi_label=False,
        )
        labels = result.get("labels", [])
        scores = result.get("scores", [])

        if not labels or not scores:
            logger.warning("Classifier returned no labels or scores.")
            return DEFAULT_CLASSIFICATION.copy()

        classification = {
            "category": str(labels[0]),
            "confidence": round(float(scores[0]), 4),
        }
        logger.info(
            "Classification completed: %s (confidence %.4f).",
            classification["category"],
            classification["confidence"],
        )
        return classification
    except Exception as exc:
        logger.exception("Threat classification failed: %s", exc)
        return DEFAULT_CLASSIFICATION.copy()
