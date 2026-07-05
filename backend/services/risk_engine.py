"""Rule-based cyber threat risk scoring engine."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

CVSS_WEIGHT = 0.65
KEV_WEIGHT = 0.20
CLASSIFICATION_WEIGHT = 0.15

CLASSIFICATION_IMPACT = {
    "Remote Code Execution": 100,
    "Authentication Bypass": 90,
    "Privilege Escalation": 85,
    "SQL Injection": 80,
    "Buffer Overflow": 80,
    "Malware": 80,
    "Information Disclosure": 65,
    "Denial of Service": 60,
    "Cross Site Scripting": 55,
    "Other": 40,
}


def _normalize_cvss(cvss: Any) -> float:
    """Convert a CVSS value from 0-10 into a 0-100 score."""
    try:
        value = float(cvss)
    except (TypeError, ValueError):
        logger.warning("Invalid CVSS value received: %s", cvss)
        return 0.0

    return max(0.0, min(value, 10.0)) * 10.0


def _score_kev(kev: Any) -> float:
    """Return the risk contribution for known exploited vulnerabilities."""
    return 100.0 if bool(kev) else 0.0


def _score_classification(classification: dict[str, Any]) -> float:
    """Return risk contribution based on attack category and confidence."""
    category = str(classification.get("category", "Other"))
    confidence = classification.get("confidence", 0.0)

    try:
        confidence_value = float(confidence)
    except (TypeError, ValueError):
        logger.warning("Invalid classification confidence: %s", confidence)
        confidence_value = 0.0

    confidence_value = max(0.0, min(confidence_value, 1.0))
    base_score = CLASSIFICATION_IMPACT.get(
        category,
        CLASSIFICATION_IMPACT["Other"],
    )
    return base_score * confidence_value


def _risk_level(score: int) -> str:
    """Map a 0-100 risk score to a business-friendly risk level."""
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def calculate_risk(
    threat: dict[str, Any],
    classification: dict[str, Any],
) -> dict[str, int | str]:
    """Calculate a weighted risk score for a threat.

    The formula is intentionally split into feature scoring helpers so future
    inputs such as EPSS, exploit maturity, and asset criticality can be added
    without changing the public function signature.
    """
    cvss_score = _normalize_cvss(threat.get("cvss"))
    kev_score = _score_kev(threat.get("kev", False))
    classification_score = _score_classification(classification)

    weighted_score = (
        cvss_score * CVSS_WEIGHT
        + kev_score * KEV_WEIGHT
        + classification_score * CLASSIFICATION_WEIGHT
    )
    risk_score = int(round(max(0.0, min(weighted_score, 100.0))))

    risk = {
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
    }
    logger.info(
        "Risk calculated for threat %s: %s.",
        threat.get("id", "unknown"),
        risk,
    )
    return risk
