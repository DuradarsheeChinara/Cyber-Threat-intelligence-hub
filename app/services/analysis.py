"""Bridge the existing AI pipeline to persisted API threat records."""
from __future__ import annotations

from typing import Any

from backend.ai.classifier import classify
from backend.ai.embeddings import generate_embedding
from backend.ai.summarizer import summarize
from backend.services.risk_engine import (
    CLASSIFICATION_WEIGHT,
    CVSS_WEIGHT,
    KEV_WEIGHT,
    _normalize_cvss,
    _score_classification,
    calculate_risk,
)


def run_analysis(threat: dict[str, Any]) -> dict[str, Any]:
    """Execute the project's Gemini, classifier, embedding and risk services."""
    summary = summarize(threat)
    if summary.startswith("Summary unavailable:"):
        raise RuntimeError(summary)
    classification = classify(summary)
    embedding = generate_embedding(summary)
    risk = calculate_risk(threat, classification)
    return {
        "ai_summary": summary,
        "threat_category": classification["category"],
        "classification_confidence": classification["confidence"],
        "embedding": embedding,
        "embedding_dimensions": len(embedding),
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "risk_breakdown": {
            "cvss_normalized": _normalize_cvss(threat.get("cvss")),
            "cvss_weight": CVSS_WEIGHT,
            "kev_flag": bool(threat.get("kev", False)),
            "kev_weight": KEV_WEIGHT,
            "classification_score": _score_classification(classification),
            "classification_weight": CLASSIFICATION_WEIGHT,
        },
    }
