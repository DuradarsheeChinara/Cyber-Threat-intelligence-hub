"""Tests for the CTI Hub rule-based risk engine."""

from __future__ import annotations

from backend.services.risk_engine import calculate_risk


def test_low_risk_score_range() -> None:
    """Low risk threats should score below 40."""
    risk = calculate_risk(
        {"id": "LOW-1", "cvss": 1.0, "kev": False},
        {"category": "Other", "confidence": 0.1},
    )

    assert risk["risk_level"] == "Low"
    assert 0 <= risk["risk_score"] < 40


def test_medium_risk_score_range() -> None:
    """Medium risk threats should score from 40 through 69."""
    risk = calculate_risk(
        {"id": "MED-1", "cvss": 6.1, "kev": False},
        {"category": "Information Disclosure", "confidence": 0.3},
    )

    assert risk["risk_level"] == "Medium"
    assert 40 <= risk["risk_score"] < 70


def test_high_risk_score_range() -> None:
    """High risk threats should score from 70 through 89."""
    risk = calculate_risk(
        {"id": "HIGH-1", "cvss": 8.6, "kev": True},
        {"category": "Authentication Bypass", "confidence": 0.9},
    )

    assert risk["risk_level"] == "High"
    assert 70 <= risk["risk_score"] < 90


def test_critical_risk_score_range() -> None:
    """Critical risk threats should score from 90 through 100."""
    risk = calculate_risk(
        {"id": "CRIT-1", "cvss": 9.8, "kev": True},
        {"category": "Remote Code Execution", "confidence": 0.95},
    )

    assert risk["risk_level"] == "Critical"
    assert 90 <= risk["risk_score"] <= 100
