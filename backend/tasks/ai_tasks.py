"""Celery tasks for the CTI Hub AI processing pipeline."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from celery import Celery
from dotenv import load_dotenv

from backend.ai.classifier import classify
from backend.ai.embeddings import generate_embedding
from backend.ai.summarizer import summarize
from backend.mock_data.sample_threats import sample_threats
from backend.services.risk_engine import calculate_risk

load_dotenv()

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "output"
OUTPUT_FILE = OUTPUT_DIR / "processed_threats.json"

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv(
    "CELERY_RESULT_BACKEND",
    CELERY_BROKER_URL,
)

celery_app = Celery(
    "cti_hub_ai_tasks",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
)


def _write_processed_threats(results: list[dict[str, Any]]) -> None:
    """Write processed threat results to a JSON file."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(results, indent=4),
        encoding="utf-8",
    )
    logger.info("Processed threats exported to %s.", OUTPUT_FILE)


def process_sample_threats() -> list[dict[str, Any]]:
    """Run the complete AI and risk pipeline for mock threat data."""
    results: list[dict[str, Any]] = []
    logger.info("AI pipeline processing started for %d threats.", len(sample_threats))

    for threat in sample_threats:
        threat_id = threat.get("id", "unknown")
        logger.info("Processing started for threat %s.", threat_id)

        try:
            summary = summarize(threat)
            logger.info("Summary generated for threat %s.", threat_id)
            classification = classify(summary)
            logger.info("Classification completed for threat %s.", threat_id)
            embedding = generate_embedding(summary)
            logger.info(
                "Embedding generated for threat %s with %d dimensions.",
                threat_id,
                len(embedding),
            )
            risk = calculate_risk(threat, classification)
            logger.info("Risk calculated for threat %s.", threat_id)

            result = {
                "threat_id": threat_id,
                "summary": summary,
                "classification": classification,
                "embedding_dimensions": len(embedding),
                "risk": risk,
            }
            results.append(result)
            logger.info("Processing completed for threat %s.", threat_id)
        except Exception as exc:
            logger.exception("AI pipeline failed for threat %s: %s", threat_id, exc)
            results.append(
                {
                    "threat_id": threat_id,
                    "error": str(exc),
                }
            )

    _write_processed_threats(results)
    logger.info("AI pipeline processing completed.")
    return results


@celery_app.task(name="backend.tasks.ai_tasks.process_threat_task")
def process_threat_task(threat_id: str) -> dict[str, Any]:
    """Process one persisted API threat without blocking its HTTP request."""
    from app import crud
    from app.database import Base, SessionLocal, engine
    from app.services.analysis import run_analysis

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        threat = crud.get_threat(db, threat_id)
        if threat is None:
            logger.warning("Threat %s disappeared before AI processing.", threat_id)
            return {"threat_id": threat_id, "status": "not_found"}
        payload = {
            "id": threat.id, "title": threat.title, "vendor": threat.vendor,
            "product": threat.product, "description": threat.description,
            "cvss": float(threat.cvss) if threat.cvss is not None else None,
            "kev": threat.kev, "published": str(threat.published) if threat.published else None,
        }
        result = run_analysis(payload)
        crud.create_ai_analysis(db, threat_id, result)
        return {"threat_id": threat_id, "status": "completed", "risk": result["risk_score"]}
    except Exception as exc:
        logger.exception("AI pipeline failed for persisted threat %s: %s", threat_id, exc)
        return {"threat_id": threat_id, "status": "failed", "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="backend.tasks.ai_tasks.process_sample_threats_task")
def process_sample_threats_task() -> list[dict[str, Any]]:
    """Celery task entry point for the sample threat AI pipeline."""
    return process_sample_threats()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    process_sample_threats()
