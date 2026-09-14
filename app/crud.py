from sqlalchemy.orm import Session
from typing import Any
from . import models, schemas

def create_threat(db: Session, threat: schemas.ThreatCreate):
    db_threat = models.Threat(**threat.model_dump())
    db.add(db_threat)
    db.commit()
    db.refresh(db_threat)
    return db_threat

def get_threat(db: Session, threat_id: str):
    return db.query(models.Threat).filter(models.Threat.id == threat_id).first()

def create_ai_analysis(db: Session, threat_id: str, ai_result: dict):
    db_analysis = models.AIAnalysis(
        threat_id=threat_id,
        ai_summary=ai_result["ai_summary"],
        threat_category=ai_result["threat_category"],
        risk_score=ai_result["risk_score"],
        risk_level=ai_result.get("risk_level"),
        classification_confidence=ai_result.get("classification_confidence"),
        embedding=ai_result.get("embedding"),
        embedding_dimensions=ai_result.get("embedding_dimensions"),
        risk_breakdown=ai_result.get("risk_breakdown"),
    )
    db.add(db_analysis)
    db.commit()
    db.refresh(db_analysis)
    return db_analysis

def latest_analysis(db: Session, threat_id: str):
    return (db.query(models.AIAnalysis)
        .filter(models.AIAnalysis.threat_id == threat_id)
        .order_by(models.AIAnalysis.generated_at.desc(), models.AIAnalysis.id.desc()).first())

def update_threat(db: Session, threat: models.Threat, values: dict[str, Any]):
    for field, value in values.items():
        if value is not None:
            setattr(threat, field, value)
    db.commit()
    db.refresh(threat)
    return threat

def delete_threat(db: Session, threat: models.Threat) -> None:
    db.query(models.AIAnalysis).filter(models.AIAnalysis.threat_id == threat.id).delete()
    db.delete(threat)
    db.commit()
