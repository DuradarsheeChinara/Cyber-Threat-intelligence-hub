from __future__ import annotations

import logging
from datetime import date
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from .. import crud, models, schemas
from ..auth import current_user
from ..database import get_db
from backend.tasks.ai_tasks import process_threat_task

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/threats", tags=["Threats"])

def _to_out(db: Session, threat: models.Threat) -> dict:
    result = {column.name: getattr(threat, column.name) for column in models.Threat.__table__.columns}
    analysis = crud.latest_analysis(db, threat.id)
    if analysis:
        result["analysis"] = analysis
    return result

def _dispatch(threat_id: str) -> None:
    try:
        process_threat_task.delay(threat_id)
    except Exception as exc:
        # Redis/Celery may be intentionally absent during local development.
        logger.warning("AI task dispatch failed for %s: %s", threat_id, exc)

@router.post("/", response_model=schemas.ThreatOut, status_code=status.HTTP_201_CREATED)
def add_threat(threat: schemas.ThreatCreate, db: Session = Depends(get_db), _user: models.User = Depends(current_user)):
    if crud.get_threat(db, threat.id): raise HTTPException(409, "Threat already exists")
    saved = crud.create_threat(db, threat)
    _dispatch(saved.id)
    return _to_out(db, saved)

@router.get("/", response_model=schemas.PaginatedThreats)
def list_threats(page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100), vendor: str | None = None, category: str | None = None, severity: str | None = None, published_from: date | None = None, published_to: date | None = None, db: Session = Depends(get_db)):
    query = db.query(models.Threat)
    if vendor: query = query.filter(models.Threat.vendor.ilike(f"%{vendor}%"))
    if published_from: query = query.filter(models.Threat.published >= published_from)
    if published_to: query = query.filter(models.Threat.published <= published_to)
    items = [_to_out(db, item) for item in query.order_by(models.Threat.published.desc()).all()]
    if category: items = [item for item in items if item.get("analysis") and item["analysis"].threat_category == category]
    if severity: items = [item for item in items if item.get("analysis") and item["analysis"].risk_level == severity]
    total, start = len(items), (page - 1) * page_size
    return {"items": items[start:start + page_size], "total": total, "page": page, "page_size": page_size}

@router.get("/{threat_id}", response_model=schemas.ThreatOut)
def read_threat(threat_id: str, db: Session = Depends(get_db)):
    threat = crud.get_threat(db, threat_id)
    if not threat: raise HTTPException(404, "Threat not found")
    return _to_out(db, threat)

@router.patch("/{threat_id}", response_model=schemas.ThreatOut)
def patch_threat(threat_id: str, update: schemas.ThreatUpdate, db: Session = Depends(get_db), _user: models.User = Depends(current_user)):
    threat = crud.get_threat(db, threat_id)
    if not threat: raise HTTPException(404, "Threat not found")
    return _to_out(db, crud.update_threat(db, threat, update.model_dump(exclude_unset=True)))

@router.put("/{threat_id}", response_model=schemas.ThreatOut)
def put_threat(threat_id: str, update: schemas.ThreatUpdate, db: Session = Depends(get_db), _user: models.User = Depends(current_user)):
    return patch_threat(threat_id, update, db, _user)

@router.delete("/{threat_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_threat(threat_id: str, db: Session = Depends(get_db), _user: models.User = Depends(current_user)):
    threat = crud.get_threat(db, threat_id)
    if not threat: raise HTTPException(404, "Threat not found")
    crud.delete_threat(db, threat)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@router.post("/{threat_id}/reprocess", status_code=status.HTTP_202_ACCEPTED)
def reprocess_threat(threat_id: str, db: Session = Depends(get_db), _user: models.User = Depends(current_user)):
    if not crud.get_threat(db, threat_id): raise HTTPException(404, "Threat not found")
    _dispatch(threat_id)
    return {"threat_id": threat_id, "status": "queued"}

@router.get("/{threat_id}/risk")
def threat_risk(threat_id: str, db: Session = Depends(get_db)):
    if not crud.get_threat(db, threat_id): raise HTTPException(404, "Threat not found")
    analysis = crud.latest_analysis(db, threat_id)
    if not analysis: raise HTTPException(404, "AI analysis not available yet")
    return {"risk_score": analysis.risk_score, "risk_level": analysis.risk_level, "breakdown": analysis.risk_breakdown}
