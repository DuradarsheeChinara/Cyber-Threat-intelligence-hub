from collections import Counter
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from .. import crud, models
from ..database import get_db

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    threats = db.query(models.Threat).order_by(models.Threat.published.desc()).all()
    analyses = {threat.id: crud.latest_analysis(db, threat.id) for threat in threats}
    severity = Counter(a.risk_level for a in analyses.values() if a and a.risk_level)
    critical = [
        {"id": threat.id, "title": threat.title, "vendor": threat.vendor,
         "risk_score": float(analyses[threat.id].risk_score), "risk_level": analyses[threat.id].risk_level}
        for threat in threats if analyses[threat.id] and analyses[threat.id].risk_level == "Critical"
    ][:10]
    return {"total_threats": len(threats), "analyzed_threats": sum(bool(a) for a in analyses.values()), "severity_distribution": dict(severity), "recent_critical_threats": critical}
