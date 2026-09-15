"""Seed sample threats or import the normalized CVE CSV into the CTI database."""
from __future__ import annotations
import argparse
import csv
import json
from datetime import date
from pathlib import Path
from sqlalchemy.orm import Session
from . import crud, models, schemas
from .database import Base, SessionLocal, engine

SAMPLE_THREATS = [
    {"id": "CVE-2026-0001", "title": "Apache HTTP Server Remote Code Execution", "vendor": "Apache", "product": "HTTP Server", "description": "A vulnerability in Apache HTTP Server allows remote attackers to execute arbitrary code.", "cvss": 9.8, "kev": True, "published": "2026-06-30"},
    {"id": "CVE-2026-0002", "title": "Microsoft Exchange Server Privilege Escalation", "vendor": "Microsoft", "product": "Exchange Server", "description": "A privilege escalation vulnerability in Microsoft Exchange Server allows an authenticated attacker to gain administrator access.", "cvss": 8.1, "kev": False, "published": "2026-05-14"},
]

def _float(value: str | None) -> float | None:
    try: return float(value) if value not in (None, "") else None
    except ValueError: return None

def _date(value: str | None) -> date | None:
    try: return date.fromisoformat(value) if value else None
    except ValueError: return None

def _bounded(value: str | None, limit: int) -> str | None:
    """Keep indexed display columns within their schema bounds; raw data is retained."""
    value = (value or "").strip()
    return value[:limit] or None

def import_dataset(db: Session, csv_path: Path, limit: int | None = None) -> dict[str, int]:
    """Insert a CSV once per CVE natural key; preserve source and ground truth."""
    inserted = skipped = invalid = 0
    with csv_path.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            cve_id = (row.get("id") or "").strip().upper()
            if not cve_id or not row.get("description"):
                invalid += 1; continue
            if crud.get_threat(db, cve_id):
                skipped += 1; continue
            db.add(models.Threat(
                id=cve_id, title=_bounded(row.get("title"), 255) or cve_id,
                vendor=_bounded(row.get("vendor"), 100), product=_bounded(row.get("product"), 150),
                description=row["description"], cvss=_float(row.get("cvss")),
                kev=str(row.get("kev", "")).lower() == "true", published=_date(row.get("published")),
                source="NVD", source_payload={
                    "cwe": row.get("cwe", ""),
                    "dataset_split": row.get("dataset_split", ""),
                    "raw_record": dict(row),
                },
                true_category=row.get("true_category") or None, true_risk_score=_float(row.get("true_risk_score")),
                cwe=_bounded(row.get("cwe"), 255), dataset_split=_bounded(row.get("dataset_split"), 20),
            ))
            inserted += 1
            if limit and inserted >= limit: break
    db.commit()
    return {"inserted": inserted, "skipped": skipped, "invalid": invalid}

def seed_samples(db: Session) -> dict[str, int]:
    inserted = 0
    for item in SAMPLE_THREATS:
        if not crud.get_threat(db, item["id"]):
            crud.create_threat(db, schemas.ThreatCreate(**item)); inserted += 1
    return {"inserted": inserted}

def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--dataset", type=Path); parser.add_argument("--limit", type=int); args = parser.parse_args()
    Base.metadata.create_all(bind=engine); db = SessionLocal()
    try: print(json.dumps(import_dataset(db, args.dataset, args.limit) if args.dataset else seed_samples(db)))
    finally: db.close()

if __name__ == "__main__": main()
