import os
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./test_cti_hub.db"

from fastapi.testclient import TestClient
from app.database import Base, engine
from app.main import app
from backend.tasks import ai_tasks
from backend.tasks.ai_tasks import process_threat_task

client = TestClient(app)

def auth_header():
    response = client.post("/api/v1/auth/register", json={"username": "analyst", "password": "safe-password"})
    if response.status_code == 409:
        response = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "safe-password"})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}

def test_crud_reprocess_and_dashboard(monkeypatch):
    Base.metadata.drop_all(bind=engine); Base.metadata.create_all(bind=engine)
    queued = []
    monkeypatch.setattr(process_threat_task, "delay", lambda threat_id: queued.append(threat_id))
    headers = auth_header()
    payload = {"id": "CVE-TEST-1", "title": "Test RCE", "description": "remote code execution", "cvss": 9.8, "kev": True, "published": "2026-01-01"}
    created = client.post("/api/v1/threats/", json=payload, headers=headers)
    assert created.status_code == 201 and queued == ["CVE-TEST-1"]
    assert client.get("/api/v1/threats/").json()["total"] == 1
    assert client.patch("/api/v1/threats/CVE-TEST-1", json={"vendor": "Acme"}, headers=headers).status_code == 200
    assert client.post("/api/v1/threats/CVE-TEST-1/reprocess", headers=headers).status_code == 202
    assert queued == ["CVE-TEST-1", "CVE-TEST-1"]
    assert client.get("/api/v1/dashboard/overview").status_code == 200
    assert client.delete("/api/v1/threats/CVE-TEST-1", headers=headers).status_code == 204

def test_worker_persists_real_pipeline_shape(monkeypatch):
    """The Celery task persists pipeline output without calling external services."""
    Base.metadata.drop_all(bind=engine); Base.metadata.create_all(bind=engine)
    headers = auth_header()
    monkeypatch.setattr(process_threat_task, "delay", lambda threat_id: None)
    created = client.post("/api/v1/threats/", json={"id": "CVE-TEST-2", "title": "Persistence test", "description": "test", "cvss": 9.0, "kev": True}, headers=headers)
    assert created.status_code == 201
    monkeypatch.setattr("app.services.analysis.run_analysis", lambda _threat: {
        "ai_summary": "A generated summary", "threat_category": "Remote Code Execution",
        "classification_confidence": 0.91, "embedding": [0.1, 0.2], "embedding_dimensions": 2,
        "risk_score": 91.0, "risk_level": "Critical", "risk_breakdown": {"cvss_weight": 0.65},
    })
    result = ai_tasks.process_threat_task.run("CVE-TEST-2")
    assert result["status"] == "completed"
    detail = client.get("/api/v1/threats/CVE-TEST-2").json()
    assert detail["analysis"]["ai_summary"] == "A generated summary"
    assert detail["analysis"]["embedding_dimensions"] == 2
    assert client.get("/api/v1/threats/CVE-TEST-2/risk").json()["breakdown"]["cvss_weight"] == 0.65

def teardown_module():
    engine.dispose()
