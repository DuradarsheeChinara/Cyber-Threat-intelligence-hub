# Cyber Threat Intelligence Hub

CTI Hub ingests CVE-style threat records, persists them, and asynchronously enriches each threat with the existing Gemini summary, zero-shot classifier, sentence embedding, and weighted risk score. The included React dashboard presents severity, AI analysis, and advisory details.

## Quick start

Use Python 3.11+ and Node.js 20+.

```powershell
python -m pip install -r requirements.txt
$env:DATABASE_URL="sqlite:///./cti_hub.db" # PostgreSQL URLs also work
$env:GEMINI_API_KEY="your-key"
$env:JWT_SECRET="a-long-random-secret"
python -m uvicorn app.main:app --reload
```

In another terminal, run the worker (Redis is the default broker):

```powershell
celery -A backend.tasks.ai_tasks.celery_app worker --loglevel=info
```

Start the dashboard:

```powershell
cd frontend
npm install
npm run dev
```

The API is at `http://localhost:8000/api/v1`; interactive docs are at `/docs`. Register through `POST /api/v1/auth/register`, then pass its bearer token to write endpoints. Read endpoints remain public for dashboard use.

## Dataset and evaluation

The NVD/CISA-derived data lives in `data/`; it uses the five labels Remote Code Execution, Denial of Service, Privilege Escalation, SQL Injection, and Other. Labels are assigned with description evidence plus CWE evidence, rather than CWE alone.

```powershell
# Load a bounded sample first, then use no --limit for the full normalized CSV
python -m app.seed_data --dataset data/threats.csv --limit 100
python scripts/evaluate_dataset.py --input data/threats_test.csv
python -m pytest -q
```

The evaluator does not supply `true_category` to the classifier at inference. It writes accuracy, macro precision/recall/F1, a confusion matrix, and risk-score MAE to `backend/output/evaluation.json`.

## Environment

`DATABASE_URL`, `GEMINI_API_KEY`, `GEMINI_MODEL` (optional), `CLASSIFICATION_MODEL` (optional), `EMBEDDING_MODEL` (optional), `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`, and `JWT_SECRET` are supported. If the AI service or broker is unavailable, ingestion still succeeds and a threat can be reprocessed with `POST /api/v1/threats/{id}/reprocess` when services recover.
