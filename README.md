# Cyber Threat Intelligence Hub

Cyber Threat Intelligence Hub (CTI Hub) is a local, full-stack security
dashboard for organizing CVE-style vulnerability intelligence and performing
safe first-pass triage of suspicious URLs and files. It combines a FastAPI
backend, a React dashboard, a relational database, optional background AI
enrichment, and explainable risk scoring.

The project is intended for local development and analyst workflows. It does
not execute uploaded files, download submitted links, or make unsupported
claims that something is malware.

## What it does

### CVE threat intelligence

- Stores CVE-style threat records with vendor, product, description, CVSS,
  known-exploited-vulnerability (KEV) status, publication date, CWE, and source
  metadata.
- Imports the included normalized NVD/CISA-derived CSV dataset.
- Displays a dashboard with threat totals, severity distribution, critical
  threats, filtering, and an analyst detail pane.
- Allows authenticated users to create, update, delete, and reprocess threats
  through the API.

### Optional AI enrichment

When Gemini, Redis/Memurai, and a Celery worker are configured, each new or
reprocessed threat is queued for background analysis:

1. Gemini writes a concise analyst summary.
2. A Hugging Face zero-shot classifier assigns a threat category.
3. A Sentence Transformers model creates an embedding for future similarity
   search or clustering.
4. The risk engine combines CVSS, KEV status, category impact, and classifier
   confidence into a score and severity.
5. The worker stores the completed analysis in the database; the dashboard then
   shows it automatically when refreshed.

The application still accepts and displays threats if the queue or AI services
are unavailable. The record can be queued again later using the `reprocess`
endpoint.

### Link and file triage

The dashboard includes a **Link & file triage** panel for safe local checks.

| Input | What CTI Hub checks | What it never does |
| --- | --- | --- |
| URL | HTTPS usage, punycode domains, IP-address hosts, local/private targets, unusually long URLs, and high-risk download terms | Opens the page, follows redirects, or downloads the content |
| File (up to 10 MB) | SHA-256 hash, executable signatures, scripts, macro-enabled Office documents, archives, and misleading double extensions | Executes, opens, unpacks, or retains the file |

A result contains a score, a verdict, the exact signals that contributed to
the score, and—when scanning a file—its SHA-256 hash. This is **static triage,
not antivirus or a malware verdict**. A production deployment should add a
trusted hash-reputation, sandbox, or antivirus provider before declaring a
file or URL safe/malicious.

## Architecture

```text
                         ┌──────────────────────────┐
                         │ React + Vite dashboard   │
                         │ http://localhost:5173    │
                         └────────────┬─────────────┘
                                      │ HTTP / JSON + multipart upload
                                      ▼
                         ┌──────────────────────────┐
                         │ FastAPI API              │
                         │ http://localhost:8000    │
                         └───────┬────────┬─────────┘
                                 │        │
               ┌─────────────────▼───┐    │ static, no-network triage
               │ SQLite / PostgreSQL │    └────────► URL/file scanner
               └─────────────────────┘
                                 │
                                 ▼
                      ┌─────────────────────┐
                      │ Celery + Redis /    │
                      │ Memurai (optional)  │
                      └─────────┬───────────┘
                                ▼
                 Gemini summary + Hugging Face models
                                ▼
                         persisted AI analysis
```

## Technology stack

| Area | Technology | Purpose |
| --- | --- | --- |
| Backend API | Python 3.11+, FastAPI, Uvicorn | REST API, OpenAPI documentation, validation, file upload endpoint |
| Database | SQLAlchemy 2, SQLite or PostgreSQL | Threat, user, and analysis persistence |
| PostgreSQL driver | psycopg2-binary | PostgreSQL connectivity when `DATABASE_URL` uses `postgresql://` |
| Authentication | HS256 JWT implemented with Python standard library | Protects write and reprocess endpoints |
| Background jobs | Celery + Redis or Memurai | Runs expensive AI analysis outside the HTTP request |
| Generative AI | Google Gen AI SDK / Gemini | Writes analyst-oriented threat summaries |
| ML | Transformers, `facebook/bart-large-mnli` by default | Zero-shot threat classification |
| Embeddings | Sentence Transformers, `all-MiniLM-L6-v2` by default | Produces normalized semantic embeddings |
| Frontend | React, TypeScript, Vite | Local dashboard interface |
| Charts | Recharts | Severity-distribution bar chart |
| Testing | pytest, FastAPI TestClient | API, risk, dataset, and scanning tests |

## Prerequisites

- **Windows PowerShell** commands below assume Windows. Other platforms can use
  the equivalent virtual-environment activation command.
- **Python 3.11 or newer**. Python 3.14 is supported in the current local setup.
- **Node.js 20 or newer** and npm.
- Optional: **PostgreSQL** if you do not want the default local SQLite database.
- Optional: **Redis** or **Memurai** on port 6379 for Celery background jobs.
- Optional: a **Gemini API key** for generated summaries.
- Internet access is normally required the first time the ML models are
  downloaded by Hugging Face/Sentence Transformers.

## Setup

All commands must be run from the repository folder:

```powershell
cd "C:\Users\DURA\Desktop\Cyber Threat\Cyber-Threat-Intelligence-Hub"
```

### 1. Create and activate the Python environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell does not allow script activation, you do not need to change the
execution policy. Use the environment's Python executable directly in every
command instead:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

### 2. Configure environment variables

Create your local environment file if one is not already present:

```powershell
Copy-Item .env.example .env
```

The default `.env.example` uses SQLite, which needs no database server:

```dotenv
DATABASE_URL=sqlite:///./cti_hub.db
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
GEMINI_API_KEY=
GEMINI_MODEL=gemini-3.6-flash
JWT_SECRET=replace-with-a-long-random-local-secret
```

Do not commit `.env`; it can contain credentials. Change `JWT_SECRET` to a
long random value before exposing the app to anyone else.

### Database options

**SQLite (simplest)**

```dotenv
DATABASE_URL=sqlite:///./cti_hub.db
```

The database file is created automatically when the API starts.

**PostgreSQL**

Create an empty database, then set:

```dotenv
DATABASE_URL=postgresql://YOUR_USER:YOUR_PASSWORD@localhost:5432/cti_hub
```

The API creates its tables automatically at startup. This project uses
`psycopg2-binary`, already listed in `requirements.txt`.

### 3. Install the dashboard dependencies

```powershell
cd frontend
npm install
cd ..
```

## Running the application

Open separate PowerShell windows for the API, dashboard, and—only when using
AI enrichment—the worker.

### Terminal 1: API

```powershell
cd "C:\Users\DURA\Desktop\Cyber Threat\Cyber-Threat-Intelligence-Hub"
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected output includes:

```text
Uvicorn running on http://127.0.0.1:8000
```

Visit these URLs:

- Dashboard API: http://localhost:8000/api/v1
- Interactive API documentation: http://localhost:8000/docs
- API health/root response: http://localhost:8000/

### Terminal 2: dashboard

```powershell
cd "C:\Users\DURA\Desktop\Cyber Threat\Cyber-Threat-Intelligence-Hub\frontend"
npm run dev
```

Open http://localhost:5173, create an analyst account, and sign in. The
dashboard talks to `http://127.0.0.1:8000/api/v1` by default. Override it in
`frontend/.env` when necessary:

```powershell
Set-Content .env 'VITE_API_URL=http://localhost:8000/api/v1'
npm run dev
```

### Terminal 3: optional AI worker

Start this only after Redis/Memurai is running and your `.env` has a valid
Gemini key:

```powershell
cd "C:\Users\DURA\Desktop\Cyber Threat\Cyber-Threat-Intelligence-Hub"
.\.venv\Scripts\Activate.ps1
celery -A backend.tasks.ai_tasks.celery_app worker --loglevel=info
```

If the `celery` command is not found, use:

```powershell
.\.venv\Scripts\python.exe -m celery -A backend.tasks.ai_tasks.celery_app worker --loglevel=info
```

## How to use it

### Use the link/file triage panel

1. Open http://localhost:5173.
2. Paste a complete `http://` or `https://` URL and select **Check link**, or
   select **Check file** and choose a file no larger than 10 MB.
3. Read the score and signals; a score is a prompt for review, not proof.
4. For files, copy the SHA-256 value when submitting it to an approved
   reputation or incident-response workflow.

The scan endpoints do not require a user account because they do not persist a
submission. Keep the app bound to `127.0.0.1` unless you add authentication,
rate limits, and stronger upload controls.

### Create an account and add a threat

1. Open http://localhost:5173 and choose **Create Account**. Registration
   creates an API account and signs you in automatically.
2. To add a threat through Swagger UI, open http://localhost:8000/docs.
3. Call `POST /api/v1/auth/login` (or register) with the same username and
   password, copy `access_token`, then click **Authorize** and enter
   `Bearer YOUR_TOKEN`.
4. Use `POST /api/v1/threats/` to create a CVE-style threat record.
5. With the worker running, the API queues analysis. Refresh the dashboard or
   call `GET /api/v1/threats/{threat_id}` to see the completed result.

Example payload:

```json
{
  "id": "CVE-LOCAL-0001",
  "title": "Example remote code execution issue",
  "vendor": "Example Vendor",
  "product": "Example Product",
  "description": "A remote attacker could execute arbitrary code.",
  "cvss": 9.8,
  "kev": true,
  "published": "2026-09-15"
}
```

### Main API endpoints

| Method | Endpoint | Purpose | Authentication |
| --- | --- | --- | --- |
| `POST` | `/api/v1/auth/register` | Create a local user and JWT | No |
| `POST` | `/api/v1/auth/login` | Receive a JWT | No |
| `GET` | `/api/v1/threats/` | List/filter threats | No |
| `POST` | `/api/v1/threats/` | Add a threat and queue analysis | Yes |
| `GET` | `/api/v1/threats/{id}` | Get a threat and latest analysis | No |
| `PATCH` / `PUT` | `/api/v1/threats/{id}` | Update a threat | Yes |
| `DELETE` | `/api/v1/threats/{id}` | Delete a threat and its analyses | Yes |
| `POST` | `/api/v1/threats/{id}/reprocess` | Queue AI analysis again | Yes |
| `GET` | `/api/v1/threats/{id}/risk` | Get stored risk result | No |
| `GET` | `/api/v1/dashboard/overview` | Dashboard totals and critical list | No |
| `POST` | `/api/v1/scans/url` | Static URL triage | No |
| `POST` | `/api/v1/scans/file` | Static file triage | No |

## Risk scoring

The stored threat risk score is 0–100 and is calculated as:

```text
score = 0.65 × normalized CVSS
      + 0.20 × KEV score
      + 0.15 × category impact × classifier confidence
```

- CVSS is normalized from 0–10 to 0–100.
- A known exploited vulnerability contributes a KEV score of 100; otherwise 0.
- Category impact is highest for Remote Code Execution and lower for categories
  such as Denial of Service or Other.
- Severity bands: **Critical** ≥ 90, **High** ≥ 70, **Medium** ≥ 40, otherwise
  **Low**.

The URL/file score is separate from the CVE risk score and is only an
explainable static-triage score.

## Dataset, import, and evaluation

The `data/` folder contains NVD/CISA-derived CSVs. The project taxonomy has
five labels: Remote Code Execution, Denial of Service, Privilege Escalation,
SQL Injection, and Other.

### Import a bounded dataset sample

```powershell
.\.venv\Scripts\python.exe -m app.seed_data --dataset data\threats.csv --limit 100
```

Run without `--limit` to import the full normalized CSV. Existing CVE IDs are
skipped, so rerunning the import does not duplicate records.

### Evaluate the held-out set

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_dataset.py --input data\threats_test.csv
```

The evaluator intentionally never gives `true_category` to the model at
inference time. It writes accuracy, macro precision/recall/F1, confusion
matrix, and risk-score MAE to `backend/output/evaluation.json`.

The first evaluation run can take time because it loads/downloads the
zero-shot model.

## Tests and production build

Run backend tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Build the frontend:

```powershell
cd frontend
npm run build
```

## Troubleshooting

### `ModuleNotFoundError: No module named 'app'`

You started Uvicorn from the parent folder. Change into the repository first:

```powershell
cd "C:\Users\DURA\Desktop\Cyber Threat\Cyber-Threat-Intelligence-Hub"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

### `.venv\Scripts\Activate.ps1 is not recognized`

You are not in the repository folder, or the environment was not created.
Run `cd` to the project folder, then `python -m venv .venv`. Alternatively,
skip activation and invoke `.\.venv\Scripts\python.exe` directly.

### File upload endpoint says `python-multipart` is missing

Reinstall project dependencies into the active environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Threat stays pending

The record was saved, but background enrichment needs the worker. Check that
Redis/Memurai is running on port 6379, `GEMINI_API_KEY` is set, and the Celery
worker is running. Then call the reprocess endpoint from `/docs`.

### Gemini model is unavailable

Set `GEMINI_MODEL` in `.env` to a model available to your Gemini account, then
restart the worker. The API continues to accept threats even if Gemini fails.

## Security notes and next improvements

- Keep the app on `127.0.0.1` during local development.
- Never treat a Low risk static result as a guarantee of safety.
- Never upload sensitive files to an untrusted public service.
- For a production scanner, add authenticated scan submissions, rate limiting,
  durable audit logs, antivirus/sandbox scanning, a hash-reputation provider,
  asynchronous large-file processing, and robust archive handling.
- For production authentication, replace the local SHA-256 password hashing
  with a purpose-built password hashing algorithm such as Argon2 or bcrypt.

## Project layout

```text
app/                    FastAPI application, database models, routers, services
app/services/scanning.py Safe local URL/file static-triage implementation
backend/ai/             Gemini summary, classifier, and embedding services
backend/tasks/          Celery task definitions
backend/services/       Risk scoring engine
frontend/               React/Vite dashboard
data/                   Normalized CVE dataset and data summaries
scripts/                Dataset build and held-out evaluation scripts
tests/                  Backend, API, evaluation, risk, and scanner tests
```
