# CTI Hub AI Service

This directory contains the AI components for the Cyber Threat Intelligence Hub pipeline.

## Pipeline

Threat feed object -> Gemini summary -> zero-shot classification -> sentence embedding -> risk score -> JSON output.

## `summarizer.py`

Purpose: Generates a concise cybersecurity analyst summary for a threat object.

Input: A threat dictionary with fields such as `id`, `title`, `vendor`, `product`, `description`, `cvss`, `kev`, and `published`.

Output: A summary string.

Technologies: `google-genai`, Gemini API, `python-dotenv`, prompt template from `backend/ai/prompts/summary.txt`.

Performance notes: The prompt template and Gemini client are lazily initialized and reused per Python process.

## `classifier.py`

Purpose: Classifies a generated summary into a vulnerability or threat category.

Input: A summary string.

Output: A dictionary containing `category` and `confidence`.

Technologies: Hugging Face `transformers` zero-shot classification pipeline.

Performance notes: The classifier model is lazily loaded once and protected by a thread lock.

## `embeddings.py`

Purpose: Converts summary text into a vector embedding.

Input: A text string, normally the generated summary.

Output: `list[float]` embedding values.

Technologies: `sentence-transformers`.

Performance notes: The embedding model is lazily loaded once and protected by a thread lock.

## `risk_engine.py`

Purpose: Calculates a normalized risk score and risk level.

Input: A threat dictionary and a classification dictionary.

Output: A dictionary containing `risk_score` and `risk_level`.

Technologies: Rule-based scoring with weighted CVSS, KEV, and classification features.

## `ai_tasks.py`

Purpose: Orchestrates the full sample-data pipeline and exposes a Celery task.

Input: Mock threats from `backend/mock_data/sample_threats.py`.

Output: Logs processing results and writes `backend/output/processed_threats.json`.

Technologies: Celery, Redis broker configuration, `python-dotenv`, JSON export.

## Environment

Required:

```env
GEMINI_API_KEY=your_api_key
```

Optional:

```env
GEMINI_MODEL=gemini-2.5-flash
CLASSIFICATION_MODEL=facebook/bart-large-mnli
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

## Execute

Run the pipeline directly:

```powershell
python -m backend.tasks.ai_tasks
```

Run tests:

```powershell
pytest
```

Run a Celery worker:

```powershell
celery -A backend.tasks.ai_tasks.celery_app worker --loglevel=info
```
