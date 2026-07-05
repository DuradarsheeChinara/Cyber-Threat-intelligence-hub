"""Sentence embedding generation service."""

from __future__ import annotations

import logging
import os
import threading

from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

_embedding_model: SentenceTransformer | None = None
_embedding_model_lock = threading.Lock()


def _get_embedding_model() -> SentenceTransformer:
    """Load and cache the sentence-transformer model safely."""
    global _embedding_model

    if _embedding_model is None:
        with _embedding_model_lock:
            if _embedding_model is None:
                load_dotenv()
                model_name = os.getenv("EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL)
                logger.info("Loading sentence-transformer model: %s", model_name)
                _embedding_model = SentenceTransformer(model_name)

    return _embedding_model


def generate_embedding(text: str) -> list[float]:
    """Generate a vector embedding for the supplied text."""
    if not text or not text.strip():
        logger.warning("Received empty text for embedding generation.")
        return []

    try:
        logger.info("Starting embedding generation.")
        embedding = _get_embedding_model().encode(text, normalize_embeddings=True)
        values = embedding.astype(float).tolist()
        logger.info("Embedding generated with %d dimensions.", len(values))
        return values
    except Exception as exc:
        logger.exception("Embedding generation failed: %s", exc)
        return []
