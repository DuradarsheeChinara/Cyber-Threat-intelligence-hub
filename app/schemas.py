from pydantic import BaseModel, ConfigDict
from datetime import date
from typing import Any, Optional

class ThreatCreate(BaseModel):
    id: str
    title: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    description: Optional[str] = None
    cvss: Optional[float] = None
    kev: Optional[bool] = False
    published: Optional[date] = None
    source: Optional[str] = None
    true_category: Optional[str] = None
    true_risk_score: Optional[float] = None
    cwe: Optional[str] = None
    dataset_split: Optional[str] = None
    source_payload: Optional[dict[str, Any]] = None

class ThreatUpdate(BaseModel):
    title: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    description: Optional[str] = None
    cvss: Optional[float] = None
    kev: Optional[bool] = None
    published: Optional[date] = None
    source: Optional[str] = None
    source_payload: Optional[dict[str, Any]] = None

class AnalysisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    ai_summary: Optional[str] = None
    threat_category: Optional[str] = None
    classification_confidence: Optional[float] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    risk_breakdown: Optional[dict[str, Any]] = None
    embedding_dimensions: Optional[int] = None
    generated_at: Optional[Any] = None


class ThreatOut(ThreatCreate):
    model_config = ConfigDict(from_attributes=True)
    analysis: Optional[AnalysisOut] = None

class PaginatedThreats(BaseModel):
    items: list[ThreatOut]
    total: int
    page: int
    page_size: int

class UserCredentials(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
