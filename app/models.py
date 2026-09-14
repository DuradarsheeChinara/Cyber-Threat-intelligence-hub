from sqlalchemy import Boolean, Column, Date, Float, ForeignKey, Integer, JSON, Numeric, String, Text, TIMESTAMP
from sqlalchemy.sql import func
from .database import Base

class Threat(Base):
    __tablename__ = "threats"
    id = Column(String(30), primary_key=True)
    title = Column(String(255), nullable=False)
    vendor = Column(String(100))
    product = Column(String(150))
    description = Column(Text)
    cvss = Column(Numeric(3, 1))
    kev = Column(Boolean, default=False)
    published = Column(Date)
    source = Column(String(50))
    source_payload = Column(JSON, nullable=True)
    true_category = Column(String(50), nullable=True)
    true_risk_score = Column(Float, nullable=True)
    cwe = Column(String(255), nullable=True)
    dataset_split = Column(String(20), nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())

class AIAnalysis(Base):
    __tablename__ = "ai_analysis"
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(30), ForeignKey("threats.id"))
    ai_summary = Column(Text)
    threat_category = Column(String(50))
    risk_score = Column(Numeric(4, 2))
    risk_level = Column(String(20), nullable=True)
    classification_confidence = Column(Float, nullable=True)
    embedding = Column(JSON, nullable=True)
    embedding_dimensions = Column(Integer, nullable=True)
    risk_breakdown = Column(JSON, nullable=True)
    generated_at = Column(TIMESTAMP, server_default=func.now())

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
