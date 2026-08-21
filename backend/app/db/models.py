import uuid
import datetime
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, Text, JSON
from app.db.session import Base

class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    url = Column(String(2048), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(String(50), nullable=False, default="SAFE")
    badge_color = Column(String(20), nullable=False, default="#10B981")
    execution_time_seconds = Column(Float, default=0.0)
    screenshot_path = Column(String(512), nullable=True)
    
    # Multimodal Score Breakdown
    vision_score = Column(Float, default=0.0)
    dom_score = Column(Float, default=0.0)
    url_score = Column(Float, default=0.0)
    nlp_score = Column(Float, default=0.0)
    metadata_score = Column(Float, default=0.0)
    
    # Forensic Findings & Brand Match
    matched_brand = Column(String(100), nullable=True)
    is_clone = Column(Boolean, default=False)
    explainable_reasons = Column(JSON, default=list)
    action_recommendation = Column(Text, nullable=True)
    details_json = Column(JSON, default=dict)
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)

class MonitoredBrand(Base):
    __tablename__ = "monitored_brands"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    brand_name = Column(String(100), unique=True, nullable=False, index=True)
    official_domain = Column(String(255), nullable=False, index=True)
    category = Column(String(100), default="Enterprise & Cloud Services")
    phash = Column(String(64), nullable=True)
    feature_vector = Column(JSON, nullable=True)
    dom_signature = Column(JSON, nullable=True)
    logo_url = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class NRDRecord(Base):
    __tablename__ = "nrd_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain = Column(String(255), unique=True, nullable=False, index=True)
    registrar = Column(String(255), nullable=True)
    registration_date = Column(DateTime, nullable=True)
    source_feed = Column(String(100), default="WHOIS_NRD")
    status = Column(String(50), default="PENDING") # PENDING, SCANNED, SUSPICIOUS, BENIGN
    risk_score = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
