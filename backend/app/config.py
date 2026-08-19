import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "SIH 1454: AI Phishing Domain Detector"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Feature Engine Weights
    WEIGHT_VISION: float = 0.35
    WEIGHT_DOM: float = 0.30
    WEIGHT_URL: float = 0.20
    WEIGHT_METADATA: float = 0.15
    
    # Thresholds
    VISUAL_SIMILARITY_THRESHOLD: float = 0.85
    HIGH_RISK_THRESHOLD: float = 70.0
    MEDIUM_RISK_THRESHOLD: float = 35.0
    
    # Storage Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    BRAND_DATA_DIR: str = os.path.join(BASE_DIR, "data", "brands")
    CAPTURES_DIR: str = os.path.join(BASE_DIR, "data", "captures")

    class Config:
        case_sensitive = True

settings = Settings()

os.makedirs(settings.BRAND_DATA_DIR, exist_ok=True)
os.makedirs(settings.CAPTURES_DIR, exist_ok=True)
