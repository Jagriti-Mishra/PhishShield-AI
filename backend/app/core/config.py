import os
from typing import List, Dict
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "PhishShield AI — Enterprise Multimodal Phishing Detector"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False

    # Storage Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    DATA_DIR: str = os.path.join(BASE_DIR, "app", "data")
    CAPTURES_DIR: str = os.path.join(DATA_DIR, "captures")
    BRANDS_DIR: str = os.path.join(DATA_DIR, "brands")
    DB_PATH: str = os.path.join(DATA_DIR, "phishshield.db")
    SQLALCHEMY_DATABASE_URI: str = f"sqlite:///{DB_PATH}"

    # Multimodal Scoring Weights (Calibrated Default Ensemble)
    WEIGHT_VISION: float = 0.30
    WEIGHT_DOM_CODE: float = 0.25
    WEIGHT_URL_WHOIS: float = 0.25
    WEIGHT_NLP_PRETEXT: float = 0.12
    WEIGHT_METADATA_SSL: float = 0.08

    # Classification Thresholds
    CRITICAL_RISK_THRESHOLD: float = 70.0
    HIGH_RISK_THRESHOLD: float = 55.0
    SUSPICIOUS_RISK_THRESHOLD: float = 35.0
    VISUAL_CLONE_THRESHOLD: float = 0.72

    # Crawler Settings
    CRAWLER_TIMEOUT_SECONDS: int = 8
    CRAWLER_HEADLESS: bool = True
    USER_AGENT: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    # NRD Stream Settings
    NRD_FEED_URL: str = "https://raw.githubusercontent.com/x0rz/whois-scraper/master/sample_whois.txt"
    NRD_MAX_BUFFER_SIZE: int = 500

    model_config = {
        "case_sensitive": True,
        "env_file": ".env",
        "extra": "ignore"
    }

settings = Settings()

# Ensure runtime directories exist
os.makedirs(settings.DATA_DIR, exist_ok=True)
os.makedirs(settings.CAPTURES_DIR, exist_ok=True)
os.makedirs(settings.BRANDS_DIR, exist_ok=True)
