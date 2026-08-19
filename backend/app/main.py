import os
import time
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, HttpUrl

from app.config import settings
from app.db.vector_store import VectorStore
from app.services.crawler import StealthCrawler
from app.services.url_analyzer import URLAnalyzer
from app.services.vision_analyzer import VisionAnalyzer
from app.services.dom_analyzer import DOMAnalyzer
from app.services.metadata_analyzer import MetadataAnalyzer
from app.services.scoring_engine import ScoringEngine
from app.utils.stix_exporter import STIXExporter

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Multimodal AI Phishing Domain Detection Platform for SIH 1454"
)

# Enable CORS for Chrome Extension & Frontend Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Services
vector_store = VectorStore()
crawler = StealthCrawler()
url_analyzer = URLAnalyzer()
vision_analyzer = VisionAnalyzer(vector_store)
dom_analyzer = DOMAnalyzer()
metadata_analyzer = MetadataAnalyzer()
scoring_engine = ScoringEngine()
stix_exporter = STIXExporter()

class URLRequest(BaseModel):
    url: str

@app.get("/api/v1/health")
def health_check():
    return {"status": "online", "project": settings.PROJECT_NAME, "version": settings.VERSION}

@app.get("/api/v1/brands")
def list_monitored_brands():
    return {"count": len(vector_store.brands), "brands": list(vector_store.brands.keys())}

@app.post("/api/v1/analyze")
def analyze_url(req: URLRequest):
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    start_time = time.time()

    # Step 1: Stealth Crawler Captures Screenshot & DOM Content
    screenshot_path, html_content, headers = crawler.capture(raw_url)

    # Step 2: URL & Typosquatting Analysis
    url_res = url_analyzer.analyze(raw_url)

    # Step 3: Computer Vision & ResNet50 Similarity Analysis
    vision_res = vision_analyzer.analyze(screenshot_path, url_res["netloc"])

    # Step 4: DOM & Code Behavioral Analysis
    dom_res = dom_analyzer.analyze(html_content, raw_url)

    # Step 5: Metadata & Security Headers Analysis
    meta_res = metadata_analyzer.analyze(raw_url, headers)

    # Step 6: Ensemble Risk Scoring Engine
    scoring_res = scoring_engine.compute(url_res, vision_res, dom_res, meta_res)

    execution_time = round(time.time() - start_time, 2)

    # Relative path for screenshot serving
    rel_screenshot = f"/captures/{os.path.basename(screenshot_path)}" if os.path.exists(screenshot_path) else None

    # Consolidated API Response
    return {
        "url": raw_url,
        "execution_time_seconds": execution_time,
        "screenshot_url": rel_screenshot,
        "assessment": scoring_res,
        "details": {
            "url_analysis": url_res,
            "vision_analysis": vision_res,
            "dom_analysis": dom_res,
            "metadata_analysis": meta_res
        }
    }

@app.post("/api/v1/stix-export")
def export_stix(payload: dict = Body(...)):
    url = payload.get("url", "")
    assessment = payload.get("assessment", {})
    
    stix_json = stix_exporter.generate_stix_bundle(url, assessment)
    dns_rule = stix_exporter.generate_dns_sinkhole_rule(payload.get("netloc", url))

    return {
        "stix_bundle": stix_json,
        "dns_sinkhole_rule": dns_rule
    }

# Static Mount for Captured Screenshots and Frontend
app.mount("/captures", StaticFiles(directory=settings.CAPTURES_DIR), name="captures")
frontend_dir = os.path.join(settings.BASE_DIR, "..", "frontend")
if os.path.exists(frontend_dir):
    app.mount("/dashboard", StaticFiles(directory=frontend_dir, html=True), name="frontend")
