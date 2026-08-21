from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.schemas.nrd import NRDFeedResponse, NRDTriggerRequest
from app.db.session import get_db
from app.db.repository import NRDRepository
from app.services.nrd_service import NRDService
from app.services.pipeline import AnalysisPipeline
from app.db.vector_store import VectorStore

router = APIRouter()
vector_store = VectorStore()
pipeline = AnalysisPipeline(vector_store)

@router.get("/nrd/feed", response_model=NRDFeedResponse)
def get_nrd_feed(db: Session = Depends(get_db)):
    repo = NRDRepository(db)
    service = NRDService(repo)
    
    # Auto-seed sample feed if empty
    all_recs = repo.get_recent_scanned(limit=200)
    if not all_recs:
        service.ingest_sample_nrd_feed(count=10)
        all_recs = repo.get_recent_scanned(limit=200)

    pending_cnt = repo.get_pending_count()
    
    items = []
    for r in all_recs:
        items.append({
            "domain": r.domain,
            "registrar": r.registrar,
            "registration_date": r.registration_date,
            "source_feed": r.source_feed,
            "status": r.status,
            "risk_score": r.risk_score,
            "created_at": r.created_at
        })

    return {
        "count": len(items),
        "pending_count": pending_cnt,
        "domains": items
    }

@router.post("/nrd/trigger")
def trigger_nrd_ingestion(req: NRDTriggerRequest, db: Session = Depends(get_db)):
    repo = NRDRepository(db)
    service = NRDService(repo)
    ingested = service.ingest_sample_nrd_feed(count=req.count)
    return {
        "message": f"Successfully ingested {len(ingested)} newly registered domains into the threat triage queue.",
        "ingested_domains": ingested
    }

@router.post("/nrd/scan-pending")
def scan_pending_nrd(limit: int = 50, db: Session = Depends(get_db)):
    repo = NRDRepository(db)
    pending = repo.get_pending(limit=limit)

    # Strictly triage pending domains only; do not re-scan or auto-generate
    if not pending:
        return {
            "message": "All domains in the NRD triage queue are already analyzed and verified. Click 'Ingest Live Stream Batch' to ingest fresh domains.",
            "scanned_count": 0,
            "results": []
        }

    scanned_results = []

    for item in pending:
        try:
            res = pipeline.analyze(f"http://{item.domain}")
            score = res["assessment"].get("overall_score", 0.0)
            level = res["assessment"].get("risk_level", "SAFE")
            
            if score >= 80.0:
                status_label = "CRITICAL PHISHING"
            elif score >= 50.0:
                status_label = "HIGH PHISHING"
            elif score >= 25.0:
                status_label = "SUSPICIOUS"
            else:
                status_label = "BENIGN"

            repo.update_status(item.domain, status=status_label, risk_score=score)
            scanned_results.append({
                "domain": item.domain,
                "score": score,
                "risk_level": level,
                "status": status_label,
                "matched_brand": res["assessment"].get("matched_brand")
            })
        except Exception as e:
            repo.update_status(item.domain, status="BENIGN", risk_score=0.0)

    return {
        "message": f"Successfully triaged {len(scanned_results)} newly registered domains with multimodal AI.",
        "scanned_count": len(scanned_results),
        "results": scanned_results
    }
