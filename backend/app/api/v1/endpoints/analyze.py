from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.schemas.analysis import URLAnalysisRequest, BatchAnalysisRequest, AnalysisResponse
from app.services.pipeline import AnalysisPipeline
from app.db.session import get_db
from app.db.repository import ScanRepository
from app.db.vector_store import VectorStore

router = APIRouter()
vector_store = VectorStore()
pipeline = AnalysisPipeline(vector_store)

@router.post("/analyze", response_model=AnalysisResponse)
def analyze_url(req: URLAnalysisRequest, db: Session = Depends(get_db)):
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")

    scan_res = pipeline.analyze(raw_url)

    # Persist to database via ScanRepository
    scan_repo = ScanRepository(db)
    assessment = scan_res["assessment"]
    breakdown = assessment.get("breakdown", {})

    record = scan_repo.create({
        "url": scan_res["url"],
        "domain": scan_res["domain"],
        "risk_score": assessment.get("overall_score", 0.0),
        "risk_level": assessment.get("risk_level", "SAFE"),
        "badge_color": assessment.get("badge_color", "#10B981"),
        "execution_time_seconds": scan_res.get("execution_time_seconds", 0.0),
        "screenshot_path": scan_res.get("screenshot_url"),
        "vision_score": breakdown.get("vision", {}).get("score", 0.0),
        "dom_score": breakdown.get("dom_code", {}).get("score", 0.0),
        "url_score": breakdown.get("url_whois", {}).get("score", 0.0),
        "nlp_score": breakdown.get("nlp_pretext", {}).get("score", 0.0),
        "metadata_score": breakdown.get("metadata_ssl", {}).get("score", 0.0),
        "matched_brand": assessment.get("matched_brand"),
        "is_clone": assessment.get("is_visual_clone", False),
        "explainable_reasons": assessment.get("explainable_reasons", []),
        "action_recommendation": assessment.get("action_recommendation", ""),
        "details_json": scan_res.get("details", {})
    })

    scan_res["id"] = record.id
    return scan_res

@router.post("/batch")
def analyze_batch(req: BatchAnalysisRequest, db: Session = Depends(get_db)):
    results = []
    scan_repo = ScanRepository(db)

    for u in req.urls:
        u_clean = u.strip()
        if not u_clean:
            continue
        try:
            res = pipeline.analyze(u_clean)
            assessment = res["assessment"]
            breakdown = assessment.get("breakdown", {})

            rec = scan_repo.create({
                "url": res["url"],
                "domain": res["domain"],
                "risk_score": assessment.get("overall_score", 0.0),
                "risk_level": assessment.get("risk_level", "SAFE"),
                "badge_color": assessment.get("badge_color", "#10B981"),
                "execution_time_seconds": res.get("execution_time_seconds", 0.0),
                "screenshot_path": res.get("screenshot_url"),
                "vision_score": breakdown.get("vision", {}).get("score", 0.0),
                "dom_score": breakdown.get("dom_code", {}).get("score", 0.0),
                "url_score": breakdown.get("url_whois", {}).get("score", 0.0),
                "nlp_score": breakdown.get("nlp_pretext", {}).get("score", 0.0),
                "metadata_score": breakdown.get("metadata_ssl", {}).get("score", 0.0),
                "matched_brand": assessment.get("matched_brand"),
                "is_clone": assessment.get("is_visual_clone", False),
                "explainable_reasons": assessment.get("explainable_reasons", []),
                "action_recommendation": assessment.get("action_recommendation", ""),
                "details_json": res.get("details", {})
            })
            res["id"] = rec.id
            results.append(res)
        except Exception as e:
            results.append({
                "url": u_clean,
                "domain": u_clean,
                "error": str(e),
                "assessment": {"overall_score": 0.0, "risk_level": "ERROR"}
            })

    return {"count": len(results), "results": results}
