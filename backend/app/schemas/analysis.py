from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="Target URL or domain to analyze")
    deep_scan: bool = Field(default=True, description="Execute full multimodal visual and DOM crawl")

class BatchAnalysisRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=100, description="List of URLs to batch analyze")

class EngineScore(BaseModel):
    score: float = Field(..., ge=0.0, le=100.0)
    weight: float = Field(..., ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)

class RiskAssessment(BaseModel):
    overall_score: float = Field(..., ge=0.0, le=100.0, description="Calibrated ensemble risk score (0-100%)")
    risk_level: str = Field(..., description="Risk category: SAFE, SUSPICIOUS, HIGH PHISHING, CRITICAL PHISHING")
    badge_color: str = Field(..., description="Hex color code for UI representation")
    action_recommendation: str = Field(..., description="Actionable SOC/User guidance")
    confidence_interval: str = Field(default="95% CI [±2.5%]", description="Statistical confidence level")
    is_official_brand: bool = Field(default=False)
    matched_brand: Optional[str] = None
    is_visual_clone: bool = Field(default=False)
    primary_root_cause: Optional[str] = Field(default=None, description="Primary technical root-cause explaining the fake website")
    attack_vector: Optional[str] = Field(default=None, description="Categorized attack vector classification")
    mitre_tactics: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK framework techniques")
    forensic_details: Dict[str, Any] = Field(default_factory=dict, description="Itemized forensic attribution evidence")
    breakdown: Dict[str, Any] = Field(default_factory=dict)
    explainable_reasons: List[str] = Field(default_factory=list)

class AnalysisResponse(BaseModel):
    id: Optional[str] = None
    url: str
    domain: str
    execution_time_seconds: float
    screenshot_url: Optional[str] = None
    assessment: RiskAssessment
    details: Dict[str, Any] = Field(default_factory=dict)
