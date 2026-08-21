from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field

class NRDItem(BaseModel):
    domain: str
    registrar: Optional[str] = None
    registration_date: Optional[datetime] = None
    source_feed: str = "WHOIS_NRD"
    status: str = "PENDING"
    risk_score: Optional[float] = None
    created_at: Optional[datetime] = None

class NRDFeedResponse(BaseModel):
    count: int
    pending_count: int
    domains: List[NRDItem]

class NRDTriggerRequest(BaseModel):
    count: int = Field(default=10, ge=1, le=100, description="Number of domains to ingest and analyze from NRD stream")
