from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class ExportRequest(BaseModel):
    url: str
    domain: str
    assessment: Dict[str, Any]
    details: Optional[Dict[str, Any]] = None

class ThreatIntelligenceExportResponse(BaseModel):
    stix_bundle: Dict[str, Any]
    misp_event: Dict[str, Any]
    suricata_rule: str
    dns_sinkhole_rule: str
    takedown_notice: str
