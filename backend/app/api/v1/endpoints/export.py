from fastapi import APIRouter, Body
from typing import Dict, Any

from app.schemas.export import ExportRequest, ThreatIntelligenceExportResponse
from app.utils.stix_exporter import STIXExporter
from app.utils.misp_exporter import MISPExporter
from app.utils.suricata_exporter import SuricataExporter
from app.utils.dns_exporter import DNSExporter
from app.utils.report_exporter import ReportExporter

router = APIRouter()
stix_exporter = STIXExporter()
misp_exporter = MISPExporter()
suricata_exporter = SuricataExporter()
dns_exporter = DNSExporter()
report_exporter = ReportExporter()

@router.post("/export/all", response_model=ThreatIntelligenceExportResponse)
def export_all_threat_formats(payload: ExportRequest):
    url = payload.url
    domain = payload.domain
    assessment = payload.assessment
    details = payload.details or {}

    stix_bundle = stix_exporter.generate_bundle(url, domain, assessment, details)
    misp_event = misp_exporter.generate_event(url, domain, assessment)
    suricata_rule = suricata_exporter.generate_rule(domain, assessment)
    dns_sinkhole = dns_exporter.generate_sinkhole_formats(domain)
    takedown_notice = report_exporter.generate_takedown_dossier(url, domain, assessment, details)

    return {
        "stix_bundle": stix_bundle,
        "misp_event": misp_event,
        "suricata_rule": suricata_rule,
        "dns_sinkhole_rule": dns_sinkhole,
        "takedown_notice": takedown_notice
    }
