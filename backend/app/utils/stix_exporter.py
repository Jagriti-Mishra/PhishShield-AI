import uuid
from datetime import datetime

class STIXExporter:
    def generate_stix_bundle(self, url: str, analysis_result: dict) -> dict:
        bundle_id = f"bundle--{uuid.uuid4()}"
        indicator_id = f"indicator--{uuid.uuid4()}"
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        overall_score = analysis_result.get("overall_score", 0)
        risk_level = analysis_result.get("risk_level", "UNKNOWN")
        reasons = analysis_result.get("explainable_reasons", [])

        stix_indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"Phishing Domain Indicator - {url}",
            "description": f"Phishing analysis flagged URL with Risk Score {overall_score}% ({risk_level}). Reasons: {'; '.join(reasons)}",
            "pattern": f"[url:value = '{url}']",
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": int(overall_score),
            "indicator_types": ["malicious-activity", "phishing"]
        }

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": [stix_indicator]
        }

        return bundle

    def generate_dns_sinkhole_rule(self, netloc: str) -> str:
        clean_domain = netloc.split(":")[0].lower()
        return f"# SIH 1454 Phishing Sinkhole Rule\n0.0.0.0 {clean_domain}\n0.0.0.0 www.{clean_domain}\n"
