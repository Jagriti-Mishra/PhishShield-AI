import uuid
from datetime import datetime
from typing import Dict, Any

class STIXExporter:
    def generate_bundle(self, url: str, domain: str, assessment: Dict[str, Any], details: Dict[str, Any] = None) -> Dict[str, Any]:
        bundle_id = f"bundle--{uuid.uuid4()}"
        indicator_id = f"indicator--{uuid.uuid4()}"
        identity_id = f"identity--{uuid.uuid4()}"
        observed_id = f"observed-data--{uuid.uuid4()}"
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        overall_score = assessment.get("overall_score", 0.0)
        risk_level = assessment.get("risk_level", "UNKNOWN")
        reasons = assessment.get("explainable_reasons", [])
        matched_brand = assessment.get("matched_brand", "Unknown")

        # Identity Object (PhishShield AI SOC Engine)
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "PhishShield AI Automated Threat Intelligence",
            "identity_class": "system"
        }

        # Indicator Object
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"Malicious Phishing Impersonator - {domain}",
            "description": f"Multimodal AI detected deceptive domain impersonating '{matched_brand}'. Risk Score: {overall_score}%. Findings: {'; '.join(reasons[:4])}",
            "pattern": f"[url:value = '{url}' OR domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": int(overall_score),
            "indicator_types": ["malicious-activity", "phishing", "impersonation"],
            "created_by_ref": identity_id
        }

        # Observed Data
        observed_data = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": now,
            "modified": now,
            "first_observed": now,
            "last_observed": now,
            "number_observed": 1,
            "objects": {
                "0": {
                    "type": "domain-name",
                    "value": domain
                },
                "1": {
                    "type": "url",
                    "value": url
                }
            }
        }

        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": [identity, indicator, observed_data]
        }
