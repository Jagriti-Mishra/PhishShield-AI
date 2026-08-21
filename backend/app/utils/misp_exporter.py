import uuid
from datetime import datetime
from typing import Dict, Any

class MISPExporter:
    def generate_event(self, url: str, domain: str, assessment: Dict[str, Any]) -> Dict[str, Any]:
        event_uuid = str(uuid.uuid4())
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        score = assessment.get("overall_score", 0.0)
        risk_level = assessment.get("risk_level", "UNKNOWN")
        matched_brand = assessment.get("matched_brand", "Unknown")

        event = {
            "Event": {
                "uuid": event_uuid,
                "info": f"PhishShield AI: Malicious Phishing Campaign Impersonating {matched_brand} ({domain})",
                "date": now[:10],
                "threat_level_id": "1" if score >= 70 else "2",
                "analysis": "2",
                "distribution": "3",
                "Attribute": [
                    {
                        "type": "url",
                        "category": "Network activity",
                        "to_ids": True,
                        "value": url,
                        "comment": f"Phishing URL with AI Risk Score {score}%"
                    },
                    {
                        "type": "domain",
                        "category": "Network activity",
                        "to_ids": True,
                        "value": domain,
                        "comment": f"Deceptive Domain Impersonating {matched_brand}"
                    }
                ],
                "Tag": [
                    {"name": "tlp:amber+strict"},
                    {"name": f"brand:{matched_brand}"},
                    {"name": f"confidence:{int(score)}"}
                ]
            }
        }
        return event
