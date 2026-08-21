import random
from typing import Dict, Any

class SuricataExporter:
    def generate_rule(self, domain: str, assessment: Dict[str, Any]) -> str:
        clean_domain = domain.split(":")[0].lower()
        sid = random.randint(3000000, 3999999)
        score = assessment.get("overall_score", 0.0)
        matched_brand = assessment.get("matched_brand", "Unknown")

        rule = (
            f'alert dns $HOME_NET any -> any 53 (msg:"PHISHSHIELD-AI High Risk Phishing Domain Lookup ({clean_domain} -> {matched_brand})"; '
            f'dns.query; content:"{clean_domain}"; nocase; '
            f'classtype:trojan-activity; sid:{sid}; rev:1; '
            f'metadata:created_by PhishShield_AI, confidence {int(score)};)\n\n'
            f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PHISHSHIELD-AI HTTP Request to Brand Impersonator ({clean_domain})"; '
            f'http.host; content:"{clean_domain}"; nocase; '
            f'classtype:trojan-activity; sid:{sid+1}; rev:1;)\n'
        )
        return rule
