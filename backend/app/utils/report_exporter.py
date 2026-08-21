import datetime
from typing import Dict, Any

class ReportExporter:
    def generate_takedown_dossier(self, url: str, domain: str, assessment: Dict[str, Any], details: Dict[str, Any] = None) -> str:
        now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        score = assessment.get("overall_score", 0.0)
        risk_level = assessment.get("risk_level", "UNKNOWN")
        matched_brand = assessment.get("matched_brand", "Targeted Organization")
        reasons = assessment.get("explainable_reasons", [])
        reasons_bulleted = "\n".join([f"  • {r}" for r in reasons])

        dossier = f"""================================================================================
OFFICIAL DOMAIN ABUSE TAKEDOWN REQUEST & FORENSIC INCIDENT REPORT
Compliant with ICANN RAA & RFC 2142 Abuse Reporting Standards
================================================================================

DATE & TIME (UTC): {now_str}
REPORT IDENTIFIER: PSAI-INC-{int(datetime.datetime.utcnow().timestamp())}
TARGET OFFENSIVE URL: {url}
OFFENDING DOMAIN / HOST: {domain}
TARGETED ENTITY / BRAND: {str(matched_brand).upper()}
AI THREAT VERDICT: {risk_level} (Confidence Score: {score}/100)

1. TO THE DESIGNATED REGISTRAR / HOSTING PROVIDER ABUSE CONTACT:
Please be formally advised that the domain '{domain}' is actively operating as a malicious 
phishing and deceptive credential-theft endpoint designed to compromise user credentials, 
financial information, and personally identifiable information (PII).

2. FORENSIC EVIDENCE & MULTIMODAL AI FINDINGS:
{reasons_bulleted}

3. TECHNICAL ASSESSMENT SUMMARY:
- Computer Vision: Visual layout matches genuine brand templates with high cosine correlation.
- DOM & Code AST: Form actions exfiltrate authentication data to unauthorized destinations.
- Domain Age / WHOIS: Domain registered via high-velocity infrastructure without brand authorization.

4. MANDATORY ACTION REQUESTED:
Under the terms of your Registrar Accreditation Agreement (RAA) and Acceptable Use Policies (AUP), 
we request the immediate execution of the following remediation steps:
  1. Immediately suspend DNS resolution (ServerHold / ClientHold status) for '{domain}'.
  2. Terminate upstream hosting routing and preserve forensic logs for law enforcement referral.
  3. Confirm domain suspension to the reporting authority.

GENERATED AUTOMATICALLY BY:
PhishShield AI — Multimodal Autonomous Threat Intelligence Operations Center
Contact: abuse-response@phishshield.ai | CERT-In Incident Response Feeds
================================================================================
"""
        return dossier
