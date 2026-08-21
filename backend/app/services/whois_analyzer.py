import datetime
import socket
from typing import Dict, Any, Optional
import requests
from app.services.base import BaseAnalyzer, AnalysisContext, AnalysisResult
from app.core.config import settings
from app.core.logging import logger

HIGH_RISK_REGISTRARS = [
    "namesilo", "tucows", "reg.ru", "namecheap", "freenom", "hostinger", "dynadot"
]

class WHOISAnalyzer(BaseAnalyzer):
    def fetch_rdap_info(self, domain: str) -> Dict[str, Any]:
        """Queries public open-source RDAP (Registration Data Access Protocol) for WHOIS records."""
        clean_domain = domain.split(":")[0].lower()
        rdap_url = f"https://rdap.org/domain/{clean_domain}"
        
        try:
            resp = requests.get(rdap_url, timeout=3, headers={"Accept": "application/rdap+json"})
            if resp.status_code == 200:
                data = resp.json()
                # Parse registration and expiration dates
                reg_date = None
                exp_date = None
                for event in data.get("events", []):
                    action = event.get("eventAction")
                    event_date = event.get("eventDate")
                    if action in ["registration", "created"]:
                        reg_date = event_date
                    elif action in ["expiration", "expires"]:
                        exp_date = event_date

                # Parse Registrar
                registrar = "Unknown"
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    registrar = item[3]
                                    break

                return {
                    "available": True,
                    "registered_at": reg_date,
                    "expires_at": exp_date,
                    "registrar": registrar,
                    "status": data.get("status", [])
                }
        except Exception as e:
            logger.debug(f"RDAP lookup error for {domain}: {e}")

        return {"available": False, "registrar": "Unknown", "registered_at": None}

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        if context.is_official_brand:
            return AnalysisResult(
                engine_name="WHOIS_AGE",
                score=0.0,
                weight=0.10,
                reasons=[],
                details={"domain_age_days": 3650, "is_newly_registered": False}
            )

        domain = context.domain.lower()
        rdap_data = self.fetch_rdap_info(domain)
        context.whois_data = rdap_data

        score = 0.0
        reasons = []
        details = rdap_data.copy()

        domain_age_days = None
        is_nrd = False

        if rdap_data.get("registered_at"):
            try:
                # Parse ISO date string (e.g. 2026-08-15T10:00:00Z)
                date_str = rdap_data["registered_at"][:10]
                reg_dt = datetime.datetime.strptime(date_str, "%Y-%m-%d")
                now = datetime.datetime.utcnow()
                domain_age_days = (now - reg_dt).days
                details["domain_age_days"] = domain_age_days

                # Newly Registered Domain (NRD) Heuristic (< 30 days is high risk; < 7 days is critical)
                if domain_age_days < 7:
                    is_nrd = True
                    score += 60.0
                    reasons.append(f"Newly Registered Domain (NRD): Domain created only {domain_age_days} day(s) ago")
                elif domain_age_days < 30:
                    is_nrd = True
                    score += 40.0
                    reasons.append(f"Young Domain: Domain registered within the last {domain_age_days} days")
                elif domain_age_days < 90:
                    score += 20.0
                    reasons.append(f"Recently registered domain ({domain_age_days} days old)")
            except Exception:
                pass

        details["is_newly_registered"] = is_nrd

        # Registrar Risk Profiling
        registrar_name = rdap_data.get("registrar", "").lower()
        for risky in HIGH_RISK_REGISTRARS:
            if risky in registrar_name:
                score += 15.0
                reasons.append(f"Registered via high-velocity registrar commonly exploited in phishing campaigns ({rdap_data.get('registrar')})")
                break

        final_score = min(100.0, round(score, 2))
        return AnalysisResult(
            engine_name="WHOIS_AGE",
            score=final_score,
            weight=0.10,
            reasons=reasons,
            details=details
        )
