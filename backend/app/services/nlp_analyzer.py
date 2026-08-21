import re
from bs4 import BeautifulSoup
from typing import Dict, Any, List

from app.services.base import BaseAnalyzer, AnalysisContext, AnalysisResult
from app.db.vector_store import VectorStore
from app.core.config import settings

# Semantic phishing pretext categories
URGENCY_KEYWORDS = [
    "urgent", "immediately", "within 24 hours", "action required", "suspended",
    "blocked", "terminated", "kyc update", "verify now", "account locked",
    "unauthorized activity", "security alert", "penalty", "compromised"
]

CREDENTIAL_BAITING_KEYWORDS = [
    "enter your password", "confirm your pin", "debit card details", "cvv",
    "otp", "one time password", "netbanking password", "aadhaar number",
    "pan card", "social security", "credit card number", "expiry date"
]

FINANCIAL_LURE_KEYWORDS = [
    "lottery", "cashback", "reward points", "refund pending", "claim 5000",
    "bonus credited", "income tax refund", "free subscription", "crypto giveaway"
]

class NLPAnalyzer(BaseAnalyzer):
    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        if context.is_official_brand:
            return AnalysisResult(
                engine_name="NLP_PRETEXT",
                score=0.0,
                weight=settings.WEIGHT_NLP_PRETEXT,
                reasons=[],
                details={"is_official": True}
            )

        html_content = context.html_content
        if not html_content:
            return AnalysisResult(
                engine_name="NLP_PRETEXT",
                score=0.0,
                weight=settings.WEIGHT_NLP_PRETEXT,
                reasons=[],
                details={"text_empty": True}
            )

        soup = BeautifulSoup(html_content, "html.parser")
        # Extract visible text content
        for element in soup(["script", "style", "meta", "noscript"]):
            element.extract()
        visible_text = soup.get_text(separator=" ").lower()
        title_text = (soup.title.string or "").lower() if soup.title else ""
        combined_text = f"{title_text} {visible_text}"

        score = 0.0
        reasons = []
        details = {}

        # 1. Detect Urgency / Coercion Pretext
        found_urgency = [kw for kw in URGENCY_KEYWORDS if kw in combined_text]
        details["urgency_triggers"] = found_urgency
        if found_urgency:
            score += min(35.0, len(found_urgency) * 12.0)
            reasons.append(f"Psychological Coercion: High-urgency threat triggers detected ({', '.join(found_urgency[:3])})")

        # 2. Detect Credential Baiting / PII Harvesting Language
        found_baiting = [kw for kw in CREDENTIAL_BAITING_KEYWORDS if kw in combined_text]
        details["credential_harvesting_triggers"] = found_baiting
        if found_baiting:
            score += min(40.0, len(found_baiting) * 15.0)
            reasons.append(f"Credential Harvesting Pretext: Requests sensitive data ({', '.join(found_baiting[:3])})")

        # 3. Detect Financial / Refund Lures
        found_lures = [kw for kw in FINANCIAL_LURE_KEYWORDS if kw in combined_text]
        details["financial_lures"] = found_lures
        if found_lures:
            score += 25.0
            reasons.append(f"Social Engineering Lure: Suspicious financial reward or refund lure ({', '.join(found_lures[:2])})")

        # 4. Brand Name Mention Mismatch (Page claims to be Brand X in Title/Body, but domain is NOT Brand X)
        all_brands = self.vector_store.get_all_brands()
        page_host = context.domain.lower()
        claimed_brand_mismatch = None

        # Pass 1: Prioritize exact brand name match
        for brand_name, data in all_brands.items():
            official_domains = data.get("official_domains", [])
            pattern = rf"\b{re.escape(brand_name)}\b"
            if re.search(pattern, title_text) or re.search(pattern, combined_text[:400]):
                is_legit = any(page_host == od or page_host.endswith(f".{od}") for od in official_domains)
                if not is_legit:
                    claimed_brand_mismatch = brand_name
                    break

        # Pass 2: Secondary keyword match if no direct brand name matched
        if not claimed_brand_mismatch:
            for brand_name, data in all_brands.items():
                keywords = data.get("keywords", [])
                official_domains = data.get("official_domains", [])
                for kw in keywords:
                    if kw == brand_name:
                        continue
                    pattern = rf"\b{re.escape(kw)}\b"
                    if re.search(pattern, title_text) or re.search(pattern, combined_text[:400]):
                        is_legit = any(page_host == od or page_host.endswith(f".{od}") for od in official_domains)
                        if not is_legit:
                            claimed_brand_mismatch = brand_name
                            break
                if claimed_brand_mismatch:
                    break

        details["claimed_brand_mismatch"] = claimed_brand_mismatch
        if claimed_brand_mismatch:
            score += 45.0
            reasons.append(f"Identity Pretext Mismatch: Webpage prominently presents as '{claimed_brand_mismatch.upper()}' but is hosted on unauthorized host '{page_host}'")

        final_score = min(100.0, round(score, 2))
        return AnalysisResult(
            engine_name="NLP_PRETEXT",
            score=final_score,
            weight=settings.WEIGHT_NLP_PRETEXT,
            reasons=reasons,
            details=details
        )
