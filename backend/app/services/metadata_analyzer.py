from urllib.parse import urlparse
from typing import Dict, Any

from app.services.base import BaseAnalyzer, AnalysisContext, AnalysisResult
from app.core.config import settings

class MetadataAnalyzer(BaseAnalyzer):
    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        if context.is_official_brand:
            return AnalysisResult(
                engine_name="METADATA_SSL",
                score=0.0,
                weight=settings.WEIGHT_METADATA_SSL,
                reasons=[],
                details={"is_https": True, "has_hsts": True, "has_csp": True}
            )

        headers = {k.lower(): v for k, v in context.headers.items()}
        is_https = (context.scheme.lower() == "https")

        score = 0.0
        reasons = []
        details = {
            "is_https": is_https,
            "has_hsts": False,
            "has_csp": False,
            "has_xframe": False
        }

        # 1. Plain HTTP Check
        if not is_https:
            score += 45.0
            reasons.append("Unencrypted Connection: Target lacks HTTPS SSL/TLS encryption")

        # 2. Strict Transport Security (HSTS)
        if "strict-transport-security" in headers:
            details["has_hsts"] = True
        elif is_https:
            score += 15.0
            reasons.append("Missing HSTS (Strict-Transport-Security) transport layer protection")

        # 3. Content Security Policy (CSP)
        if "content-security-policy" in headers:
            details["has_csp"] = True
        else:
            score += 10.0
            reasons.append("Missing Content-Security-Policy (CSP) anti-XSS header")

        # 4. Clickjacking Protection (X-Frame-Options)
        if "x-frame-options" in headers or "frame-ancestors" in headers.get("content-security-policy", ""):
            details["has_xframe"] = True
        else:
            score += 10.0
            reasons.append("Missing X-Frame-Options: Page is vulnerable to UI clickjacking/overlay attacks")

        final_score = min(100.0, round(score, 2))
        return AnalysisResult(
            engine_name="METADATA_SSL",
            score=final_score,
            weight=settings.WEIGHT_METADATA_SSL,
            reasons=reasons,
            details=details
        )
