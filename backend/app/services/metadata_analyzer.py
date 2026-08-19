from urllib.parse import urlparse
import datetime

class MetadataAnalyzer:
    def analyze(self, url: str, headers: dict = None) -> dict:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        scheme = parsed.scheme.lower()

        score = 0.0
        reasons = []

        is_https = (scheme == "https")
        if not is_https:
            score += 35.0
            reasons.append("Unencrypted connection: Website lacks HTTPS / SSL Encryption")

        # Security Headers Inspection
        headers = headers or {}
        has_hsts = "strict-transport-security" in [k.lower() for k in headers.keys()]
        has_csp = "content-security-policy" in [k.lower() for k in headers.keys()]

        if is_https and not has_hsts:
            score += 15.0
            reasons.append("Missing Strict-Transport-Security (HSTS) protection header")

        if not has_csp:
            score += 10.0
            reasons.append("Missing Content-Security-Policy (CSP) anti-XSS header")

        score = min(100.0, score)

        return {
            "score": round(score, 2),
            "is_https": is_https,
            "has_hsts": has_hsts,
            "has_csp": has_csp,
            "reasons": reasons
        }
