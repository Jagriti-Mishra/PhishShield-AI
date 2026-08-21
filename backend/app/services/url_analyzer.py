import re
import math
import unicodedata
from urllib.parse import urlparse
import Levenshtein
import tldextract

from app.services.base import BaseAnalyzer, AnalysisContext, AnalysisResult
from app.db.vector_store import VectorStore
from app.core.config import settings

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".site", ".info", ".online", ".work", ".click",
    ".cf", ".gq", ".ml", ".biz", ".icu", ".cam", ".rest", ".buzz", ".monster",
    ".fit", ".cfd", ".sbs", ".quest"
}

# Common homoglyph mappings (Cyrillic/Greek/Latin lookalikes)
HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ν': 'v', 'α': 'a', 'ο': 'o'
}

class URLAnalyzer(BaseAnalyzer):
    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculates Shannon Entropy of a string to detect Domain Generation Algorithms (DGA)."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum(p * math.log(p, 2) for p in prob)
        return round(entropy, 3)

    @staticmethod
    def detect_homoglyphs(domain: str) -> tuple[bool, str]:
        """Detects if non-ASCII characters or Unicode lookalikes are present in the domain."""
        has_homoglyphs = False
        normalized_chars = []
        for char in domain:
            if char in HOMOGLYPH_MAP:
                has_homoglyphs = True
                normalized_chars.append(HOMOGLYPH_MAP[char])
            elif not char.isascii():
                has_homoglyphs = True
                norm = unicodedata.normalize('NFKD', char)
                normalized_chars.append(norm if norm.isascii() else char)
            else:
                normalized_chars.append(char)
        return has_homoglyphs, "".join(normalized_chars)

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        domain = context.domain.lower()
        full_url = context.normalized_url.lower()

        # Check official whitelist
        if context.is_official_brand:
            return AnalysisResult(
                engine_name="URL_WHOIS",
                score=0.0,
                weight=settings.WEIGHT_URL_WHOIS,
                reasons=[f"Domain '{domain}' is a verified official brand domain for '{context.official_brand_name}'."],
                details={"is_official": True, "brand": context.official_brand_name}
            )

        score = 0.0
        reasons = []
        details = {}

        # 1. IP Address Host Check
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))
        details["is_ip"] = is_ip
        if is_ip:
            score += 50.0
            reasons.append("Raw IPv4 address used as host instead of registered domain name")

        # 2. Homoglyph Detection
        has_homoglyphs, normalized_domain = self.detect_homoglyphs(domain)
        details["has_homoglyphs"] = has_homoglyphs
        if has_homoglyphs:
            score += 55.0
            reasons.append(f"Unicode Homoglyph / Confusable characters detected in domain (Resolves to: '{normalized_domain}')")

        # 3. Domain Shannon Entropy (DGA Detection)
        ext = tldextract.extract(domain)
        domain_sld = ext.domain
        entropy = self.calculate_entropy(domain_sld)
        details["domain_entropy"] = entropy
        if entropy > 3.8 and len(domain_sld) > 10:
            score += 25.0
            reasons.append(f"High domain character entropy ({entropy}) indicates algorithmically generated (DGA) phishing domain")

        # 4. Suspicious TLD
        tld_dot = f".{ext.suffix}"
        is_suspicious_tld = tld_dot in SUSPICIOUS_TLDS
        details["suspicious_tld"] = is_suspicious_tld
        if is_suspicious_tld:
            score += 20.0
            reasons.append(f"Domain uses high-abuse / high-risk top-level domain: '{tld_dot}'")

        # 5. Excessive Subdomain Nesting
        subdomain_parts = ext.subdomain.split(".") if ext.subdomain else []
        subdomain_count = len([p for p in subdomain_parts if p])
        details["subdomain_depth"] = subdomain_count
        if subdomain_count >= 2:
            score += 15.0
            reasons.append(f"Excessive subdomain depth ({subdomain_count} levels) used to mask real destination")

        # 6. Brand Keyword Typosquatting / Combosquatting
        all_brands = self.vector_store.get_all_brands()
        matched_brand_typo = None
        min_distance = 999

        for brand_name, data in all_brands.items():
            # Combosquatting: brand name in domain/subdomain with hyphens/keywords (e.g. sbi-kyc-update, paypal-security)
            if brand_name in domain:
                matched_brand_typo = brand_name
                min_distance = 0
                score += 50.0
                reasons.append(f"Combosquatting: Legitimate brand '{brand_name}' embedded in unauthorized domain '{domain}'")
                break
            
            # Typosquatting (Levenshtein distance 1 or 2)
            dist = Levenshtein.distance(domain_sld, brand_name)
            if 1 <= dist <= 2 and len(brand_name) >= 3:
                matched_brand_typo = brand_name
                min_distance = dist
                score += 45.0
                reasons.append(f"Typosquatting: Domain '{domain_sld}' is an edit-distance clone ({dist}) of brand '{brand_name}'")
                break

        details["matched_brand_typo"] = matched_brand_typo
        details["levenshtein_distance"] = min_distance if min_distance != 999 else None

        # 7. Suspicious Keywords in URL Path
        suspicious_keywords = ["login", "signin", "verify", "secure", "update", "banking", "kyc", "account", "wallet", "recover", "authenticate"]
        found_keywords = [kw for kw in suspicious_keywords if kw in full_url]
        details["suspicious_keywords"] = found_keywords
        if found_keywords and matched_brand_typo:
            score += 20.0
            reasons.append(f"High-risk security keywords in URL structure: {', '.join(found_keywords)}")

        final_score = min(100.0, round(score, 2))
        return AnalysisResult(
            engine_name="URL_WHOIS",
            score=final_score,
            weight=settings.WEIGHT_URL_WHOIS,
            reasons=reasons,
            details=details
        )
