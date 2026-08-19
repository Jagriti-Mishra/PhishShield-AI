import re
from urllib.parse import urlparse
import Levenshtein

try:
    from confusable_homoglyphs import confusables
    CONFUSABLES_AVAILABLE = True
except ImportError:
    CONFUSABLES_AVAILABLE = False

# Known high-target target brands and their official domains
TARGET_BRANDS = {
    "paypal": "paypal.com",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "apple": "apple.com",
    "icici": "icicibank.com"
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".site", ".info", ".online", ".work", ".click", ".cf", ".gq", ".ml", ".biz"}

class URLAnalyzer:
    def analyze(self, url: str) -> dict:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        netloc = parsed.netloc.split(":")[0].lower()
        path = parsed.path.lower()

        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", netloc))
        
        # Split domain parts
        parts = netloc.split(".")
        tld = f".{parts[-1]}" if len(parts) > 1 else ""
        domain_name = parts[-2] if len(parts) >= 2 else netloc
        
        # 1. Check if domain is an official domain or legitimate subdomain of a target brand
        is_official = False
        matched_official_brand = None
        for brand, official_domain in TARGET_BRANDS.items():
            if netloc == official_domain or netloc.endswith("." + official_domain):
                is_official = True
                matched_official_brand = brand
                break

        # 2. Homoglyph Detection (Only for NON-ASCII strings containing Unicode homoglyphs)
        homoglyph_detected = False
        if not netloc.isascii():
            if CONFUSABLES_AVAILABLE:
                try:
                    homoglyph_detected = bool(confusables.is_confusable(netloc))
                except Exception:
                    homoglyph_detected = True
            else:
                homoglyph_detected = True

        # 3. Brand Typosquatting Check (Only if NOT an official domain)
        typosquatting_detected = False
        target_brand_matched = None
        min_distance = 999

        if not is_official:
            for brand, official_domain in TARGET_BRANDS.items():
                # Check if brand keyword is in subdomain/domain name, but domain is NOT official
                if brand in netloc:
                    typosquatting_detected = True
                    target_brand_matched = brand
                    min_distance = 0
                    break
                    
                dist = Levenshtein.distance(domain_name, brand)
                if 1 <= dist <= 2:
                    typosquatting_detected = True
                    target_brand_matched = brand
                    min_distance = dist
                    break

        # Scoring heuristics (Aggressive Phishing Threat Weights)
        score = 0.0
        reasons = []

        if is_official:
            # Verified official brand domain -> Score is 0
            score = 0.0
        else:
            if is_ip:
                score += 65.0
                reasons.append("Raw IP address used instead of domain name")

            if homoglyph_detected:
                score += 65.0
                reasons.append("Unicode Homoglyph attack characters detected in domain")

            if typosquatting_detected:
                score += 70.0
                reasons.append(f"Typosquatting detected against legitimate brand '{target_brand_matched}' (Distance: {min_distance})")

            if tld in SUSPICIOUS_TLDS:
                score += 25.0
                reasons.append(f"High-risk TLD detected: '{tld}'")

            if len(parts) > 3:
                score += 15.0
                reasons.append("Excessive subdomains used to obscure origin")

            if "-" in domain_name and typosquatting_detected:
                score += 15.0
                reasons.append("Suspicious hyphenation in brand-like domain")

            score = min(100.0, score)

        return {
            "score": round(score, 2),
            "netloc": netloc,
            "domain_name": domain_name,
            "is_official": is_official,
            "is_ip": is_ip,
            "homoglyph_detected": homoglyph_detected,
            "typosquatting_detected": typosquatting_detected,
            "target_brand_matched": target_brand_matched if typosquatting_detected else matched_official_brand,
            "levenshtein_distance": min_distance if min_distance != 999 else None,
            "suspicious_tld": tld in SUSPICIOUS_TLDS,
            "reasons": reasons
        }
