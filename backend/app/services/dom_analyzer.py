import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class DOMAnalyzer:
    def analyze(self, html_content: str, page_url: str) -> dict:
        if not html_content:
            return {
                "score": 0.0,
                "form_action_mismatch": False,
                "password_field_present": False,
                "insecure_password_post": False,
                "js_obfuscation_detected": False,
                "asset_theft_detected": False,
                "reasons": []
            }

        soup = BeautifulSoup(html_content, "html.parser")
        parsed_page = urlparse(page_url if "://" in page_url else f"http://{page_url}")
        page_host = parsed_page.netloc.split(":")[0].lower()

        score = 0.0
        reasons = []
        
        # 1. Form Action Destination Check
        forms = soup.find_all("form")
        form_action_mismatch = False
        insecure_password_post = False
        has_password = False

        for form in forms:
            action = form.get("action", "").strip()
            inputs = form.find_all("input")
            
            contains_pass = any(i.get("type", "").lower() == "password" for i in inputs)
            if contains_pass:
                has_password = True

            if action:
                parsed_action = urlparse(action)
                action_host = parsed_action.netloc.split(":")[0].lower()
                
                # Check if form action posts to different external host or raw IP
                if action_host and action_host != page_host and not action_host.endswith(f".{page_host}"):
                    form_action_mismatch = True
                    if contains_pass:
                        insecure_password_post = True
                        score += 50.0
                        reasons.append(f"CRITICAL: Login form posts credentials to external host '{action_host}'")
                    else:
                        score += 30.0
                        reasons.append(f"Form action posts data to external host '{action_host}'")
                elif parsed_action.scheme == "http" and contains_pass:
                    insecure_password_post = True
                    score += 40.0
                    reasons.append("Password input form submits over unencrypted HTTP protocol")

        # 2. Obfuscated JavaScript Detection
        scripts = soup.find_all("script")
        js_obfuscation = False
        obfuscation_patterns = [
            r"eval\s*\(\s*function",
            r"unescape\s*\(",
            r"\\x[0-9a-fA-F]{2}",
            r"String\.fromCharCode",
            r"document\[['\"]write['\"]\]"
        ]

        for s in scripts:
            js_text = s.string or ""
            for pat in obfuscation_patterns:
                if re.search(pat, js_text):
                    js_obfuscation = True
                    break
            if js_obfuscation:
                break

        if js_obfuscation:
            score += 25.0
            reasons.append("Obfuscated or dynamically evaluated JavaScript code detected")

        # 3. Asset Theft Detection (Fetching brand logos from official CDNs on unofficial domain)
        images = soup.find_all(["img", "link"])
        asset_theft = False
        trusted_cdns = ["paypal.com", "sbi.co.in", "hdfcbank.com", "google.com", "microsoft.com", "apple.com"]

        for img in images:
            src = img.get("src") or img.get("href") or ""
            if "://" in src:
                img_host = urlparse(src).netloc.split(":")[0].lower()
                if img_host and img_host != page_host:
                    for cdn in trusted_cdns:
                        if cdn in img_host and cdn not in page_host:
                            asset_theft = True
                            break
            if asset_theft:
                break

        if asset_theft:
            score += 30.0
            reasons.append("Hotlinking / Asset theft: Stolen brand logos loaded directly from official brand servers")

        score = min(100.0, score)

        return {
            "score": round(score, 2),
            "form_action_mismatch": form_action_mismatch,
            "password_field_present": has_password,
            "insecure_password_post": insecure_password_post,
            "js_obfuscation_detected": js_obfuscation,
            "asset_theft_detected": asset_theft,
            "reasons": reasons
        }
