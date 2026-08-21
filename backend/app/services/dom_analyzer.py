import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import Dict, Any, List

from app.services.base import BaseAnalyzer, AnalysisContext, AnalysisResult
from app.db.vector_store import VectorStore
from app.core.config import settings

class DOMAnalyzer(BaseAnalyzer):
    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store

    @staticmethod
    def compute_dom_structure_hash(soup: BeautifulSoup) -> str:
        """Extracts top tag hierarchy sequence to fingerprint DOM structure."""
        tags = [tag.name for tag in soup.find_all() if tag.name not in ["script", "style", "meta", "link"]]
        tag_str = "-".join(tags[:60])
        return tag_str

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        if context.is_official_brand:
            return AnalysisResult(
                engine_name="DOM_CODE",
                score=0.0,
                weight=settings.WEIGHT_DOM_CODE,
                reasons=[],
                details={"form_action_mismatch": False, "is_official": True}
            )

        html_content = context.html_content
        if not html_content:
            return AnalysisResult(
                engine_name="DOM_CODE",
                score=0.0,
                weight=settings.WEIGHT_DOM_CODE,
                reasons=["No HTML source content retrieved for DOM tree inspection"],
                details={"html_empty": True}
            )

        soup = BeautifulSoup(html_content, "html.parser")
        page_host = context.domain.lower()

        score = 0.0
        reasons = []
        details = {}

        # 1. Form Action Destination & Credential Exfiltration Check
        forms = soup.find_all("form")
        form_mismatch_detected = False
        insecure_password_post = False
        has_password_field = False
        external_action_endpoints = []

        for form in forms:
            action = form.get("action", "").strip()
            inputs = form.find_all("input")
            
            contains_pass = any(i.get("type", "").lower() == "password" for i in inputs)
            if contains_pass:
                has_password_field = True

            if action:
                parsed_action = urlparse(action)
                action_host = parsed_action.netloc.split(":")[0].lower()
                
                # Check if form action targets an external domain or raw IP
                if action_host and action_host != page_host and not action_host.endswith(f".{page_host}"):
                    form_mismatch_detected = True
                    external_action_endpoints.append(action_host)
                    
                    if contains_pass:
                        insecure_password_post = True
                        score += 65.0
                        reasons.append(f"CRITICAL Credential Exfiltration: Login form posts passwords to unauthorized external host '{action_host}'")
                    else:
                        score += 35.0
                        reasons.append(f"Suspicious Form Action: Form submits user data to external host '{action_host}'")
                elif parsed_action.scheme == "http" and contains_pass:
                    insecure_password_post = True
                    score += 45.0
                    reasons.append("Insecure Authentication: Password form submits credentials over unencrypted plain HTTP")

        details["form_action_mismatch"] = form_mismatch_detected
        details["insecure_password_post"] = insecure_password_post
        details["has_password_field"] = has_password_field
        details["external_action_endpoints"] = external_action_endpoints

        # 2. JavaScript AST Obfuscation, Anti-Analysis & AitM Evasion Techniques
        scripts = soup.find_all("script")
        js_obfuscation_detected = False
        obfuscation_patterns = [
            (r"eval\s*\(\s*function", "Dynamic eval() unpacking"),
            (r"unescape\s*\(", "Obsolete unescape() decoding"),
            (r"\\x[0-9a-fA-F]{2}", "Hex-encoded string array literals"),
            (r"_0x[a-fA-F0-9]{4,}", "Polymorphic obfuscated variable mangling"),
            (r"String\.fromCharCode", "CharCode obfuscated strings"),
            (r"document\[['\"]write['\"]\]", "Dynamically written DOM injection"),
            (r"atob\s*\(", "Base64 payload execution"),
            (r"navigator\.webdriver", "Anti-Analysis: Headless browser & sandbox evasion"),
            (r"debugger\s*;", "Anti-Forensics: Anti-debugging execution trap"),
            (r"setInterval\s*\(\s*function\s*\(\s*\)\s*\{\s*debugger", "Continuous DevTools killer loop"),
            (r"window\.location\.replace", "Immediate client-side redirect"),
            (r"document\.cookie", "Session Token / Cookie Exfiltration Attempt")
        ]

        found_js_tricks = []
        for s in scripts:
            js_text = s.string or ""
            for pat, desc in obfuscation_patterns:
                if re.search(pat, js_text):
                    js_obfuscation_detected = True
                    if desc not in found_js_tricks:
                        found_js_tricks.append(desc)

        details["js_obfuscation_detected"] = js_obfuscation_detected
        details["obfuscation_techniques"] = found_js_tricks
        if js_obfuscation_detected:
            score += min(45.0, len(found_js_tricks) * 15.0)
            reasons.append(f"Adversarial / Evasive JavaScript Detected: {', '.join(found_js_tricks[:3])}")

        # 3. Brand Asset Leeching / Hotlinking from Official CDNs
        all_official_domains = self.vector_store.get_all_official_domains()
        images_and_links = soup.find_all(["img", "link", "script"])
        hotlinked_brands = []

        for elem in images_and_links:
            src = elem.get("src") or elem.get("href") or ""
            if "://" in src:
                src_host = urlparse(src).netloc.split(":")[0].lower()
                for off_dom, brand in all_official_domains.items():
                    if (src_host == off_dom or src_host.endswith(f".{off_dom}")) and (page_host != off_dom and not page_host.endswith(f".{off_dom}")):
                        if brand not in hotlinked_brands:
                            hotlinked_brands.append(brand)

        details["asset_theft_detected"] = bool(hotlinked_brands)
        details["hotlinked_brands"] = hotlinked_brands
        if hotlinked_brands:
            score += 40.0
            reasons.append(f"Brand Asset Leeching: Page hotlinks authentic logos/styles directly from official servers of: {', '.join(hotlinked_brands)}")

        # 4. Anti-Analysis / Right-Click & DevTools Blocker Detection
        raw_html_lower = html_content.lower()
        anti_analysis_detected = False
        if any(term in raw_html_lower for term in ["event.keycode == 123", "event.keycode==123", "oncontextmenu=\"return false\"", "onselectstart=\"return false\"", "debugger"]):
            anti_analysis_detected = True
            score += 25.0
            reasons.append("Anti-Forensic Code: Page disables right-click context menu and keyboard DevTools (F12) inspection")

        details["anti_analysis_detected"] = anti_analysis_detected

        final_score = min(100.0, round(score, 2))
        return AnalysisResult(
            engine_name="DOM_CODE",
            score=final_score,
            weight=settings.WEIGHT_DOM_CODE,
            reasons=reasons,
            details=details
        )
