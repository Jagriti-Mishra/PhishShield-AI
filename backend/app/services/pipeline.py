import os
import time
from urllib.parse import urlparse
import tldextract
from typing import Dict, Any, Optional

from app.services.base import AnalysisContext, AnalysisResult, BaseAnalyzer
from app.services.crawler import StealthCrawler
from app.services.url_analyzer import URLAnalyzer
from app.services.whois_analyzer import WHOISAnalyzer
from app.services.vision_analyzer import VisionAnalyzer
from app.services.dom_analyzer import DOMAnalyzer
from app.services.nlp_analyzer import NLPAnalyzer
from app.services.metadata_analyzer import MetadataAnalyzer
from app.services.scoring_engine import ScoringEngine
from app.db.vector_store import VectorStore
from app.core.logging import logger

class AnalysisPipeline:
    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store
        self.crawler = StealthCrawler()
        self.url_analyzer = URLAnalyzer(vector_store)
        self.whois_analyzer = WHOISAnalyzer()
        self.vision_analyzer = VisionAnalyzer(vector_store)
        self.dom_analyzer = DOMAnalyzer(vector_store)
        self.nlp_analyzer = NLPAnalyzer(vector_store)
        self.metadata_analyzer = MetadataAnalyzer()
        self.scoring_engine = ScoringEngine()

    def create_context(self, raw_url: str) -> AnalysisContext:
        formatted_url = raw_url.strip()
        if not (formatted_url.startswith("http://") or formatted_url.startswith("https://")):
            formatted_url = f"http://{formatted_url}"

        parsed = urlparse(formatted_url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.split(":")[0].lower()
        path = parsed.path or "/"

        ext = tldextract.extract(netloc)
        subdomain = ext.subdomain
        suffix = ext.suffix
        domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else netloc

        # Check official brand whitelist
        all_official_domains = self.vector_store.get_all_official_domains()
        is_official = False
        official_brand_name = None

        for off_dom, b_name in all_official_domains.items():
            if netloc == off_dom or netloc.endswith(f".{off_dom}"):
                is_official = True
                official_brand_name = b_name
                break

        return AnalysisContext(
            raw_url=raw_url,
            normalized_url=formatted_url,
            scheme=scheme,
            domain=netloc,
            subdomain=subdomain,
            suffix=suffix,
            path=path,
            is_official_brand=is_official,
            official_brand_name=official_brand_name
        )

    def analyze(self, raw_url: str) -> Dict[str, Any]:
        start_time = time.time()
        context = self.create_context(raw_url)

        # 1. Execute Stealth Crawler
        screenshot_path, html_content, headers = self.crawler.capture(context.normalized_url)
        context.screenshot_path = screenshot_path
        context.html_content = html_content
        context.headers = headers

        # 2. Execute Multimodal Strategy Analyzers
        results: Dict[str, AnalysisResult] = {}

        results["URL_WHOIS"] = self.url_analyzer.analyze(context)
        results["WHOIS_AGE"] = self.whois_analyzer.analyze(context)
        results["VISION"] = self.vision_analyzer.analyze(context)
        results["DOM_CODE"] = self.dom_analyzer.analyze(context)
        results["NLP_PRETEXT"] = self.nlp_analyzer.analyze(context)
        results["METADATA_SSL"] = self.metadata_analyzer.analyze(context)

        # 3. Compute Calibrated Ensemble Score
        assessment = self.scoring_engine.compute(context, results)

        execution_time = round(time.time() - start_time, 3)

        return {
            "url": context.normalized_url,
            "domain": context.domain,
            "execution_time_seconds": execution_time,
            "screenshot_url": f"/captures/{os.path.basename(screenshot_path)}" if screenshot_path else None,
            "assessment": assessment,
            "details": {
                "url_analysis": results["URL_WHOIS"].details,
                "whois_analysis": results["WHOIS_AGE"].details,
                "vision_analysis": results["VISION"].details,
                "dom_analysis": results["DOM_CODE"].details,
                "nlp_analysis": results["NLP_PRETEXT"].details,
                "metadata_analysis": results["METADATA_SSL"].details
            }
        }
