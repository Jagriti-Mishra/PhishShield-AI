import os
import time
import asyncio
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
from app.core.config import settings
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

    def _safe_analyze(self, analyzer: BaseAnalyzer, context: AnalysisContext, name: str, weight: float) -> AnalysisResult:
        try:
            return analyzer.analyze(context)
        except Exception as e:
            logger.error(f"Analyzer '{name}' failed: {e}")
            return AnalysisResult(engine_name=name, score=0.0, weight=weight, reasons=[f"Analysis failed: {str(e)}"], details={"error": str(e)})

    def analyze(self, raw_url: str) -> Dict[str, Any]:
        start_time = time.time()
        context = self.create_context(raw_url)

        # 1. Execute Stealth Crawler
        capture_res = self.crawler.capture(context.normalized_url)
        if len(capture_res) == 4:
            screenshot_path, html_content, headers, ssl_info = capture_res
            context.ssl_info = ssl_info
        else:
            screenshot_path, html_content, headers = capture_res[:3]

        context.screenshot_path = screenshot_path
        context.html_content = html_content
        context.headers = headers

        # 2. Execute Multimodal Strategy Analyzers
        results: Dict[str, AnalysisResult] = {}
        results["URL_WHOIS"] = self._safe_analyze(self.url_analyzer, context, "URL_WHOIS", settings.WEIGHT_URL_WHOIS)
        results["WHOIS_AGE"] = self._safe_analyze(self.whois_analyzer, context, "WHOIS_AGE", 0.10)
        results["VISION"] = self._safe_analyze(self.vision_analyzer, context, "VISION", settings.WEIGHT_VISION)
        results["DOM_CODE"] = self._safe_analyze(self.dom_analyzer, context, "DOM_CODE", settings.WEIGHT_DOM_CODE)
        results["NLP_PRETEXT"] = self._safe_analyze(self.nlp_analyzer, context, "NLP_PRETEXT", settings.WEIGHT_NLP_PRETEXT)
        results["METADATA_SSL"] = self._safe_analyze(self.metadata_analyzer, context, "METADATA_SSL", settings.WEIGHT_METADATA_SSL)

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

    async def analyze_async(self, raw_url: str) -> Dict[str, Any]:
        start_time = time.time()
        context = self.create_context(raw_url)

        # 1. Async Crawler Capture
        capture_res = await self.crawler.capture_async(context.normalized_url)
        if len(capture_res) == 4:
            screenshot_path, html_content, headers, ssl_info = capture_res
            context.ssl_info = ssl_info
        else:
            screenshot_path, html_content, headers = capture_res[:3]

        context.screenshot_path = screenshot_path
        context.html_content = html_content
        context.headers = headers

        # 2. Async Concurrent Execution of All 6 Analyzers
        tasks = [
            self.url_analyzer.analyze_async(context),
            self.whois_analyzer.analyze_async(context),
            self.vision_analyzer.analyze_async(context),
            self.dom_analyzer.analyze_async(context),
            self.nlp_analyzer.analyze_async(context),
            self.metadata_analyzer.analyze_async(context)
        ]

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        names = ["URL_WHOIS", "WHOIS_AGE", "VISION", "DOM_CODE", "NLP_PRETEXT", "METADATA_SSL"]
        weights = [settings.WEIGHT_URL_WHOIS, 0.10, settings.WEIGHT_VISION, settings.WEIGHT_DOM_CODE, settings.WEIGHT_NLP_PRETEXT, settings.WEIGHT_METADATA_SSL]

        results: Dict[str, AnalysisResult] = {}
        for name, weight, res in zip(names, weights, raw_results):
            if isinstance(res, Exception):
                logger.error(f"Async Analyzer '{name}' failed with error: {res}")
                results[name] = AnalysisResult(engine_name=name, score=0.0, weight=weight, reasons=[f"Error: {res}"], details={"error": str(res)})
            else:
                results[name] = res

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

