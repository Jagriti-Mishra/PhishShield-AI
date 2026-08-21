import pytest
import os
import sys

# Ensure backend in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.url_analyzer import URLAnalyzer
from app.services.base import AnalysisContext
from app.db.vector_store import VectorStore

@pytest.fixture
def vector_store():
    return VectorStore()

@pytest.fixture
def url_analyzer(vector_store):
    return URLAnalyzer(vector_store)

def test_official_domain_zero_score(url_analyzer):
    ctx = AnalysisContext(
        raw_url="https://sbi.co.in/portal",
        normalized_url="https://sbi.co.in/portal",
        scheme="https",
        domain="sbi.co.in",
        subdomain="",
        suffix="co.in",
        path="/portal",
        is_official_brand=True,
        official_brand_name="sbi"
    )
    res = url_analyzer.analyze(ctx)
    assert res.score == 0.0
    assert res.details.get("is_official") is True

def test_combosquatting_phishing_domain(url_analyzer):
    ctx = AnalysisContext(
        raw_url="http://sbi-kyc-verification-update.top",
        normalized_url="http://sbi-kyc-verification-update.top",
        scheme="http",
        domain="sbi-kyc-verification-update.top",
        subdomain="",
        suffix="top",
        path="/",
        is_official_brand=False
    )
    res = url_analyzer.analyze(ctx)
    assert res.score >= 50.0
    assert res.details.get("matched_brand_typo") == "sbi"
    assert res.details.get("suspicious_tld") is True

def test_homoglyph_cyrillic_domain(url_analyzer):
    # 'а' is Cyrillic small letter a (U+0430) instead of ASCII 'a'
    homoglyph_domain = "pаypal.com"
    ctx = AnalysisContext(
        raw_url=f"http://{homoglyph_domain}",
        normalized_url=f"http://{homoglyph_domain}",
        scheme="http",
        domain=homoglyph_domain,
        subdomain="",
        suffix="com",
        path="/",
        is_official_brand=False
    )
    res = url_analyzer.analyze(ctx)
    assert res.details.get("has_homoglyphs") is True
    assert res.score >= 50.0

def test_raw_ip_address(url_analyzer):
    ctx = AnalysisContext(
        raw_url="http://192.168.1.50/login",
        normalized_url="http://192.168.1.50/login",
        scheme="http",
        domain="192.168.1.50",
        subdomain="",
        suffix="",
        path="/login",
        is_official_brand=False
    )
    res = url_analyzer.analyze(ctx)
    assert res.details.get("is_ip") is True
    assert res.score >= 50.0
