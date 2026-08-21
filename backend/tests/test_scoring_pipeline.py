import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.pipeline import AnalysisPipeline
from app.db.vector_store import VectorStore

@pytest.fixture
def pipeline():
    return AnalysisPipeline(VectorStore())

def test_official_brand_domain_zero_false_positives(pipeline):
    # Official SBI domain must be guaranteed 0% risk score
    res = pipeline.analyze("https://sbi.co.in")
    assessment = res["assessment"]
    assert assessment["overall_score"] == 0.0
    assert assessment["risk_level"] == "SAFE"
    assert assessment["is_official_brand"] is True

def test_official_paypal_domain_zero_false_positives(pipeline):
    res = pipeline.analyze("https://www.paypal.com/signin")
    assessment = res["assessment"]
    assert assessment["overall_score"] == 0.0
    assert assessment["risk_level"] == "SAFE"
    assert assessment["is_official_brand"] is True

def test_sbi_phishing_combosquatted_domain(pipeline):
    res = pipeline.analyze("http://sbi-online-kyc-update.top")
    assessment = res["assessment"]
    assert assessment["overall_score"] >= 85.0
    assert assessment["risk_level"] in ["HIGH PHISHING", "CRITICAL PHISHING"]
    assert len(assessment["explainable_reasons"]) > 0

def test_paypal_phishing_domain(pipeline):
    res = pipeline.analyze("http://paypal-login-secure-auth.xyz")
    assessment = res["assessment"]
    assert assessment["overall_score"] >= 85.0
    assert assessment["risk_level"] in ["HIGH PHISHING", "CRITICAL PHISHING"]
