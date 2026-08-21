import pytest
import os
import sys
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.main import app

client = TestClient(app)

def test_api_health():
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "online"

def test_api_stats():
    resp = client.get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "accuracy_rate" in data

def test_api_list_brands():
    resp = client.get("/api/v1/brands")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] >= 10

def test_api_analyze_official():
    resp = client.post("/api/v1/analyze", json={"url": "https://sbi.co.in"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["assessment"]["risk_level"] == "SAFE"
    assert data["assessment"]["overall_score"] == 0.0

def test_api_analyze_phishing():
    resp = client.post("/api/v1/analyze", json={"url": "http://sbi-online-kyc-update.top"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["assessment"]["overall_score"] >= 80.0

def test_api_nrd_feed():
    resp = client.get("/api/v1/nrd/feed")
    assert resp.status_code == 200
    data = resp.json()
    assert "domains" in data

def test_api_export_threat_formats():
    payload = {
        "url": "http://sbi-online-kyc-update.top",
        "domain": "sbi-online-kyc-update.top",
        "assessment": {
            "overall_score": 96.0,
            "risk_level": "CRITICAL PHISHING",
            "matched_brand": "sbi",
            "explainable_reasons": ["Visual clone match", "Form action mismatch"]
        }
    }
    resp = client.post("/api/v1/export/all", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "stix_bundle" in data
    assert "misp_event" in data
    assert "suricata_rule" in data
    assert "dns_sinkhole_rule" in data
    assert "takedown_notice" in data

def test_api_brand_registration_blocks_phishing_combosquats():
    """Verify that registering a suspicious combosquatted domain is blocked with HTTP 422."""
    payload = {
        "brand_name": "sbi",
        "official_domain": "sbi-online-kyc-update.top"
    }
    resp = client.post("/api/v1/brands/add", json=payload)
    assert resp.status_code == 422
    assert "Registration Blocked" in resp.json()["detail"]

def test_api_brand_registration_cross_brand_conflict():
    """Verify that attempting to register an existing brand's domain under another brand fails with 409."""
    payload = {
        "brand_name": "hackerbrand",
        "official_domain": "sbi.co.in"
    }
    resp = client.post("/api/v1/brands/add", json=payload)
    assert resp.status_code == 409
    assert "Registration Conflict" in resp.json()["detail"]
