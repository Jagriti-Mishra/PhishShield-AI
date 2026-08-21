import pytest
import os
import sys
from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.vision_analyzer import VisionAnalyzer
from app.services.base import AnalysisContext
from app.db.vector_store import VectorStore
from app.core.config import settings

@pytest.fixture
def vector_store():
    return VectorStore()

@pytest.fixture
def vision_analyzer(vector_store):
    return VisionAnalyzer(vector_store)

def test_visual_clone_detection(vision_analyzer):
    # Use pre-generated SBI template
    template_path = os.path.join(settings.BRANDS_DIR, "templates", "sbi_template.png")
    if not os.path.exists(template_path):
        pytest.skip("SBI template not present")

    ctx = AnalysisContext(
        raw_url="http://sbi-fake-portal.top",
        normalized_url="http://sbi-fake-portal.top",
        scheme="http",
        domain="sbi-fake-portal.top",
        subdomain="",
        suffix="top",
        path="/",
        screenshot_path=template_path,
        is_official_brand=False
    )
    res = vision_analyzer.analyze(ctx)
    assert res.details.get("is_clone") is True
    assert res.details.get("matched_brand") == "sbi"
    assert res.score >= 70.0
