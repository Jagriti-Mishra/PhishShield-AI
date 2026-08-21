// Injected Content Script for PhishShield AI
console.log("🛡️ PhishShield AI active on page:", window.location.href);

const API_URL = "http://127.0.0.1:8000/api/v1/analyze";

// Auto-scan page on load and inject real-time security warning banner if malicious
function autoScanPage() {
  const currentUrl = window.location.href;
  
  // Skip extension checking internal chrome/local pages
  if (currentUrl.startsWith("chrome://") || currentUrl.startsWith("about:") || currentUrl.includes("127.0.0.1:8000")) {
    return;
  }

  fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: currentUrl })
  })
  .then(res => res.json())
  .then(data => {
    const assessment = data.assessment || {};
    const level = assessment.risk_level;
    const score = assessment.overall_score || 0;

    if (level === "CRITICAL PHISHING" || level === "HIGH PHISHING" || level === "SUSPICIOUS") {
      injectWarningBanner(level, score, assessment.explainable_reasons || []);
    }
  })
  .catch(err => {
    // API backend offline
  });
}

function injectWarningBanner(level, score, reasons) {
  if (document.getElementById("phishshield-alert-banner")) return;

  const isCritical = (level === "CRITICAL PHISHING");
  const bgGradient = isCritical ? "linear-gradient(90deg, #dc2626, #991b1b)" : "linear-gradient(90deg, #d97706, #b45309)";
  const icon = isCritical ? "🚨" : "⚠️";

  const banner = document.createElement("div");
  banner.id = "phishshield-alert-banner";
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    background: ${bgGradient};
    color: #ffffff;
    padding: 12px 20px;
    z-index: 2147483647;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 13px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.5);
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-sizing: border-box;
  `;

  const topReason = reasons[0] || "Potential credential theft attempt detected.";

  banner.innerHTML = `
    <div style="display: flex; align-items: center; gap: 12px;">
      <span style="font-size: 22px;">${icon}</span>
      <div>
        <strong style="font-size: 14px; letter-spacing: 0.5px;">PHISHSHIELD AI WARNING: ${level} (${score}%)</strong>
        <div style="font-size: 11px; opacity: 0.9; margin-top: 2px;">${topReason} — Do NOT enter login credentials on this website.</div>
      </div>
    </div>
    <button id="phishshield-close-banner" style="background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.4); color: white; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: 700; font-size: 11px;">Dismiss Banner</button>
  `;

  document.body.insertBefore(banner, document.body.firstChild);

  document.getElementById("phishshield-close-banner").addEventListener("click", () => {
    banner.remove();
  });
}

// Run auto-scan when page DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", autoScanPage);
} else {
  autoScanPage();
}

// Listen for messages from extension popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getPageInfo") {
    sendResponse({
      url: window.location.href,
      domain: window.location.hostname,
      hasPasswordInput: !!document.querySelector("input[type='password']"),
      formActions: Array.from(document.querySelectorAll("form")).map(f => f.action)
    });
  }
  return true;
});
