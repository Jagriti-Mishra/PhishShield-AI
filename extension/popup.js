const API_URL = "http://127.0.0.1:8000/api/v1/analyze";
const DASHBOARD_URL = "http://127.0.0.1:8000/dashboard/index.html";

document.addEventListener("DOMContentLoaded", () => {
  const currentUrlEl = document.getElementById("current-url");
  const badgePill = document.getElementById("badge-pill");
  const riskValueEl = document.getElementById("risk-score-value");
  const progressFill = document.getElementById("progress-fill");
  const bVision = document.getElementById("b-vision");
  const bDom = document.getElementById("b-dom");
  const bUrl = document.getElementById("b-url");
  const bMeta = document.getElementById("b-meta");
  const reasonsList = document.getElementById("reasons-list");
  const scanBtn = document.getElementById("scan-btn");
  const dashboardBtn = document.getElementById("dashboard-btn");

  function scanTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || !tabs[0] || !tabs[0].url) {
        currentUrlEl.textContent = "Unable to read active tab URL";
        return;
      }

      const activeUrl = tabs[0].url;
      currentUrlEl.textContent = activeUrl;
      reasonsList.innerHTML = "<li class='empty-msg'>Scanning URL & page visual layout...</li>";

      fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: activeUrl })
      })
      .then(res => res.json())
      .then(data => {
        const assessment = data.assessment || {};
        const score = assessment.overall_score || 0;
        const level = assessment.risk_level || "SAFE";
        const breakdown = assessment.breakdown || {};

        riskValueEl.textContent = `${score}%`;
        progressFill.style.width = `${score}%`;

        // Update badge and colors
        badgePill.className = "badge";
        progressFill.className = "progress-fill";

        if (level === "CRITICAL PHISHING") {
          badgePill.classList.add("badge-critical");
          badgePill.textContent = "CRITICAL";
          progressFill.classList.add("fill-critical");
        } else if (level === "SUSPICIOUS") {
          badgePill.classList.add("badge-warning");
          badgePill.textContent = "SUSPICIOUS";
          progressFill.classList.add("fill-warning");
        } else {
          badgePill.classList.add("badge-safe");
          badgePill.textContent = "SAFE";
          progressFill.classList.add("fill-safe");
        }

        // Breakdown scores
        bVision.textContent = `${breakdown.vision?.score || 0}%`;
        bDom.textContent = `${breakdown.dom?.score || 0}%`;
        bUrl.textContent = `${breakdown.url?.score || 0}%`;
        bMeta.textContent = `${breakdown.metadata?.score || 0}%`;

        // Reasons
        const reasons = assessment.explainable_reasons || [];
        if (reasons.length === 0) {
          reasonsList.innerHTML = "<li class='empty-msg'>✅ No security anomalies detected. Site appears legitimate.</li>";
        } else {
          reasonsList.innerHTML = reasons.map(r => `<li>⚠️ ${r}</li>`).join("");
        }
      })
      .catch(err => {
        console.error("Scan error:", err);
        reasonsList.innerHTML = "<li class='empty-msg'>❌ Unable to connect to PhishShield API Server (Is FastAPI backend running on port 8000?)</li>";
      });
    });
  }

  scanBtn.addEventListener("click", scanTab);
  dashboardBtn.addEventListener("click", () => {
    chrome.tabs.create({ url: DASHBOARD_URL });
  });

  scanTab();
});
