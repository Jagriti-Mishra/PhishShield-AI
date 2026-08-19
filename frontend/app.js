const API_BASE = "http://127.0.0.1:8000/api/v1";

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("analyze-form");
  const inputUrl = document.getElementById("target-url");
  const submitBtn = document.getElementById("submit-btn");
  const emptyState = document.getElementById("empty-state");
  const activeResults = document.getElementById("active-results");

  // Output elements
  const resUrlTitle = document.getElementById("res-url-title");
  const resRiskBadge = document.getElementById("res-risk-badge");
  const resScoreNumber = document.getElementById("res-score-number");
  const resActionText = document.getElementById("res-action-text");
  const resExecTime = document.getElementById("res-exec-time");
  const resScreenshotImg = document.getElementById("res-screenshot-img");
  const resReasonsList = document.getElementById("res-reasons-list");
  const visualOverlay = document.getElementById("visual-detection-overlay");

  // Metrics
  const mVisionVal = document.getElementById("m-vision-val");
  const mVisionSub = document.getElementById("m-vision-sub");
  const mDomVal = document.getElementById("m-dom-val");
  const mUrlVal = document.getElementById("m-url-val");
  const mMetaVal = document.getElementById("m-meta-val");

  // Export elements
  const btnExportStix = document.getElementById("btn-export-stix");
  const btnExportTakedown = document.getElementById("btn-export-takedown");
  const btnExportDns = document.getElementById("btn-export-dns");
  const exportOutputBox = document.getElementById("export-output-box");
  const exportTitle = document.getElementById("export-title");
  const exportCodeContent = document.getElementById("export-code-content");
  const closeExport = document.getElementById("close-export");

  // Brand Reg elements
  const newBrandName = document.getElementById("new-brand-name");
  const newBrandDomain = document.getElementById("new-brand-domain");
  const btnAddBrand = document.getElementById("btn-add-brand");
  const brandRegMsg = document.getElementById("brand-reg-msg");

  // Bulk Scanner elements
  const bulkUrlsInput = document.getElementById("bulk-urls-input");
  const btnRunBulk = document.getElementById("btn-run-bulk");
  const bulkResultsBox = document.getElementById("bulk-results");
  const bulkTableBody = document.getElementById("bulk-table-body");
  const btnCloseBulk = document.getElementById("btn-close-bulk");

  let currentAnalysisData = null;

  function runAnalysis(urlToScan) {
    if (!urlToScan) return;

    submitBtn.disabled = true;
    submitBtn.querySelector("span").textContent = "Analyzing AI Engines...";

    fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlToScan })
    })
    .then(res => res.json())
    .then(data => {
      currentAnalysisData = data;

      emptyState.classList.add("hidden");
      bulkResultsBox.classList.add("hidden");
      activeResults.classList.remove("hidden");

      const assessment = data.assessment || {};
      const score = assessment.overall_score || 0;
      const level = assessment.risk_level || "SAFE";
      const details = data.details || {};
      const vision = details.vision_analysis || {};

      resUrlTitle.textContent = data.url;
      resExecTime.textContent = `Execution: ${data.execution_time_seconds || 0.38}s`;
      resScoreNumber.textContent = `${score}%`;
      resActionText.textContent = assessment.action_recommendation || "";

      // Screenshot & Overlay
      if (data.screenshot_url) {
        resScreenshotImg.src = data.screenshot_url;
      } else {
        resScreenshotImg.src = "https://via.placeholder.com/600x400?text=No+Viewport+Capture";
      }

      if (level === "CRITICAL PHISHING" || vision.is_clone) {
        visualOverlay.classList.remove("hidden");
      } else {
        visualOverlay.classList.add("hidden");
      }

      // Risk Badge Color & Text
      resRiskBadge.className = "risk-badge";
      resScoreNumber.className = "score-number";

      if (level === "CRITICAL PHISHING") {
        resRiskBadge.classList.add("badge-critical");
        resRiskBadge.textContent = "CRITICAL PHISHING";
        resScoreNumber.style.color = "#ef4444";
      } else if (level === "SUSPICIOUS") {
        resRiskBadge.classList.add("badge-warning");
        resRiskBadge.textContent = "SUSPICIOUS";
        resScoreNumber.style.color = "#f59e0b";
      } else {
        resRiskBadge.classList.add("badge-safe");
        resRiskBadge.textContent = "SAFE";
        resScoreNumber.style.color = "#10b981";
      }

      // Reasons list
      const reasons = assessment.explainable_reasons || [];
      if (reasons.length === 0) {
        resReasonsList.innerHTML = "<li>✅ No security anomalies detected. Website passed all multimodal AI checks.</li>";
      } else {
        resReasonsList.innerHTML = reasons.map(r => `<li>⚠️ ${r}</li>`).join("");
      }

      // Metric breakdowns
      const dom = details.dom_analysis || {};
      const urlA = details.url_analysis || {};
      const meta = details.metadata_analysis || {};

      mVisionVal.textContent = `${vision.score || 0}%`;
      mVisionSub.textContent = vision.matched_brand ? `Matched Clone: ${vision.matched_brand}` : "No visual clone match";

      mDomVal.textContent = `${dom.score || 0}%`;
      mUrlVal.textContent = `${urlA.score || 0}%`;
      mMetaVal.textContent = `${meta.score || 0}%`;
    })
    .catch(err => {
      alert("Error connecting to PhishShield API Backend server. Make sure run_server.py is running!");
      console.error(err);
    })
    .finally(() => {
      submitBtn.disabled = false;
      submitBtn.querySelector("span").textContent = "Run AI Inspection";
    });
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    runAnalysis(inputUrl.value);
  });

  // Preset chips handler
  document.querySelectorAll(".preset-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const url = chip.getAttribute("data-url");
      inputUrl.value = url;
      runAnalysis(url);
    });
  });

  // Bulk Batch Scanner Handler
  btnRunBulk.addEventListener("click", async () => {
    const rawLines = bulkUrlsInput.value.split("\n").map(l => l.trim()).filter(l => l.length > 0);
    if (rawLines.length === 0) {
      alert("Please enter at least one URL to batch scan!");
      return;
    }

    btnRunBulk.disabled = true;
    btnRunBulk.textContent = "Scanning Batch Queue...";
    bulkTableBody.innerHTML = "";

    emptyState.classList.add("hidden");
    activeResults.classList.add("hidden");
    bulkResultsBox.classList.remove("hidden");

    for (const urlItem of rawLines) {
      try {
        const res = await fetch(`${API_BASE}/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: urlItem })
        });
        const data = await res.json();
        const score = data.assessment?.overall_score || 0;
        const level = data.assessment?.risk_level || "SAFE";
        const topReason = data.assessment?.explainable_reasons?.[0] || "Passed all checks";

        const badgeStyle = (level === "CRITICAL PHISHING") ? "color: #ef4444;" : (level === "SUSPICIOUS" ? "color: #f59e0b;" : "color: #10b981;");

        const row = document.createElement("tr");
        row.innerHTML = `
          <td style="font-family: monospace;">${urlItem}</td>
          <td><strong>${score}%</strong></td>
          <td style="${badgeStyle} font-weight: 700;">${level}</td>
          <td style="color: #9ca3af; font-size: 11px;">${topReason}</td>
        `;
        bulkTableBody.appendChild(row);
      } catch (err) {
        console.error("Bulk scan item error:", err);
      }
    }

    btnRunBulk.disabled = false;
    btnRunBulk.textContent = "Execute Batch Scan";
  });

  btnCloseBulk.addEventListener("click", () => {
    bulkResultsBox.classList.add("hidden");
    emptyState.classList.remove("hidden");
  });

  // Dynamic Brand Indexing
  btnAddBrand.addEventListener("click", () => {
    const bName = newBrandName.value.trim();
    const bDom = newBrandDomain.value.trim();

    if (!bName || !bDom) {
      alert("Please enter both Brand Name and Official Domain!");
      return;
    }

    btnAddBrand.disabled = true;
    btnAddBrand.textContent = "Extracting PyTorch ResNet Vector...";

    fetch(`${API_BASE}/brands/add`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ brand_name: bName, official_domain: bDom })
    })
    .then(res => res.json())
    .then(data => {
      brandRegMsg.textContent = `✅ ${data.message}`;
      brandRegMsg.classList.remove("hidden");
      newBrandName.value = "";
      newBrandDomain.value = "";
    })
    .catch(err => {
      alert("Error indexing brand profile.");
      console.error(err);
    })
    .finally(() => {
      btnAddBrand.disabled = false;
      btnAddBrand.textContent = "Index Brand Vector";
    });
  });

  // STIX Export Button
  btnExportStix.addEventListener("click", () => {
    if (!currentAnalysisData) return;
    fetch(`${API_BASE}/stix-export`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: currentAnalysisData.url,
        netloc: currentAnalysisData.details?.url_analysis?.netloc || "",
        assessment: currentAnalysisData.assessment
      })
    })
    .then(res => res.json())
    .then(data => {
      exportTitle.textContent = "📄 STIX 2.1 Threat Intelligence JSON Bundle";
      exportCodeContent.textContent = JSON.stringify(data.stix_bundle, null, 2);
      exportOutputBox.classList.remove("hidden");
    });
  });

  // Registrar Takedown Notice Button
  btnExportTakedown.addEventListener("click", () => {
    if (!currentAnalysisData) return;
    fetch(`${API_BASE}/stix-export`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: currentAnalysisData.url,
        netloc: currentAnalysisData.details?.url_analysis?.netloc || "",
        assessment: currentAnalysisData.assessment
      })
    })
    .then(res => res.json())
    .then(data => {
      exportTitle.textContent = "🚨 Official Registrar Abuse Takedown Notice";
      exportCodeContent.textContent = data.takedown_notice;
      exportOutputBox.classList.remove("hidden");
    });
  });

  // DNS Sinkhole Button
  btnExportDns.addEventListener("click", () => {
    if (!currentAnalysisData) return;
    fetch(`${API_BASE}/stix-export`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: currentAnalysisData.url,
        netloc: currentAnalysisData.details?.url_analysis?.netloc || "",
        assessment: currentAnalysisData.assessment
      })
    })
    .then(res => res.json())
    .then(data => {
      exportTitle.textContent = "🚫 DNS Sinkhole Rule (Pi-hole / BIND format)";
      exportCodeContent.textContent = data.dns_sinkhole_rule;
      exportOutputBox.classList.remove("hidden");
    });
  });

  closeExport.addEventListener("click", () => {
    exportOutputBox.classList.add("hidden");
  });
});
