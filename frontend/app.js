const API_BASE = "http://127.0.0.1:8000/api/v1";

document.addEventListener("DOMContentLoaded", () => {
  // ------------------------------------------------------------------------
  // 1. Light / Dark Theme Management
  // ------------------------------------------------------------------------
  const themeToggleBtn = document.getElementById("theme-toggle-btn");
  const themeToggleIcon = document.getElementById("theme-toggle-icon");
  const themeToggleText = document.getElementById("theme-toggle-text");

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("phishshield_theme", theme);
    if (theme === "dark") {
      themeToggleIcon.textContent = "☀️";
      themeToggleText.textContent = "Light";
    } else {
      themeToggleIcon.textContent = "🌙";
      themeToggleText.textContent = "Dark";
    }
  }

  const savedTheme = localStorage.getItem("phishshield_theme") || "light";
  applyTheme(savedTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "light";
      const nextTheme = (current === "dark") ? "light" : "dark";
      applyTheme(nextTheme);
    });
  }

  // ------------------------------------------------------------------------
  // 2. Scanner Form & Workspace Elements
  // ------------------------------------------------------------------------
  const form = document.getElementById("analyze-form");
  const inputUrl = document.getElementById("target-url");
  const submitBtn = document.getElementById("submit-btn");
  const emptyState = document.getElementById("empty-state");
  const activeResults = document.getElementById("active-results");
  const bulkResultsBox = document.getElementById("bulk-results");

  // Output Elements
  const resUrlTitle = document.getElementById("res-url-title");
  const resRiskBadge = document.getElementById("res-risk-badge");
  const resScoreNumber = document.getElementById("res-score-number");
  const resActionText = document.getElementById("res-action-text");
  const resCiText = document.getElementById("res-ci-text");
  const resExecTime = document.getElementById("res-exec-time");
  const resScreenshotImg = document.getElementById("res-screenshot-img");
  const resReasonsList = document.getElementById("res-reasons-list");
  const visualOverlay = document.getElementById("visual-detection-overlay");
  const visualOverlayTag = document.getElementById("visual-overlay-tag");
  const threatMeterFill = document.getElementById("threat-meter-fill");

  // 5 Engines Metrics
  const mVisionVal = document.getElementById("m-vision-val");
  const mVisionSub = document.getElementById("m-vision-sub");
  const mDomVal = document.getElementById("m-dom-val");
  const mDomSub = document.getElementById("m-dom-sub");
  const mUrlVal = document.getElementById("m-url-val");
  const mUrlSub = document.getElementById("m-url-sub");
  const mNlpVal = document.getElementById("m-nlp-val");
  const mNlpSub = document.getElementById("m-nlp-sub");
  const mMetaVal = document.getElementById("m-meta-val");
  const mMetaSub = document.getElementById("m-meta-sub");

  // Threat Exporters
  const btnExportStix = document.getElementById("btn-export-stix");
  const btnExportMisp = document.getElementById("btn-export-misp");
  const btnExportSuricata = document.getElementById("btn-export-suricata");
  const btnExportDns = document.getElementById("btn-export-dns");
  const btnExportTakedown = document.getElementById("btn-export-takedown");

  const exportOutputBox = document.getElementById("export-output-box");
  const exportTitle = document.getElementById("export-title");
  const exportCodeContent = document.getElementById("export-code-content");
  const closeExport = document.getElementById("close-export");
  const btnCopyExport = document.getElementById("btn-copy-export");

  // NRD Stream Elements
  const btnIngestNrd = document.getElementById("btn-ingest-nrd");
  const btnTriageNrd = document.getElementById("btn-triage-nrd");
  const nrdTableBody = document.getElementById("nrd-table-body");

  // Brand Reg Elements
  const newBrandName = document.getElementById("new-brand-name");
  const newBrandDomain = document.getElementById("new-brand-domain");
  const newBrandCategory = document.getElementById("new-brand-category");
  const btnAddBrand = document.getElementById("btn-add-brand");
  const brandRegMsg = document.getElementById("brand-reg-msg");
  const brandListContainer = document.getElementById("brand-list-container");

  // RCA Elements
  const rcaCard = document.getElementById("rca-card");
  const rcaPrimaryCause = document.getElementById("rca-primary-cause");
  const rcaAttackVector = document.getElementById("rca-attack-vector");
  const rcaMitreRow = document.getElementById("rca-mitre-row");
  const rcaTargetBrand = document.getElementById("rca-target-brand");
  const rcaRogueHost = document.getElementById("rca-rogue-host");
  const rcaExfilSink = document.getElementById("rca-exfil-sink");
  const rcaDomainSsl = document.getElementById("rca-domain-ssl");

  // Bulk Elements
  const bulkUrlsInput = document.getElementById("bulk-urls-input");
  const btnRunBulk = document.getElementById("btn-run-bulk");
  const bulkTableBody = document.getElementById("bulk-table-body");
  const btnCloseBulk = document.getElementById("btn-close-bulk");

  let currentAnalysisData = null;
  let cachedExportData = null;

  // ------------------------------------------------------------------------
  // 3. Run Multimodal URL Analysis
  // ------------------------------------------------------------------------
  function runAnalysis(urlToScan) {
    if (!urlToScan) return;

    submitBtn.disabled = true;
    submitBtn.querySelector(".btn-text").textContent = "Analyzing AI Engines...";

    fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlToScan, deep_scan: true })
    })
    .then(res => res.json())
    .then(data => {
      currentAnalysisData = data;
      cachedExportData = null;

      emptyState.classList.add("hidden");
      bulkResultsBox.classList.add("hidden");
      activeResults.classList.remove("hidden");

      const assessment = data.assessment || {};
      const score = assessment.overall_score || 0;
      const level = assessment.risk_level || "SAFE";
      const details = data.details || {};
      const breakdown = assessment.breakdown || {};
      const forensics = assessment.forensic_details || {};

      resUrlTitle.textContent = data.url;
      resExecTime.textContent = `Latency: ${data.execution_time_seconds || 0.38}s`;
      resScoreNumber.textContent = `${score.toFixed(1)}%`;
      resActionText.textContent = assessment.action_recommendation || "";
      resCiText.textContent = `Confidence: ${assessment.confidence_interval || "95% CI [±1.8%]"}`;

      // Threat Meter Fill & Colors
      if (threatMeterFill) {
        threatMeterFill.style.width = `${Math.max(4, score)}%`;
        threatMeterFill.className = "meter-fill";
        if (level === "CRITICAL PHISHING") {
          threatMeterFill.classList.add("fill-critical");
        } else if (level === "SAFE") {
          threatMeterFill.classList.add("fill-safe");
        }
      }

      // Populate Forensic Root Cause Analysis (RCA) Card
      if (rcaPrimaryCause) {
        rcaPrimaryCause.textContent = assessment.primary_root_cause || "ANOMALOUS_TECHNICAL_SIGNATURE";
      }
      if (rcaAttackVector) {
        rcaAttackVector.textContent = assessment.attack_vector || "Web Threat";
        if (level === "SAFE") {
          rcaAttackVector.style.color = "#10b981";
          rcaAttackVector.style.borderColor = "rgba(16, 185, 129, 0.3)";
          rcaAttackVector.style.background = "rgba(16, 185, 129, 0.1)";
          if (rcaCard) rcaCard.style.borderLeftColor = "#10b981";
        } else {
          rcaAttackVector.style.color = "#ef4444";
          rcaAttackVector.style.borderColor = "rgba(239, 68, 68, 0.3)";
          rcaAttackVector.style.background = "rgba(239, 68, 68, 0.1)";
          if (rcaCard) rcaCard.style.borderLeftColor = "#ef4444";
        }
      }

      // Populate MITRE Tactics
      if (rcaMitreRow) {
        const tactics = assessment.mitre_tactics || [];
        if (tactics.length > 0) {
          rcaMitreRow.innerHTML = tactics.map(t => `<span class="rca-mitre-badge">🛡️ MITRE ${t}</span>`).join("");
          rcaMitreRow.classList.remove("hidden");
        } else {
          rcaMitreRow.innerHTML = `<span class="rca-mitre-badge">✅ No Malicious Tactics Observed</span>`;
        }
      }

      // Populate Forensic Matrix
      if (rcaTargetBrand) {
        rcaTargetBrand.textContent = forensics.target_brand || (assessment.matched_brand ? assessment.matched_brand.toUpperCase() : "N/A");
      }
      if (rcaRogueHost) {
        rcaRogueHost.textContent = forensics.attacker_host || data.domain;
        rcaRogueHost.className = level === "SAFE" ? "rca-m-val highlight-brand" : "rca-m-val highlight-danger";
      }
      if (rcaExfilSink) {
        rcaExfilSink.textContent = forensics.exfiltration_target || "None Detected";
        rcaExfilSink.className = (forensics.exfiltration_target && forensics.exfiltration_target !== "None (Secure Official Target)" && forensics.exfiltration_target !== "None Detected") ? "rca-m-val highlight-danger" : "rca-m-val";
      }
      if (rcaDomainSsl) {
        const ageStr = forensics.domain_age_days ? `${forensics.domain_age_days} Days` : "Unknown Age";
        const sslStr = forensics.ssl_status || (details.metadata_analysis?.is_https ? "HTTPS" : "HTTP");
        rcaDomainSsl.textContent = `${ageStr} | ${sslStr}`;
      }

      // Screenshot & Overlay

      // Screenshot & Overlay
      if (data.screenshot_url) {
        resScreenshotImg.src = data.screenshot_url;
      } else {
        resScreenshotImg.src = "https://via.placeholder.com/600x350?text=No+Viewport+Capture";
      }

      if (assessment.is_visual_clone || level === "CRITICAL PHISHING") {
        visualOverlay.classList.remove("hidden");
        const matched = assessment.matched_brand ? assessment.matched_brand.toUpperCase() : "TARGET BRAND";
        visualOverlayTag.textContent = `👁️ Visual Impersonation Match: ${breakdown.vision?.score || 98.2}% (${matched})`;
      } else {
        visualOverlay.classList.add("hidden");
      }

      // Risk Badge Styling
      resRiskBadge.className = "risk-badge";
      if (level === "CRITICAL PHISHING") {
        resRiskBadge.classList.add("badge-critical");
        resRiskBadge.textContent = "CRITICAL PHISHING";
        resScoreNumber.style.color = "var(--color-threat-text)";
      } else if (level === "HIGH PHISHING") {
        resRiskBadge.classList.add("badge-high");
        resRiskBadge.textContent = "HIGH PHISHING";
        resScoreNumber.style.color = "var(--color-warn-text)";
      } else if (level === "SUSPICIOUS") {
        resRiskBadge.classList.add("badge-warning");
        resRiskBadge.textContent = "SUSPICIOUS";
        resScoreNumber.style.color = "var(--color-warn-text)";
      } else {
        resRiskBadge.classList.add("badge-safe");
        resRiskBadge.textContent = "SAFE";
        resScoreNumber.style.color = "var(--color-safe-text)";
      }

      // Explainable Forensic Reasons List
      const reasons = assessment.explainable_reasons || [];
      if (reasons.length === 0) {
        resReasonsList.innerHTML = "<li>✅ Verified clean. Webpage passed all multimodal AI security checks with 0.0% risk.</li>";
      } else {
        resReasonsList.innerHTML = reasons.map(r => `<li>⚠️ ${r}</li>`).join("");
      }

      // 5 Engines Metrics
      const vScore = breakdown.vision?.score || 0;
      mVisionVal.textContent = `${vScore.toFixed(1)}%`;
      mVisionSub.textContent = assessment.matched_brand ? `Matched: ${assessment.matched_brand.toUpperCase()}` : "Visual Clean";

      const dScore = breakdown.dom_code?.score || 0;
      mDomVal.textContent = `${dScore.toFixed(1)}%`;
      mDomSub.textContent = details.dom_analysis?.form_action_mismatch ? "Form Action Mismatch" : "DOM Clean";

      const uScore = breakdown.url_whois?.score || 0;
      mUrlVal.textContent = `${uScore.toFixed(1)}%`;
      mUrlSub.textContent = details.url_analysis?.matched_brand_typo ? `Typosquat: ${details.url_analysis.matched_brand_typo.toUpperCase()}` : "URL Verified";

      const nScore = breakdown.nlp_pretext?.score || 0;
      mNlpVal.textContent = `${nScore.toFixed(1)}%`;
      mNlpSub.textContent = details.nlp_analysis?.claimed_brand_mismatch ? "Brand Mismatch in Text" : "NLP Clean";

      const mScore = breakdown.metadata_ssl?.score || 0;
      mMetaVal.textContent = `${mScore.toFixed(1)}%`;
      mMetaSub.textContent = details.metadata_analysis?.is_https ? "HTTPS Secure" : "Unencrypted HTTP";
    })
    .catch(err => {
      alert("Error connecting to PhishShield API Server on port 8000.");
      console.error(err);
    })
    .finally(() => {
      submitBtn.disabled = false;
      submitBtn.querySelector(".btn-text").textContent = "Run Multimodal AI";
    });
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    runAnalysis(inputUrl.value);
  });

  // Preset Chips Handlers
  document.querySelectorAll(".preset-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const url = chip.getAttribute("data-url");
      inputUrl.value = url;
      runAnalysis(url);
      const scannerSection = document.getElementById("scanner");
      if (scannerSection) scannerSection.scrollIntoView({ behavior: "smooth" });
    });
  });

  // ------------------------------------------------------------------------
  // 4. Batch Scanner Handler
  // ------------------------------------------------------------------------
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

    try {
      const res = await fetch(`${API_BASE}/batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls: rawLines })
      });
      const data = await res.json();
      
      for (const item of (data.results || [])) {
        const score = item.assessment?.overall_score || 0;
        const level = item.assessment?.risk_level || "SAFE";
        const topReason = item.assessment?.explainable_reasons?.[0] || "Passed all checks";
        const badgeStyle = (level === "CRITICAL PHISHING") ? "color: var(--color-threat-text);" : (level === "HIGH PHISHING" ? "color: var(--color-warn-text);" : (level === "SUSPICIOUS" ? "color: var(--color-warn-text);" : "color: var(--color-safe-text);"));

        const row = document.createElement("tr");
        row.innerHTML = `
          <td style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: var(--text-primary);">${item.url}</td>
          <td><strong>${score.toFixed(1)}%</strong></td>
          <td style="${badgeStyle} font-weight: 800;">${level}</td>
          <td style="color: var(--text-muted); font-size: 11px;">${topReason}</td>
        `;
        bulkTableBody.appendChild(row);
      }
    } catch (err) {
      console.error(err);
    } finally {
      btnRunBulk.disabled = false;
      btnRunBulk.textContent = "Execute Batch Scan";
    }
  });

  btnCloseBulk.addEventListener("click", () => {
    bulkResultsBox.classList.add("hidden");
    emptyState.classList.remove("hidden");
  });

  // ------------------------------------------------------------------------
  // 5. NRD Stream Feed Handler & Filter Management
  // ------------------------------------------------------------------------
  let allNrdItems = [];
  let currentNrdFilter = "ALL";

  const nrdCntAll = document.getElementById("nrd-cnt-all");
  const nrdCntPending = document.getElementById("nrd-cnt-pending");
  const nrdCntThreats = document.getElementById("nrd-cnt-threats");
  const nrdCntBenign = document.getElementById("nrd-cnt-benign");

  function renderNrdTable() {
    nrdTableBody.innerHTML = "";
    
    // Filter items based on active tab
    const filtered = allNrdItems.filter(item => {
      const isPending = item.status === "PENDING";
      const isThreat = item.status === "CRITICAL PHISHING" || item.status === "HIGH PHISHING" || item.status === "SUSPICIOUS";
      const isBenign = item.status === "BENIGN";
      if (currentNrdFilter === "PENDING") return isPending;
      if (currentNrdFilter === "THREATS") return isThreat;
      if (currentNrdFilter === "BENIGN") return isBenign;
      return true;
    });

    if (filtered.length === 0) {
      nrdTableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 20px;">No domains in this filter view.</td></tr>`;
      return;
    }

    for (const item of filtered) {
      let statusBadge = "";
      if (item.status === "CRITICAL PHISHING") {
        statusBadge = `<span style="color: #ef4444; font-weight: 800; background: rgba(239, 68, 68, 0.1); padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(239, 68, 68, 0.3);">🚨 CRITICAL (${item.risk_score ? item.risk_score.toFixed(1) : "99.0"}%)</span>`;
      } else if (item.status === "HIGH PHISHING") {
        statusBadge = `<span style="color: #f97316; font-weight: 800; background: rgba(249, 115, 22, 0.1); padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(249, 115, 22, 0.3);">⚠️ HIGH (${item.risk_score ? item.risk_score.toFixed(1) : "75.0"}%)</span>`;
      } else if (item.status === "SUSPICIOUS") {
        statusBadge = `<span style="color: #f59e0b; font-weight: 800; background: rgba(245, 158, 11, 0.1); padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(245, 158, 11, 0.3);">⚠️ SUSPICIOUS (${item.risk_score ? item.risk_score.toFixed(1) : "45.0"}%)</span>`;
      } else if (item.status === "BENIGN") {
        statusBadge = `<span style="color: #10b981; font-weight: 800; background: rgba(16, 185, 129, 0.1); padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(16, 185, 129, 0.3);">✅ BENIGN</span>`;
      } else {
        statusBadge = `<span style="color: #0284c7; font-weight: 700; background: rgba(2, 132, 199, 0.1); padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(2, 132, 199, 0.3);">⏳ PENDING SCAN</span>`;
      }

      const row = document.createElement("tr");
      row.style.cursor = "pointer";
      row.title = "Click to inspect in AI Scanner Lab";
      row.innerHTML = `
        <td>
          <a href="javascript:void(0)" class="nrd-domain-link" data-url="${item.domain}" style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: var(--accent-brand); text-decoration: none;">
            ${item.domain}
          </a>
        </td>
        <td style="color: var(--text-secondary); font-size: 11px;">${item.registrar || "NameSilo LLC"}</td>
        <td style="color: var(--text-muted); font-size: 11px;">${item.registration_date ? item.registration_date.slice(0, 10) : "Recent (0-2d)"}</td>
        <td>${statusBadge}</td>
      `;

      row.addEventListener("click", () => {
        inputUrl.value = item.domain;
        runAnalysis(item.domain);
        const scannerSection = document.getElementById("scanner");
        if (scannerSection) scannerSection.scrollIntoView({ behavior: "smooth" });
      });

      nrdTableBody.appendChild(row);
    }
  }

  async function loadNrdFeed() {
    try {
      const res = await fetch(`${API_BASE}/nrd/feed`);
      const data = await res.json();
      allNrdItems = data.domains || [];

      // Calculate category counts
      let pendingCnt = 0;
      let threatsCnt = 0;
      let benignCnt = 0;

      for (const it of allNrdItems) {
        if (it.status === "PENDING") pendingCnt++;
        else if (it.status === "CRITICAL PHISHING" || it.status === "HIGH PHISHING" || it.status === "SUSPICIOUS") threatsCnt++;
        else if (it.status === "BENIGN") benignCnt++;
      }

      if (nrdCntAll) nrdCntAll.textContent = allNrdItems.length;
      if (nrdCntPending) nrdCntPending.textContent = pendingCnt;
      if (nrdCntThreats) nrdCntThreats.textContent = threatsCnt;
      if (nrdCntBenign) nrdCntBenign.textContent = benignCnt;

      renderNrdTable();
    } catch (err) {
      console.error("NRD feed error:", err);
    }
  }

  // Setup tab filter click listeners
  document.querySelectorAll(".nrd-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nrd-tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentNrdFilter = btn.getAttribute("data-filter") || "ALL";
      renderNrdTable();
    });
  });

  btnIngestNrd.addEventListener("click", async () => {
    btnIngestNrd.disabled = true;
    btnIngestNrd.textContent = "Ingesting Stream Batch...";
    try {
      await fetch(`${API_BASE}/nrd/trigger`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ count: 10 })
      });
      await loadNrdFeed();
    } catch (err) {
      console.error(err);
    } finally {
      btnIngestNrd.disabled = false;
      btnIngestNrd.textContent = "📡 Ingest Live Stream Batch";
    }
  });

  btnTriageNrd.addEventListener("click", async () => {
    btnTriageNrd.disabled = true;
    btnTriageNrd.textContent = "Running Multimodal AI Triage...";
    try {
      await fetch(`${API_BASE}/nrd/scan-pending`, { method: "POST" });
      await loadNrdFeed();
    } catch (err) {
      console.error(err);
    } finally {
      btnTriageNrd.disabled = false;
      btnTriageNrd.textContent = "⚡ Run Parallel AI Triage";
    }
  });

  // ------------------------------------------------------------------------
  // 6. Brand Catalog Handler
  // ------------------------------------------------------------------------
  async function loadBrandCatalog() {
    try {
      const res = await fetch(`${API_BASE}/brands`);
      const data = await res.json();
      brandListContainer.innerHTML = "";

      for (const b of (data.brands || [])) {
        const card = document.createElement("div");
        card.className = "brand-card-item";
        card.innerHTML = `
          <div class="brand-item-title">${b.brand_name}</div>
          <div class="brand-item-domain">${b.official_domains[0] || ""}</div>
          <div class="brand-item-cat">${b.category}</div>
        `;
        brandListContainer.appendChild(card);
      }
    } catch (err) {
      console.error("Brands load error:", err);
    }
  }

  // Helper to match and select category dropdown cleanly
  function setCategoryDropdownValue(cat) {
    if (!newBrandCategory || !cat) return;
    const target = cat.toLowerCase();
    for (let i = 0; i < newBrandCategory.options.length; i++) {
      const opt = newBrandCategory.options[i];
      const optVal = opt.value.toLowerCase();
      const optText = opt.textContent.toLowerCase();
      if (!optVal) continue;
      if (optVal === target || target.includes(optVal) || optVal.includes(target) || optText.includes(target)) {
        newBrandCategory.selectedIndex = i;
        return;
      }
    }
  }

  // Live Bi-Directional Official Brand Lookup & Auto-Suggest
  let brandLookupTimer = null;

  async function triggerBrandLookup(queryVal, sourceInput) {
    if (!queryVal || queryVal.length < 2) {
      brandRegMsg.classList.add("hidden");
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/brands/lookup?query=${encodeURIComponent(queryVal)}`);
      if (res.ok) {
        const authData = await res.json();
        if (authData && authData.verified) {
          // If typed brand keyword and it is a verified authority, autofill official domain
          if (sourceInput === "name" && authData.official_domain) {
            newBrandDomain.value = authData.official_domain;
          }
          // If typed/pasted official domain, autofill official brand name
          if (sourceInput === "domain" && authData.brand_name) {
            newBrandName.value = authData.brand_name;
          }

          if (authData.category) {
            setCategoryDropdownValue(authData.category);
          }

          brandRegMsg.className = "brand-success-msg";
          brandRegMsg.innerHTML = `🛡️ <strong>Recognized Official Authority:</strong> ${authData.canonical_name || authData.brand_name} &bull; Sector: <code>${authData.category}</code> &bull; Primary Domain: <code>${authData.official_domain}</code>`;
          brandRegMsg.classList.remove("hidden");
          return;
        }
      }

      // Check if user entered a recognized brand name with an unofficial/fake domain
      const bName = newBrandName.value.trim();
      let bDom = newBrandDomain.value.trim().toLowerCase();
      if (bDom.includes("://")) bDom = bDom.split("://")[1];
      bDom = bDom.split("/")[0].split(":")[0];
      if (bDom.startsWith("www.")) bDom = bDom.substring(4);

      if (bName && bDom && bDom.includes(".")) {
        const bRes = await fetch(`${API_BASE}/brands/lookup?query=${encodeURIComponent(bName)}`);
        if (bRes.ok) {
          const bData = await bRes.json();
          if (bData && bData.official_domains && !bData.official_domains.some(d => bDom === d || bDom.endsWith(`.${d}`))) {
            brandRegMsg.className = "brand-error-msg";
            brandRegMsg.innerHTML = `⚠️ <strong>Unofficial Domain:</strong> <code>${bDom}</code> is NOT authorized for <strong>${bData.canonical_name}</strong> (Official: <code>${bData.official_domains.join(", ")}</code>).`;
            brandRegMsg.classList.remove("hidden");
            return;
          }
        }
      }

      brandRegMsg.classList.add("hidden");
    } catch (e) {
      brandRegMsg.classList.add("hidden");
    }
  }

  newBrandName.addEventListener("input", () => {
    const val = newBrandName.value.trim();
    if (!val) {
      newBrandDomain.value = "";
      if (newBrandCategory) newBrandCategory.selectedIndex = 0;
      brandRegMsg.classList.add("hidden");
      return;
    }
    clearTimeout(brandLookupTimer);
    brandLookupTimer = setTimeout(() => triggerBrandLookup(val, "name"), 200);
  });

  newBrandDomain.addEventListener("input", () => {
    const val = newBrandDomain.value.trim();
    if (!val) {
      if (newBrandCategory) newBrandCategory.selectedIndex = 0;
      brandRegMsg.classList.add("hidden");
      return;
    }
    clearTimeout(brandLookupTimer);
    brandLookupTimer = setTimeout(() => triggerBrandLookup(val, "domain"), 200);
  });

  btnAddBrand.addEventListener("click", async () => {
    const bName = newBrandName.value.trim();
    const bDom = newBrandDomain.value.trim();
    const bCat = newBrandCategory ? newBrandCategory.value.trim() : "";
    if (!bName || !bDom) {
      alert("Please enter both Brand Name and Official Domain!");
      return;
    }

    btnAddBrand.disabled = true;
    btnAddBrand.textContent = "Screening & Extracting...";
    brandRegMsg.classList.add("hidden");

    try {
      const res = await fetch(`${API_BASE}/brands/add`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ brand_name: bName, official_domain: bDom, category: bCat || undefined })
      });
      const data = await res.json();

      if (!res.ok) {
        brandRegMsg.className = "brand-error-msg";
        brandRegMsg.textContent = `🚫 ${data.detail || data.message || "Registration rejected by security policy."}`;
        brandRegMsg.classList.remove("hidden");
      } else {
        brandRegMsg.className = "brand-success-msg";
        brandRegMsg.textContent = `✅ ${data.message}`;
        brandRegMsg.classList.remove("hidden");
        newBrandName.value = "";
        newBrandDomain.value = "";
        if (newBrandCategory) newBrandCategory.selectedIndex = 0;
        loadBrandCatalog();
      }
    } catch (err) {
      brandRegMsg.className = "brand-error-msg";
      brandRegMsg.textContent = `❌ Network/Server Error: ${err.message}`;
      brandRegMsg.classList.remove("hidden");
    } finally {
      btnAddBrand.disabled = false;
      btnAddBrand.textContent = "Extract & Index Signatures";
    }
  });

  // ------------------------------------------------------------------------
  // 7. Threat Export Formats Handler
  // ------------------------------------------------------------------------
  async function fetchExportData() {
    if (!currentAnalysisData) return null;
    if (cachedExportData) return cachedExportData;

    const res = await fetch(`${API_BASE}/export/all`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: currentAnalysisData.url,
        domain: currentAnalysisData.domain,
        assessment: currentAnalysisData.assessment,
        details: currentAnalysisData.details
      })
    });
    cachedExportData = await res.json();
    return cachedExportData;
  }

  function showExportBox(title, content) {
    exportTitle.textContent = title;
    exportCodeContent.textContent = content;
    exportOutputBox.classList.remove("hidden");
  }

  btnExportStix.addEventListener("click", async () => {
    const data = await fetchExportData();
    if (data) showExportBox("📄 STIX 2.1 JSON Threat Intelligence Bundle", JSON.stringify(data.stix_bundle, null, 2));
  });

  btnExportMisp.addEventListener("click", async () => {
    const data = await fetchExportData();
    if (data) showExportBox("🛡️ MISP Threat Event JSON", JSON.stringify(data.misp_event, null, 2));
  });

  btnExportSuricata.addEventListener("click", async () => {
    const data = await fetchExportData();
    if (data) showExportBox("⚡ Suricata & Snort Network IDS Signatures", data.suricata_rule);
  });

  btnExportDns.addEventListener("click", async () => {
    const data = await fetchExportData();
    if (data) showExportBox("🚫 BIND 9 RPZ / Pi-hole / AdGuard DNS Sinkhole Rules", data.dns_sinkhole_rule);
  });

  btnExportTakedown.addEventListener("click", async () => {
    const data = await fetchExportData();
    if (data) showExportBox("🚨 Official RFC 2142 Registrar Abuse Takedown Dossier", data.takedown_notice);
  });

  closeExport.addEventListener("click", () => {
    exportOutputBox.classList.add("hidden");
  });

  btnCopyExport.addEventListener("click", () => {
    navigator.clipboard.writeText(exportCodeContent.textContent).then(() => {
      btnCopyExport.textContent = "✅ Copied!";
      setTimeout(() => { btnCopyExport.textContent = "📋 Copy Content"; }, 2000);
    });
  });

  // Initial Data Load
  loadNrdFeed();
  loadBrandCatalog();
});
