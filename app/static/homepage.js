document.addEventListener('DOMContentLoaded', function() {

// ---- Config / State ----
const API_BASE   = window.API_BASE   || "/api";
const PAGES_BASE = window.PAGES_BASE || "/static";

let scanId = null;
let pollTimer = null;
let smoothTimer = null;
let lastProgress = 0;
let pollDelay = 800;       
let isPaused = false;      

// ---- DOM Elements ----
const startBtn       = document.getElementById("start");
const pauseBtn       = document.getElementById("pause");
const stopBtn        = document.getElementById("stop");

const progressFill   = document.getElementById("progress-fill");
const progressText   = document.getElementById("progress-text");
const progressSection= document.getElementById("progress-section");

const issueCountEl   = document.getElementById("issue-count");
const overallSevEl   = document.getElementById("overall-severity");

const resultTargetEl = document.getElementById("result-target");
const resultModeEl   = document.getElementById("result-mode");
const resultDateEl   = document.getElementById("result-date");

const resultsTable   = document.getElementById("results-table");
const resultsBody    = document.getElementById("results-body");
const noResult       = document.getElementById("no-result");

const targetInput    = document.getElementById("target");
const viewDetailBtn  = document.getElementById("view-detail");
const pdfBtn         = document.getElementById("pdf-report");

// ---- Utils ----
const formatDate = () => {
  const d = new Date();
  return `${String(d.getDate()).padStart(2,'0')}.${String(d.getMonth()+1).padStart(2,'0')}.${d.getFullYear()}`;
};

async function api(path, { method="GET", body } = {}) {
  const safe = String(path).replace(/^\/+/, "");
  const res = await fetch(`${API_BASE}/${safe}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function colouriseOverall(level) {
  overallSevEl.classList.remove('sev-high','sev-med','sev-low');
  const cls = level === 'High' ? 'sev-high' : level === 'Medium' ? 'sev-med' : 'sev-low';
  overallSevEl.classList.add(cls);
}

function renderProgress(p) {
  const target = Math.min(100, Math.max(0, Math.round(Number(p) || 0)));
  lastProgress = Math.max(lastProgress, target);   // keep monotonic
  if (smoothTimer) { clearInterval(smoothTimer); smoothTimer = null; }

  const current = parseInt(progressText.textContent.replace("%","")) || 0;
  let val = current;

  smoothTimer = setInterval(() => {
    if (val >= target) { clearInterval(smoothTimer); smoothTimer = null; return; }
    val++;
    progressFill.style.width = `${val}%`;
    progressText.textContent = `${val}%`;
  }, 25);
}

function setSummary(n, sev) {
  issueCountEl.textContent = String(n);
  overallSevEl.textContent = sev;
  colouriseOverall(sev);
}

function resetUI() {
  clearInterval(pollTimer);
  pollTimer = null;
  if (smoothTimer) { clearInterval(smoothTimer); smoothTimer = null; }
  lastProgress = 0;
  scanId = null;

  renderProgress(0);
  setSummary(0, "-");

  startBtn.disabled = false;
  pauseBtn.disabled = true;
  pauseBtn.textContent = "Pause";
  stopBtn.disabled  = true;

  resultsBody.innerHTML = "";
  resultsTable.classList.add("hidden");
  noResult.classList.remove("hidden");

  if (viewDetailBtn) {
    viewDetailBtn.disabled = true;
    viewDetailBtn.onclick = null;
  }
}

function normalise(doc) {
  const modules = doc?.results?.modules || {};

  if (Object.keys(modules).length > 0) {
    const portsMod = modules.port_scan || {};
    const ports    = portsMod.open_ports || portsMod.services || [];

    const hdr      = modules.http_headers?.results || {};
    const missing  = hdr.missing_headers || [];
    const secIssues= hdr.security_issues || [];
    const headerIssues = [...missing, ...secIssues];

    const sslRes   = modules.ssl_scan?.results || {};
    const sslIssues= sslRes.vulnerabilities || sslRes.issues || [];

    const cveRes   = modules.cve_check || {};
    const cves     = cveRes.cves_found || [];

    return {
      open_ports:          ports,
      http_headers_issues: headerIssues,
      ssl_issues:          sslIssues,
      cve_matches:         cves
    };
  }

  const ports = doc.open_ports || [];
  return {
    open_ports:          ports,
    http_headers_issues: [],
    ssl_issues:          [],
    cve_matches:         []
  };
}

function overallSeverity(b) {
  const hi  = (b.cve_matches?.length || 0) + (b.ssl_issues?.length || 0);
  const med = (b.http_headers_issues?.length || 0) + ((b.open_ports?.length || 0) ? 1 : 0);
  if (hi  > 0) return "High";
  if (med > 0) return "Medium";
  return "Low";
}

function sevCell(level) {
  if (level === "High")   return '<span class="dot high"></span> High';
  if (level === "Medium") return '<span class="dot medium"></span> Medium';
  return '<span class="dot low"></span> Low';
}

function catSeverity(name, count) {
  if (name === "headers") {
    if (count >= 7) return "High";
    if (count >= 3) return "Medium";
    return "Low";
  }
  if (name === "ports") return count > 0 ? "Medium" : "Low";
  if (name === "ssl")   return count > 0 ? "High"   : "Low";
  if (name === "cve")   return count > 0 ? "High"   : "Low";
  return "Low";
}

function renderSummaryTable(totals) {
  const rows = [
    ["Open Port & Services", totals.ports,   catSeverity("ports", totals.ports)],
    ["Insecure HTTP Headers", totals.headers, catSeverity("headers", totals.headers)],
    ["SSL/TLS Misconfigurations", totals.ssl, catSeverity("ssl", totals.ssl)],
    ["CVE Matches", totals.cve,              catSeverity("cve", totals.cve)],
  ];

  resultsBody.innerHTML = rows.map(([label, count, sev]) =>
    `<tr><td>${label}</td><td>${count}</td><td>${sevCell(sev)}</td></tr>`
  ).join("");

  resultsTable.classList.remove("hidden");
  noResult.classList.add("hidden");
}

// ---- Polling ----
function startPolling(id) {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }

  pollTimer = setInterval(async () => {
    // if scan is gone or this polling belongs to an older id, stop
    if (!scanId || id !== scanId) {
      clearInterval(pollTimer);
      pollTimer = null;
      return;
    }

    if (isPaused) return;

    try {
      const st = await api(`scan/status/${encodeURIComponent(id)}`);

      const prog = Number(st.progress || 0);
      lastProgress = prog;

      // progress bar
      renderProgress(prog);
      progressText.textContent = `${prog}%`;

      if (st.status === "running") {
        return;
      }

      if (st.status === "completed" ||
          st.status === "failed" ||
          st.status === "stopped") {

        clearInterval(pollTimer);
        pollTimer = null;
        isPaused = false;
        pauseBtn.disabled = true;
        stopBtn.disabled  = true;
        startBtn.disabled = false;

        if (st.status === "completed") {
          progressText.textContent = "Scan completed.";

          loadResults(st);

        } else if (st.status === "stopped") {
          progressText.textContent = "Scan stopped.";
        } else {
          // failed
          const errMsg = st.error || "Scan failed";
          progressText.textContent = `Error: ${errMsg}`;
          noResult.textContent = errMsg;
          noResult.classList.remove("hidden");
          resultsTable.classList.add("hidden");
        }
      }
    } catch (e) {
      console.error("Polling error:", e);
      clearInterval(pollTimer);
      pollTimer = null;

      progressText.textContent = "Error checking scan status";
      startBtn.disabled = false;
      pauseBtn.disabled = true;
      stopBtn.disabled  = true;
    }
  }, pollDelay);
}

function loadResults(scanData) {
  try {
    // Hide progress bar when we are done
    progressSection.classList.add("hidden");

    const norm = normalise(scanData);

    const totals = {
      ports:   norm.open_ports.length,
      headers: norm.http_headers_issues.length,
      ssl:     norm.ssl_issues.length,
      cve:     norm.cve_matches.length,
    };

    const totalIssues = totals.ports + totals.headers + totals.ssl + totals.cve;
    const overall     = overallSeverity(norm);

    setSummary(totalIssues, overall);

    renderSummaryTable(totals);

    resultsTable.classList.remove("hidden");
    noResult.classList.add("hidden");
    startBtn.disabled = false;

  } catch (e) {
    console.error("Error loading results:", e);
    progressText.textContent = "Error loading results";
    noResult.textContent = `Error: ${e.message || "Failed to load scan results"}`;
    noResult.classList.remove("hidden");
    resultsTable.classList.add("hidden");
    startBtn.disabled = false;
    pauseBtn.disabled = true;
    stopBtn.disabled = true;
  }
}

// ---- Events ----
// Stop button click handler
stopBtn.addEventListener("click", async () => {
  // Cancel any ongoing scans
  if (scanId) {
    try {
      // Notify the backend to stop the scan
      await api(`scan/${encodeURIComponent(scanId)}/stop`, { method: 'POST' });
      console.log(`Scan ${scanId} was cancelled`);
    } catch (error) {
      console.error('Error stopping scan:', error);
      // Continue with reset even if API call fails
    }
  }
  
  // Reset the UI
  resetUI();
  
  // Re-enable the start button and reset UI state
  startBtn.disabled = false;
  progressSection.classList.add("hidden");
  resultsTable.classList.add("hidden");
  noResult.classList.remove("hidden");
  
  // Clear the polling interval
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  
  // Reset progress
  renderProgress(0);
  progressText.textContent = '0%';
});

startBtn.addEventListener("click", async () => {
  try {
    const raw = (targetInput.value || "").trim();
    if (!raw) return alert("Enter a valid target host or IP.");

    // clean state
    resetUI();
    pollDelay = 800;
    if (smoothTimer) { clearInterval(smoothTimer); smoothTimer = null; }

    const targetClean = raw.replace(/^https?:\/\//i, "").replace(/\/+$/, "");

    // ---- map radio -> backend scan_type + modules + ports ----
    const uiMode   = document.querySelector('input[name="mode"]:checked').value; // "Active" | "Passive"
    const isActive = uiMode === "Active";

    // This lines up with your backend:
    // data.get("scan_type", "quick")
    // data.get("modules", ["port_scan"])
    const scanType = isActive ? "full" : "quick";   // full for Active, quick for Passive

    const modules = isActive
      ? ["port_scan", "ssl_scan", "http_headers", "cve_check"]   // full multi-module job
      : ["ssl_scan", "http_headers"];                           // lighter passive scan

    const ports = isActive
      ? "1-1024"                          // full scan range (adjust as you like)
      : "21-23,80,443,8080,8443";         // quick 35-port style list

    // ---- prime right-hand summary panel ----
    resultTargetEl.textContent = targetClean;
    resultModeEl.textContent   = uiMode;
    resultDateEl.textContent   = formatDate();

    progressSection.classList.remove("hidden");
    resultsTable.classList.add("hidden");
    noResult.classList.add("hidden");

    startBtn.disabled = true;
    pauseBtn.disabled = false;
    pauseBtn.textContent = "Pause";
    isPaused = false;
    stopBtn.disabled  = false;

    sessionStorage.removeItem("lastScanId");

    // ---- start backend scan (this matches your Flask snippet) ----
    const res = await api("scan", {
      method: "POST",
      body: {
        target:    targetClean,
        scan_type: scanType,   // <- backend: data.get("scan_type", "quick")
        modules:   modules,    // <- backend: data.get("modules", ["port_scan"])
        ports:     ports
      }
    });

    if (!res?.scan_id) throw new Error("No scan_id returned from server");
    scanId = res.scan_id;

    // persist context for result page
    sessionStorage.setItem("lastScanId", scanId);
    sessionStorage.setItem("lastTarget", targetClean);
    sessionStorage.setItem("lastMode", uiMode);
    sessionStorage.setItem("lastDate", resultDateEl.textContent);

    if (viewDetailBtn) {
      viewDetailBtn.disabled = false;
      viewDetailBtn.onclick = () => {
        const qs = new URLSearchParams({
          scan_id: scanId,
          target:  targetClean,
          mode:    uiMode,
          date:    resultDateEl.textContent
        }).toString();
        window.location.href = `${PAGES_BASE}/resultpage.html?${qs}`;
      };
    }

    startPolling(scanId);
  } catch (err) {
    let msg = err?.message || String(err);
    try { msg = JSON.stringify(JSON.parse(msg), null, 2); } catch {}
    alert("Error starting scan: " + msg);
    console.error("start scan error:", err);
    resetUI();
  }
});

pauseBtn.addEventListener("click", async () => {
  if (!scanId) return;

  // Determine action: pause → resume, resume → pause
  const action = isPaused ? "resume" : "pause";
  pauseBtn.disabled = true;

  try {
    const endpoint = `scan/${encodeURIComponent(scanId)}/${action}`;
    const res = await api(endpoint, { method: "POST" });

    // Backend returns { ok: true } or { ok: false, error: "..."}
    if (!res || res.ok === false || res.error) {
      console.warn("Pause/Resume backend error:", res);
      return;
    }

    if (action === "pause") {
      isPaused = true;
      pauseBtn.textContent = "Resume";
      progressText.textContent = "Paused";

      // Stop polling loop immediately
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
      return;
    }

    if (action === "resume") {
      isPaused = false;
      pauseBtn.textContent = "Pause";

      // Restore last known progress
      progressText.textContent = `${lastProgress}%`;

      // Restart polling
      startPolling(scanId);
      return;
    }

  } catch (err) {
    console.error("Pause/Resume network failure:", err);

  } finally {
    // Re-enable only if scan still exists
    if (scanId) pauseBtn.disabled = false;
  }
});

stopBtn.addEventListener("click", async () => {
  if (!scanId) return;

  // prevent double-click spam
  stopBtn.disabled  = true;
  pauseBtn.disabled = true;

  try {
    await api(`scan/stop/${encodeURIComponent(scanId)}`, { method: "POST" });
  } catch (e) {
    console.warn("stop API failed:", e);
    // still proceed with local cancel
  } finally {
    // hard-cancel any polling or smooth animations
    if (pollTimer)  { clearInterval(pollTimer);  pollTimer  = null; }
    if (smoothTimer){ clearInterval(smoothTimer); smoothTimer = null; }

    // make sure any late poll tick for the old id won’t touch the UI
    // (startPolling already captures an id; this guard relies on scanId changing)
    const oldId = scanId;
    scanId = null; // invalidate the active scan

    // reset session state to avoid auto-resume
    try { sessionStorage.removeItem("lastScanId"); } catch {}

    // reset progress visuals
    lastProgress = 0;
    pollDelay    = 800;
    isPaused     = false;
    progressFill.style.width = "0%";
    progressText.textContent = "Stopped";

    // unlock Start; keep any existing results panel as-is
    startBtn.disabled = false;

    // (optional) hide the progress bar if you prefer:
    // progressSection.classList.add("hidden");
  }
});

// PDF
if (pdfBtn) {
  pdfBtn.addEventListener("click", async () => {
    if (!scanId) {
      alert("No scan available. Run a scan first.");
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/scan/${encodeURIComponent(scanId)}/pdf`);
      if (!res.ok) throw new Error(await res.text());

      const blob = await res.blob();
      const url  = window.URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url;
      a.download = `vasa_scan_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      console.error("PDF download failed:", e);
      alert("Failed to download PDF report.");
    }
  });
}

// Initialize the UI
resetUI();

// ---- Auto-start when redirected from result page ----
(function autoStartIfRequested() {
  try {
    const auto = sessionStorage.getItem("autoStart");
    if (auto !== "true") return;
    sessionStorage.removeItem("autoStart");

    const lastTarget = sessionStorage.getItem("lastTarget") || "";
    const lastMode   = sessionStorage.getItem("lastMode")   || "Active";

    if (lastTarget) {
      targetInput.value = lastTarget;
      const modeRadio = document.querySelector(`input[name="mode"][value="${lastMode}"]`);
      if (modeRadio) modeRadio.checked = true;

      setTimeout(() => {
        if (!startBtn.disabled) startBtn.click();
      }, 0);
    }
  } catch (e) {
    console.warn("Auto-start failed:", e);
  }
})();

// Close the DOMContentLoaded event listener
});