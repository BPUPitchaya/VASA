let scanId = null;
let pollTimer = null;
let isPaused = false;

let fakeProgress = 0;
let lastProgress = 0;
const MAX_FAKE = 88;

// let progress = 0;
// let timer = null;
// let isPaused = false;
// let interval;

const startBtn = document.getElementById("start");
const pauseBtn = document.getElementById("pause");
const stopBtn = document.getElementById("stop");

const progressFill = document.getElementById("progress-fill");
const progressText = document.getElementById("progress-text");
const progressSection = document.getElementById("progress-section");

const issueCount = document.getElementById("issue-count");
const overallSeverity = document.getElementById("overall-severity");

const resultTarget = document.getElementById("result-target");
const resultMode = document.getElementById("result-mode");
const resultDate = document.getElementById("result-date");

const resultsTable = document.getElementById("results-table");
const noResult = document.getElementById("no-result");

const targetInput = document.getElementById('target');
const viewDetailBtn = document.getElementById('view-detail');
const pdfBtn = document.getElementById('pdf-report');

var API_BASE = window.API_BASE || "/api";
window.API_BASE = API_BASE;

// UI
function formatDate() {
  const d = new Date();
  return `${d.getDate().toString().padStart(2,'0')}.${(d.getMonth()+1).toString().padStart(2,'0')}.${d.getFullYear()}`;
}

function renderProgress(p) {
  const displayValue = Math.round(p);
  lastProgress = Math.max(lastProgress,p);

  progressFill.style.width = `${displayValue}%`;
  progressText.textContent = `${displayValue}%`; 
}

function setSummary(countText, sevText) {
  issueCount.textContent = countText;
  overallSeverity.textContent = sevText;
}

function resetUI() {
  clearInterval(pollTimer);
  pollTimer = null
  isPaused = false;
  scanId = null

  fakeProgress = 0;
  lastProgress = 0;

  renderProgress(0);
  setSummary('0', '-');
  pauseBtn.textContent = 'Pause';
  pauseBtn.disabled = true;
  startBtn.disabled = false;
}

// backend request
async function api(path, { method = "GET", body } = {}) {
  const safe = String(path).replace(/^\/+/, "");   // strip leading slashes
  const res = await fetch(`${API_BASE}/${safe}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// polling backend for progress update
function startPolling(id, { resume = false } = {}) {
  clearInterval(pollTimer);
  if (!resume) { fakeProgress = 0; }   // keep value when resuming

  pollTimer = setInterval(async () => {
    try {
      const s = await api(`scan/status/${id}`);

      let p;
      if (typeof s.progress === 'number') {
        // trust backend, clamp to 0..99 while running
        p = Math.max(0, Math.min(99, Math.round(s.progress)));
        fakeProgress = p;                   // sync fallback
      } else if (s.status === 'running') {
        // slow, capped, never below lastProgress
        const step = Math.random() * 1.0 + 0.4; // ~0.4–1.4% per tick
        fakeProgress = Math.min(
          MAX_FAKE,
          Math.max(fakeProgress, lastProgress) + step
        );
        p = fakeProgress;
      } else {
        p = lastProgress;
      }

      renderProgress(p);

      if (s.status === 'completed' || s.status === 'failed' || s.status === 'stopped') {
        clearInterval(pollTimer);
        renderProgress(s.status === 'completed' ? 100 : lastProgress);
        progressText.textContent = (s.status === 'completed') ? '100%' : 'Stopped';
        loadResults(id, s);
      } else if (s.message) {
        // Optional: show what the backend says it is doing
        progressText.setAttribute('title', s.message);
      }

    } catch (e) {
      clearInterval(pollTimer);
      progressText.textContent = "Error";
      console.error(e);
    }
  }, 1500); 
}

function lockResultsMetaLayout() {
  const el = document.querySelector('.right-panel .overview');
}

// to load results summary once scan is done
async function loadResults(id, statusDoc) {
  try {
    // "statusDoc" is the object returned by /api/scan/status/<id>
    progressSection.classList.add("hidden");
    resultsTable.classList.remove("hidden");
    noResult.classList.add("hidden");

    resultTarget.textContent = statusDoc.target || "-";
    resultMode.textContent   = statusDoc.scan_type || (statusDoc.mode || "-");
    resultDate.textContent   = formatDate();

    // Summary
    const r = statusDoc.results || {};
    // Example totals: tweak to your actual structure
    const totalIssues =
      (r.open_ports        ? r.open_ports.length : 0) +
      (r.http_headers_issues ? r.http_headers_issues.length : 0) +
      (r.ssl_issues          ? r.ssl_issues.length : 0) +
      (r.cve_matches         ? r.cve_matches.length : 0);

    issueCount.textContent     = String(totalIssues);
    overallSeverity.textContent = statusDoc.severity || "-";

    // TODO: populate your table rows from r.* the way you want
  } catch (e) {
    console.error("Error rendering results:", e);
    progressText.textContent = "Failed to render results";
  }
}

/* Single tick of the fake scan animation */
/* 
function tick() {
  if (progress >= 100) {
    clearInterval(timer);
    timer = null;
    isPaused = false;
    pauseBtn.textContent = 'Pause';
    // mock final numbers
    setSummary('6', 'High', 'high-text');
    return;
  }
  progress += 1;                 // adjust speed as needed
  renderProgress();
}
*/

// Event Handlers

// Start Scanning
startBtn.addEventListener("click", async () => {
  const target = targetInput.value.trim();
  if (!target) return alert("Enter a valid target host or IP.");

  const uiMode = document.querySelector('input[name="mode"]:checked').value; // "Active" | "Passive"
  resultTarget.textContent = target;
  resultMode.textContent   = uiMode;  // keep UI text
  resultDate.textContent   = formatDate();

  progressSection.classList.remove("hidden");
  resultsTable.classList.add("hidden");
  noResult.classList.add("hidden");

  resetUI();
  pauseBtn.disabled = false;
  startBtn.disabled = true;

  try {
    // Either omit mode (backend defaults to 'quick')
    // or explicitly send 'quick' to match ScanMode
    const res = await api("scan", {
      method: "POST",
      body: {
        target,
        mode: "quick",                       // <- VALID for ScanMode
        authorized: uiMode === "Active"      // if your backend cares
      },
    });
    scanId = res.scan_id;
    startPolling(scanId);
  } catch (e) {
    alert("Error starting scan: " + e.message);
    resetUI();
  }
});

// Pause/Resume
pauseBtn.addEventListener("click", async () => {
  if (!scanId) return;

  if (!isPaused) {
    isPaused = true;
    clearInterval(pollTimer);
    pauseBtn.textContent = "Resume";
  }
  else {
    isPaused = false;
    pauseBtn.textContent = "Pause";
    startPolling(scanId, {resume: true});
  }
});


// Stop scanning
stopBtn.addEventListener("click", async () => {
  if (!scanId) return;
  clearInterval(pollTimer);
  isPaused = false;
  progressText.textContent = "Stopped";
  startBtn.disabled = false;
  pauseBtn.disabled = true;
});


// Navigate to results page with current context
if (viewDetailBtn) {
  viewDetailBtn.addEventListener('click', () => {
    const target = document.getElementById('target').value || '192.168.xx.xx';
    const mode = document.querySelector('input[name="mode"]:checked').value;
    const date = new Date();
    const dd = String(date.getDate()).padStart(2,'0');
    const mm = String(date.getMonth()+1).padStart(2,'0');
    const yyyy = date.getFullYear();
    const when = `${dd}.${mm}.${yyyy}`;

    // pass values via query string (result page can read these)
    const qs = new URLSearchParams({ target, mode, date: when }).toString();
    window.location.href = `resultpage.html?${qs}`;
  });
}

// pdf report
if (pdfBtn) {
  pdfBtn.addEventListener('click', () => window.print());
}

renderProgress(0);
pauseBtn.disabled = true;