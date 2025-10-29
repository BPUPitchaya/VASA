let scanId = null;
let pollTimer = null;
let isPaused = false;

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

// UI
function formatDate() {
  const d = new Date();
  return `${d.getDate().toString().padStart(2,'0')}.${(d.getMonth()+1).toString().padStart(2,'0')}.${d.getFullYear()}`;
}

function renderProgress(p) {
  progressFill.style.width = `${p}%`;
  progressText.textContent = `${p}%`;
}

function setSummary(countText, sevText) {
  issueCount.textContent = countText;
  overallSeverity.textContent = sevText;
}

function resetUI() {
  clearInterval(pollTimer);
  pollTimer = null
  isPaused = false;
  scanID = null

  renderProgress(0);
  setSummary('0', '-');
  pauseBtn.textContent = 'Pause';
  pauseBtn.disabled = true;
  startBtn.disabled = false;
}

// backend request
async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// polling backend for progress update
function startPolling(id) {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const s = await api(`/scan/${id}/status`);
      renderProgress(Math.round(s.progress || 0));

      if (s.state === "completed" || s.state === "failed" || s.state === "stopped") {
        clearInterval(pollTimer);
        loadResults(id, s);
      }
    } catch (e) {
      clearInterval(pollTimer);
      progressText.textContent = "Error";
    }
  }, 1500);
}

// to load results summary once scan is done
async function loadResults(id, status) {
  try {
    const r = await api(`/scan/${id}/results`);
    progressSection.classList.add("hidden");
    resultsTable.classList.remove("hidden");
    noResult.classList.add("hidden");

    // summary
    const now = new Date();
    resultDate.textContent = formatDate();
    resultTarget.textContent = r.target || "-";
    issueCount.textContent = r.cve_scan ? Object.keys(r.cve_scan).length : 0;
    overallSeverity.textContent = r.status === "completed" ? r.severity || "Low" : "Stopped";
  } catch (e) {
    console.error("Error loading results:", e);
    progressText.textContent = "Failed to load results";
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

  const mode = document.querySelector('input[name="mode"]:checked').value;
  resultTarget.textContent = target;
  resultMode.textContent = mode;
  resultDate.textContent = formatDate();

  progressSection.classList.remove("hidden");
  resultsTable.classList.add("hidden");
  noResult.classList.add("hidden");

  resetUI();
  pauseBtn.disabled = false;
  startBtn.disabled = true;

  try {
    const res = await api("/scan/start", {
      method: "POST",
      body: { target: target, ports: "21-23,80,443,8080,8443" },
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

  try {
    if (!isPaused) {
      await api(`/scan/${scanId}/pause`, { method: "POST" });
      isPaused = true;
      pauseBtn.textContent = "Resume";
    } else {
      await api(`/scan/${scanId}/resume`, { method: "POST" });
      isPaused = false;
      pauseBtn.textContent = "Pause";
    }
  } catch (e) {
    console.error("Pause/Resume failed:", e);
  }
});


// Stop scanning
stopBtn.addEventListener("click", async () => {
  if (!scanId) return;
  try {
    await api(`/scan/${scanId}/stop`, { method: "POST" });
    clearInterval(pollTimer);
    progressText.textContent = "Stopped";
    startBtn.disabled = false;
  } catch (e) {
    console.error("Stop failed:", e);
  }
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