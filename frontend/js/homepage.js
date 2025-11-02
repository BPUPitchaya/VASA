let progress = 0;
let timer = null;
let isPaused = false;
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

function formatDate() {
  const d = new Date();
  return `${d.getDate().toString().padStart(2,'0')}.${(d.getMonth()+1).toString().padStart(2,'0')}.${d.getFullYear()}`;
}

function renderProgress() {
  progressFill.style.width = `${progress}%`;
  progressText.textContent = `${progress}%`;
}

function setSummary(countText, sevText, sevClassAdd = null) {
  issueCount.textContent = countText;
  overallSeverity.textContent = sevText;
  overallSeverity.classList.remove('high-text'); // remove any prior emphasis class you used
  if (sevClassAdd) overallSeverity.classList.add(sevClassAdd);
}

function resetUI() {
  clearInterval(timer);
  timer = null;
  isPaused = false;
  progress = 0;
  renderProgress();
  setSummary('0', '-');
  pauseBtn.textContent = 'Pause';
  pauseBtn.disabled = true;
}

/* Single tick of the fake scan animation */
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


startBtn.addEventListener('click', () => {
  const target = targetInput.value || '192.168.xx.xx';
  const mode = document.querySelector('input[name="mode"]:checked').value;

  // Fill summary header
  resultTarget.textContent = target;
  resultMode.textContent   = mode;
  resultDate.textContent   = formatDate();

  // Show progress + results frame
  noResult.classList.add('hidden');
  progressSection.classList.remove('hidden');
  resultsTable.classList.remove('hidden');

  // Reset and go
  resetUI();
  pauseBtn.disabled = false;
  timer = setInterval(tick, 100);
});

// Pause <-> Resume toggle
pauseBtn.addEventListener('click', () => {
  if (progressSection.classList.contains('hidden')) return; // nothing to toggle

  if (!isPaused) {
    clearInterval(timer);
    timer = null;
    isPaused = true;
    pauseBtn.textContent = 'Resume';
  } else {
    timer = setInterval(tick, 100);
    isPaused = false;
    pauseBtn.textContent = 'Pause';
  }
});

// Stop scanning (reset view to idle)
stopBtn.addEventListener('click', () => {
  resetUI();
  progressSection.classList.add('hidden');
  resultsTable.classList.add('hidden');
  noResult.classList.remove('hidden');
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

if (pdfBtn) {
  pdfBtn.addEventListener('click', () => window.print());
}

renderProgress();
pauseBtn.disabled = true;