let progress = 0;
let interval;

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

function formatDate() {
  const d = new Date();
  return `${d.getDate().toString().padStart(2,'0')}.${(d.getMonth()+1).toString().padStart(2,'0')}.${d.getFullYear()}`;
}

startBtn.addEventListener("click", () => {
  const target = document.getElementById("target").value || "192.168.xx.xx";
  const mode = document.querySelector('input[name=\"mode\"]:checked').value;
  
  // Update UI
  resultTarget.textContent = target;
  resultMode.textContent = mode;
  resultDate.textContent = formatDate();
  noResult.classList.add("hidden");
  progressSection.classList.remove("hidden");
  resultsTable.classList.remove("hidden");

  // Reset
  progress = 0;
  issueCount.textContent = 0;
  overallSeverity.textContent = "-";
  progressFill.style.width = "0%";
  progressText.textContent = "0%";

  // Start animation
  clearInterval(interval);
  interval = setInterval(() => {
    if (progress < 100) {
      progress++;
      progressFill.style.width = progress + "%";
      progressText.textContent = progress + "%";

      if (progress === 100) {
        issueCount.textContent = "6";
        overallSeverity.textContent = "High";
        overallSeverity.classList.add("high-text");
        clearInterval(interval);
      }
    }
  }, 100);
});

pauseBtn.addEventListener("click", () => clearInterval(interval));

stopBtn.addEventListener("click", () => {
  clearInterval(interval);
  progress = 0;
  progressFill.style.width = "0%";
  progressText.textContent = "0%";
  progressSection.classList.add("hidden");
  resultsTable.classList.add("hidden");
  noResult.classList.remove("hidden");
  issueCount.textContent = "0";
  overallSeverity.textContent = "-";
});