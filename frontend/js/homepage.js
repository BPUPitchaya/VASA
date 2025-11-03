// VASA Homepage - Real Backend Integration
// Connects to Flask backend API for actual vulnerability scanning

// ============================================================================
// STATE MANAGEMENT
// ============================================================================
let currentScanId = null;
let currentScanData = null;
let pollingActive = false;

// ============================================================================
// DOM ELEMENT REFERENCES
// ============================================================================
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

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
function formatDate() {
  const d = new Date();
  return `${d.getDate().toString().padStart(2,'0')}.${(d.getMonth()+1).toString().padStart(2,'0')}.${d.getFullYear()}`;
}

function renderProgress(percent) {
  progressFill.style.width = `${percent}%`;
  progressText.textContent = `${percent}%`;
}

function setSummary(countText, sevText, sevClassAdd = null) {
  issueCount.textContent = countText;
  overallSeverity.textContent = sevText;
  overallSeverity.classList.remove('high-text');
  if (sevClassAdd) overallSeverity.classList.add(sevClassAdd);
}

function resetUI() {
  pollingActive = false;
  currentScanId = null;
  renderProgress(0);
  setSummary('0', '-');
  pauseBtn.textContent = 'Pause';
  pauseBtn.disabled = true;
  stopBtn.disabled = true;
  startBtn.disabled = false;
}

function showError(message) {
  alert(`Error: ${message}`);
  resetUI();
  progressSection.classList.add('hidden');
}

// Calculate overall severity from scan results
function calculateSeverity(scanData) {
  if (!scanData || !scanData.results) return 'Unknown';
  
  const results = scanData.results;
  let hasHigh = false;
  let hasMedium = false;
  
  // Check port scanner results
  if (results.port_scanner && results.port_scanner.open_ports) {
    results.port_scanner.open_ports.forEach(port => {
      if (port.risk_level === 'high') hasHigh = true;
      else if (port.risk_level === 'medium') hasMedium = true;
    });
  }
  
  // Check SSL/TLS results
  if (results.ssl_scanner && results.ssl_scanner.vulnerabilities) {
    results.ssl_scanner.vulnerabilities.forEach(vuln => {
      if (vuln.severity === 'high' || vuln.severity === 'critical') hasHigh = true;
      else if (vuln.severity === 'medium') hasMedium = true;
    });
  }
  
  // Check HTTP headers
  if (results.headers_scanner && results.headers_scanner.missing_headers) {
    if (results.headers_scanner.missing_headers.length > 0) hasMedium = true;
  }
  
  // Check CVE matches
  if (results.cve_checker && results.cve_checker.vulnerabilities) {
    results.cve_checker.vulnerabilities.forEach(cve => {
      if (cve.severity === 'HIGH' || cve.severity === 'CRITICAL') hasHigh = true;
      else if (cve.severity === 'MEDIUM') hasMedium = true;
    });
  }
  
  if (hasHigh) return 'High';
  if (hasMedium) return 'Medium';
  return 'Low';
}

// Count total issues found
function countIssues(scanData) {
  if (!scanData || !scanData.results) return 0;
  
  const results = scanData.results;
  let count = 0;
  
  // Count open ports
  if (results.port_scanner && results.port_scanner.open_ports) {
    count += results.port_scanner.open_ports.length;
  }
  
  // Count SSL vulnerabilities
  if (results.ssl_scanner && results.ssl_scanner.vulnerabilities) {
    count += results.ssl_scanner.vulnerabilities.length;
  }
  
  // Count missing headers
  if (results.headers_scanner && results.headers_scanner.missing_headers) {
    count += results.headers_scanner.missing_headers.length;
  }
  
  // Count CVE matches
  if (results.cve_checker && results.cve_checker.vulnerabilities) {
    count += results.cve_checker.vulnerabilities.length;
  }
  
  return count;
}

// ============================================================================
// SCAN MANAGEMENT
// ============================================================================
async function startScanning() {
  const target = targetInput.value.trim();
  
  // Validate input
  if (!target) {
    alert('Please enter a target (domain or IP address)');
    return;
  }
  
  const scanMode = document.querySelector('input[name="mode"]:checked').value;
  const authorized = (scanMode === 'Active');
  
  // Map UI mode to backend mode
  // Active = full scan, Passive = quick scan
  const backendMode = authorized ? 'full' : 'quick';
  
  // Update UI
  resultTarget.textContent = target;
  resultMode.textContent = scanMode + ' Scanning';
  resultDate.textContent = formatDate();
  
  noResult.classList.add('hidden');
  progressSection.classList.remove('hidden');
  resultsTable.classList.add('hidden');
  
  renderProgress(0);
  setSummary('0', 'Scanning...');
  
  startBtn.disabled = true;
  pauseBtn.disabled = true; // Backend doesn't support pause
  stopBtn.disabled = false;
  
  try {
    // Start scan via API
    const scanRequest = {
      target: target,
      mode: backendMode,
      authorized: authorized,
      modules: ['port_scanner', 'ssl_scanner', 'headers_scanner', 'cve_checker']
    };
    
    const response = await window.VASA_API.startScan(scanRequest);
    
    if (!response.scan_id) {
      throw new Error('No scan ID returned from server');
    }
    
    currentScanId = response.scan_id;
    pollingActive = true;
    
    // Start polling for status
    await window.VASA_API.pollScanStatus(
      currentScanId,
      (statusData) => handleScanProgress(statusData)
    );
    
  } catch (error) {
    console.error('Scan failed:', error);
    showError(error.message || 'Failed to start scan');
  }
}

function handleScanProgress(statusData) {
  if (!pollingActive) return;
  
  const status = statusData.status;
  const progress = statusData.progress || 0;
  
  // Update progress bar
  renderProgress(Math.round(progress));
  
  if (status === 'completed') {
    pollingActive = false;
    currentScanData = statusData;
    displayResults(statusData);
  } else if (status === 'failed') {
    pollingActive = false;
    showError(statusData.error || 'Scan failed');
  } else if (status === 'cancelled') {
    pollingActive = false;
    showError('Scan was cancelled');
  }
}

function displayResults(scanData) {
  // Calculate summary
  const totalIssues = countIssues(scanData);
  const severity = calculateSeverity(scanData);
  const sevClass = severity.toLowerCase() === 'high' ? 'high-text' : null;
  
  setSummary(totalIssues.toString(), severity, sevClass);
  
  // Show results table
  resultsTable.classList.remove('hidden');
  
  // Enable buttons
  startBtn.disabled = false;
  stopBtn.disabled = true;
  
  // Store scan data for detail view
  sessionStorage.setItem('latestScanData', JSON.stringify(scanData));
  sessionStorage.setItem('latestScanId', currentScanId);
}

function stopScanning() {
  pollingActive = false;
  resetUI();
  progressSection.classList.add('hidden');
  resultsTable.classList.add('hidden');
  noResult.classList.remove('hidden');
}

// ============================================================================
// NAVIGATION
// ============================================================================
function viewDetailedResults() {
  if (!currentScanData || !currentScanId) {
    alert('No scan results available. Please complete a scan first.');
    return;
  }
  
  // Store data in sessionStorage
  sessionStorage.setItem('currentScanData', JSON.stringify(currentScanData));
  sessionStorage.setItem('currentScanId', currentScanId);
  
  // Navigate to results page
  window.location.href = 'resultpage.html';
}

async function exportPDFReport() {
  if (!currentScanId) {
    alert('No scan results available. Please complete a scan first.');
    return;
  }
  
  try {
    pdfBtn.disabled = true;
    pdfBtn.textContent = 'Generating...';
    
    await window.VASA_API.getScanReport(currentScanId);
    
    pdfBtn.disabled = false;
    pdfBtn.textContent = 'PDF Report';
  } catch (error) {
    console.error('PDF export failed:', error);
    alert('Failed to generate PDF report: ' + error.message);
    pdfBtn.disabled = false;
    pdfBtn.textContent = 'PDF Report';
  }
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================
startBtn.addEventListener('click', startScanning);
stopBtn.addEventListener('click', stopScanning);
viewDetailBtn.addEventListener('click', viewDetailedResults);
pdfBtn.addEventListener('click', exportPDFReport);

// Pause button - not supported by backend
pauseBtn.addEventListener('click', () => {
  alert('Pause/Resume is not supported. You can only stop the scan.');
});

// ============================================================================
// INITIALIZATION
// ============================================================================
resetUI();
renderProgress(0);
