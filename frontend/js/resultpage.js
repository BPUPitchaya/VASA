// VASA Results Page - Display Real Backend Scan Results
// Loads scan data from sessionStorage and displays detailed vulnerability information

// ============================================================================
// STATE MANAGEMENT
// ============================================================================
let scanData = null;
let scanId = null;

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
function formatDate(dateString) {
  const d = dateString ? new Date(dateString) : new Date();
  const dd = String(d.getDate()).padStart(2, '0');
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const yyyy = d.getFullYear();
  return `${dd}.${mm}.${yyyy}`;
}

function sevCell(level) {
  const levelUpper = (level || '').toUpperCase();
  const map = {
    'LOW': '<span class="dot low"></span> Low',
    'MEDIUM': '<span class="dot medium"></span> Medium',
    'HIGH': '<span class="dot high"></span> High',
    'CRITICAL': '<span class="dot high"></span> Critical'
  };
  return map[levelUpper] || `<span class="dot low"></span> ${level}`;
}

// ============================================================================
// DATA LOADING
// ============================================================================
function loadScanData() {
  // Try to load from sessionStorage
  const storedData = sessionStorage.getItem('currentScanData');
  const storedId = sessionStorage.getItem('currentScanId');
  
  if (storedData && storedId) {
    try {
      scanData = JSON.parse(storedData);
      scanId = storedId;
      return true;
    } catch (error) {
      console.error('Failed to parse scan data:', error);
      return false;
    }
  }
  
  return false;
}

// ============================================================================
// UI RENDERING
// ============================================================================
function renderScanMetadata() {
  if (!scanData) return;
  
  document.getElementById('scan-target').textContent = scanData.target || 'Unknown';
  document.getElementById('scan-mode').textContent = scanData.mode || 'Unknown';
  document.getElementById('scan-date').textContent = formatDate(scanData.created_at || scanData.timestamp);
}

function renderPortScanResults() {
  const tbody = document.getElementById('ports-body');
  
  if (!scanData || !scanData.results || !scanData.results.port_scanner) {
    tbody.innerHTML = '<tr><td colspan="4">No port scan data available</td></tr>';
    return;
  }
  
  const portResults = scanData.results.port_scanner;
  const openPorts = portResults.open_ports || [];
  
  if (openPorts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4">No open ports detected</td></tr>';
    return;
  }
  
  tbody.innerHTML = openPorts.map(port => `
    <tr>
      <td>${port.port}</td>
      <td>${port.service || 'Unknown'}</td>
      <td>${port.state || 'Open'}</td>
      <td>${sevCell(port.risk_level || 'low')}</td>
    </tr>
  `).join('');
}

function renderHeadersResults() {
  const container = document.querySelector('#acc-headers .list');
  
  if (!scanData || !scanData.results || !scanData.results.headers_scanner) {
    container.innerHTML = '<li>No HTTP headers scan data available</li>';
    return;
  }
  
  const headersResults = scanData.results.headers_scanner;
  const missing = headersResults.missing_headers || [];
  const insecure = headersResults.insecure_headers || [];
  
  const items = [];
  
  missing.forEach(header => {
    items.push(`<li><span class="dot low"></span> Missing ${header.name || header}</li>`);
  });
  
  insecure.forEach(header => {
    const severity = header.severity || 'medium';
    items.push(`<li>${sevCell(severity)} Insecure ${header.name}: ${header.value || ''}</li>`);
  });
  
  if (items.length === 0) {
    container.innerHTML = '<li><span class="dot low"></span> No issues detected</li>';
  } else {
    container.innerHTML = items.join('');
  }
}

function renderSSLResults() {
  const container = document.querySelector('#acc-ssl .list');
  
  if (!scanData || !scanData.results || !scanData.results.ssl_scanner) {
    container.innerHTML = '<li>No SSL/TLS scan data available</li>';
    return;
  }
  
  const sslResults = scanData.results.ssl_scanner;
  const vulnerabilities = sslResults.vulnerabilities || [];
  const issues = sslResults.issues || [];
  
  const items = [];
  
  vulnerabilities.forEach(vuln => {
    const severity = vuln.severity || 'medium';
    const desc = vuln.description || vuln.issue || vuln.name || 'SSL/TLS vulnerability';
    items.push(`<li>${sevCell(severity)} ${desc}</li>`);
  });
  
  issues.forEach(issue => {
    const severity = issue.severity || 'medium';
    const desc = issue.description || issue.name || 'SSL/TLS issue';
    items.push(`<li>${sevCell(severity)} ${desc}</li>`);
  });
  
  if (items.length === 0) {
    container.innerHTML = '<li><span class="dot low"></span> No issues detected</li>';
  } else {
    container.innerHTML = items.join('');
  }
}

function renderCVEResults() {
  const container = document.querySelector('#acc-cve .list');
  
  if (!scanData || !scanData.results || !scanData.results.cve_checker) {
    container.innerHTML = '<li>No CVE scan data available</li>';
    return;
  }
  
  const cveResults = scanData.results.cve_checker;
  const vulnerabilities = cveResults.vulnerabilities || [];
  
  if (vulnerabilities.length === 0) {
    container.innerHTML = '<li><span class="dot low"></span> No CVE matches found</li>';
    return;
  }
  
  container.innerHTML = vulnerabilities.map(cve => {
    const severity = cve.severity || 'MEDIUM';
    const cveId = cve.cve_id || cve.id || 'Unknown CVE';
    const description = cve.description || '';
    const service = cve.service || '';
    
    let text = `${cveId}`;
    if (service) text += ` on ${service}`;
    if (description) text += ` - ${description.substring(0, 100)}`;
    
    return `<li>${sevCell(severity)} ${text}</li>`;
  }).join('');
}

function calculateOverallSeverity() {
  if (!scanData || !scanData.results) return 'Unknown';
  
  const results = scanData.results;
  let hasHigh = false;
  let hasMedium = false;
  
  // Check port scanner results
  if (results.port_scanner && results.port_scanner.open_ports) {
    results.port_scanner.open_ports.forEach(port => {
      const risk = (port.risk_level || '').toUpperCase();
      if (risk === 'HIGH' || risk === 'CRITICAL') hasHigh = true;
      else if (risk === 'MEDIUM') hasMedium = true;
    });
  }
  
  // Check SSL/TLS results
  if (results.ssl_scanner) {
    (results.ssl_scanner.vulnerabilities || []).forEach(vuln => {
      const sev = (vuln.severity || '').toUpperCase();
      if (sev === 'HIGH' || sev === 'CRITICAL') hasHigh = true;
      else if (sev === 'MEDIUM') hasMedium = true;
    });
  }
  
  // Check HTTP headers
  if (results.headers_scanner) {
    if ((results.headers_scanner.missing_headers || []).length > 0) hasMedium = true;
    (results.headers_scanner.insecure_headers || []).forEach(header => {
      const sev = (header.severity || '').toUpperCase();
      if (sev === 'HIGH' || sev === 'CRITICAL') hasHigh = true;
      else if (sev === 'MEDIUM') hasMedium = true;
    });
  }
  
  // Check CVE matches
  if (results.cve_checker && results.cve_checker.vulnerabilities) {
    results.cve_checker.vulnerabilities.forEach(cve => {
      const sev = (cve.severity || '').toUpperCase();
      if (sev === 'HIGH' || sev === 'CRITICAL') hasHigh = true;
      else if (sev === 'MEDIUM') hasMedium = true;
    });
  }
  
  if (hasHigh) return 'High';
  if (hasMedium) return 'Medium';
  return 'Low';
}

function countTotalIssues() {
  if (!scanData || !scanData.results) return 0;
  
  const results = scanData.results;
  let count = 0;
  
  // Count open ports
  if (results.port_scanner && results.port_scanner.open_ports) {
    count += results.port_scanner.open_ports.length;
  }
  
  // Count SSL vulnerabilities
  if (results.ssl_scanner) {
    count += (results.ssl_scanner.vulnerabilities || []).length;
    count += (results.ssl_scanner.issues || []).length;
  }
  
  // Count header issues
  if (results.headers_scanner) {
    count += (results.headers_scanner.missing_headers || []).length;
    count += (results.headers_scanner.insecure_headers || []).length;
  }
  
  // Count CVE matches
  if (results.cve_checker && results.cve_checker.vulnerabilities) {
    count += results.cve_checker.vulnerabilities.length;
  }
  
  return count;
}

function renderKPIs() {
  const totalIssues = countTotalIssues();
  const overallSev = calculateOverallSeverity();
  
  document.getElementById('total-issues').textContent = totalIssues;
  
  const sevElement = document.getElementById('overall-sev');
  sevElement.textContent = overallSev;
  sevElement.className = 'kpi-value';
  if (overallSev === 'High') sevElement.classList.add('sev-high');
  else if (overallSev === 'Medium') sevElement.classList.add('sev-medium');
  else sevElement.classList.add('sev-low');
}

function renderBreakdownTable() {
  const tbody = document.querySelector('.breakdown table tbody');
  
  if (!scanData || !scanData.results) {
    tbody.innerHTML = '<tr><td colspan="3">No data available</td></tr>';
    return;
  }
  
  const results = scanData.results;
  const categories = [];
  
  // Ports
  if (results.port_scanner) {
    const count = (results.port_scanner.open_ports || []).length;
    let maxSev = 'Low';
    (results.port_scanner.open_ports || []).forEach(port => {
      const risk = (port.risk_level || '').toUpperCase();
      if (risk === 'HIGH' || risk === 'CRITICAL') maxSev = 'High';
      else if (risk === 'MEDIUM' && maxSev !== 'High') maxSev = 'Medium';
    });
    categories.push({ name: 'Open Port & Services', count, severity: maxSev });
  }
  
  // Headers
  if (results.headers_scanner) {
    const count = (results.headers_scanner.missing_headers || []).length + 
                  (results.headers_scanner.insecure_headers || []).length;
    let maxSev = 'Low';
    (results.headers_scanner.insecure_headers || []).forEach(h => {
      const sev = (h.severity || '').toUpperCase();
      if (sev === 'HIGH' || sev === 'CRITICAL') maxSev = 'High';
      else if (sev === 'MEDIUM' && maxSev !== 'High') maxSev = 'Medium';
    });
    categories.push({ name: 'Insecure HTTP Headers', count, severity: maxSev });
  }
  
  // SSL
  if (results.ssl_scanner) {
    const count = (results.ssl_scanner.vulnerabilities || []).length + 
                  (results.ssl_scanner.issues || []).length;
    let maxSev = 'Low';
    (results.ssl_scanner.vulnerabilities || []).forEach(v => {
      const sev = (v.severity || '').toUpperCase();
      if (sev === 'HIGH' || sev === 'CRITICAL') maxSev = 'High';
      else if (sev === 'MEDIUM' && maxSev !== 'High') maxSev = 'Medium';
    });
    categories.push({ name: 'SSL/TLS Misconfigurations', count, severity: maxSev });
  }
  
  // CVE
  if (results.cve_checker) {
    const count = (results.cve_checker.vulnerabilities || []).length;
    let maxSev = 'Low';
    (results.cve_checker.vulnerabilities || []).forEach(cve => {
      const sev = (cve.severity || '').toUpperCase();
      if (sev === 'HIGH' || sev === 'CRITICAL') maxSev = 'High';
      else if (sev === 'MEDIUM' && maxSev !== 'High') maxSev = 'Medium';
    });
    categories.push({ name: 'CVE Matches', count, severity: maxSev });
  }
  
  tbody.innerHTML = categories.map(cat => `
    <tr>
      <td>${cat.name}</td>
      <td>${cat.count}</td>
      <td>${sevCell(cat.severity)}</td>
    </tr>
  `).join('');
}

function renderAllResults() {
  renderScanMetadata();
  renderPortScanResults();
  renderHeadersResults();
  renderSSLResults();
  renderCVEResults();
  renderKPIs();
  renderBreakdownTable();
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================
function setupAccordions() {
  document.querySelectorAll('.acc-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-acc');
      const panel = document.getElementById(id);
      const isOpen = panel.style.display === 'block';
      
      closeAllAccordions();
      
      if (!isOpen) {
        panel.style.display = 'block';
        btn.querySelector('.chev').textContent = '▴';
      }
    });
  });
}

function closeAllAccordions() {
  document.querySelectorAll('.acc-panel').forEach(p => p.style.display = 'none');
  document.querySelectorAll('.acc-btn .chev').forEach(c => c.textContent = '▾');
}

async function handleRescan() {
  if (!scanData || !scanData.target) {
    alert('Cannot rescan: no target information available');
    return;
  }
  
  const confirmRescan = confirm(`Rescan ${scanData.target}?`);
  if (!confirmRescan) return;
  
  try {
    const scanRequest = {
      target: scanData.target,
      mode: scanData.mode || 'passive',
      authorized: scanData.authorized || false,
      modules: ['port_scanner', 'ssl_scanner', 'headers_scanner', 'cve_checker']
    };
    
    const response = await window.VASA_API.startScan(scanRequest);
    
    // Store new scan ID and redirect to homepage to show progress
    sessionStorage.setItem('currentScanId', response.scan_id);
    sessionStorage.removeItem('currentScanData'); // Clear old data
    
    alert('Rescan started. Redirecting to homepage...');
    window.location.href = 'homepage.html';
    
  } catch (error) {
    console.error('Rescan failed:', error);
    alert('Failed to start rescan: ' + error.message);
  }
}

function handleAnotherScan() {
  // Clear current scan data
  sessionStorage.removeItem('currentScanData');
  sessionStorage.removeItem('currentScanId');
  
  // Navigate back to homepage
  window.location.href = 'homepage.html';
}

async function handleExportPDF() {
  if (!scanId) {
    alert('Cannot export: no scan ID available');
    return;
  }
  
  try {
    const btn = document.getElementById('exportBtn');
    btn.disabled = true;
    btn.textContent = 'Generating PDF...';
    
    await window.VASA_API.getScanReport(scanId);
    
    btn.disabled = false;
    btn.textContent = 'Export PDF Report';
    
  } catch (error) {
    console.error('PDF export failed:', error);
    alert('Failed to generate PDF report: ' + error.message);
    
    const btn = document.getElementById('exportBtn');
    btn.disabled = false;
    btn.textContent = 'Export PDF Report';
  }
}

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  // Load scan data
  const dataLoaded = loadScanData();
  
  if (!dataLoaded) {
    alert('No scan results available. Redirecting to homepage...');
    window.location.href = 'homepage.html';
    return;
  }
  
  // Render all results
  renderAllResults();
  
  // Setup accordions
  setupAccordions();
  
  // Setup button event listeners
  document.getElementById('rescanBtn').addEventListener('click', handleRescan);
  document.getElementById('anotherScanBtn').addEventListener('click', handleAnotherScan);
  document.getElementById('exportBtn').addEventListener('click', handleExportPDF);
});
