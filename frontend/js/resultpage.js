/**
 * VASA Results Page - Display Scan Results
 * Fetches and displays scan results from backend API
 * 
 * @requires api.js - Must be loaded before this script
 */

// ==================== STATE MANAGEMENT ====================

let scanData = null;
let scanId = null;

// ==================== INITIALIZATION ====================

/**
 * Extract scan_id from URL query parameter
 * @returns {string|null} - Scan ID or null if not found
 */
function getScanIdFromURL() {
    const params = new URLSearchParams(window.location.search);
    return params.get('scan_id');
}

/**
 * Load scan results from API and display
 */
async function loadResults() {
    try {
        console.log('[ResultPage] Loading results...');
        
        // Get scan_id from URL
        scanId = getScanIdFromURL();
        
        if (!scanId) {
            console.error('[ResultPage] No scan_id in URL');
            alert('No scan ID provided. Redirecting to homepage...');
            window.location.href = 'homepage.html';
            return;
        }
        
        console.log(`[ResultPage] Loading scan: ${scanId}`);
        
        // Fetch results from API
        scanData = await API.getScanResults(scanId);
        console.log('[ResultPage] Scan data loaded:', scanData);
        
        // Display all data
        displayMetadata(scanData);
        displayKPIs(scanData.summary);
        displayPortScan(scanData.results?.port_scan);
        displayHeadersScan(scanData.results?.headers_scan);
        displaySSLScan(scanData.results?.ssl_scan);
        displayCVEScan(scanData.results?.cve_check);
        
        console.log('[ResultPage] All data displayed successfully');
        
    } catch (error) {
        console.error('[ResultPage] Error loading results:', error);
        alert(`Failed to load scan results: ${error.message}\n\nRedirecting to homepage...`);
        setTimeout(() => {
            window.location.href = 'homepage.html';
        }, 2000);
    }
}

// ==================== METADATA DISPLAY ====================

/**
 * Display scan metadata (target, date, mode)
 * @param {Object} data - Scan data from API
 */
function displayMetadata(data) {
    console.log('[ResultPage] Displaying metadata');
    
    // Update target
    const targetElem = document.getElementById('scan-target');
    if (targetElem) {
        targetElem.textContent = data.target || 'Unknown';
    }
    
    // Update date
    const dateElem = document.getElementById('scan-date');
    if (dateElem) {
        const formattedDate = data.timestamp ? formatDate(data.timestamp) : formatDate(new Date().toISOString());
        dateElem.textContent = formattedDate;
    }
    
    // Update mode (if element exists)
    const modeElem = document.getElementById('scan-mode');
    if (modeElem) {
        const mode = data.scan_mode || 'active';
        modeElem.textContent = mode.charAt(0).toUpperCase() + mode.slice(1);
    }
}

/**
 * Format ISO date string to dd.mm.yyyy
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted date
 */
function formatDate(dateString) {
    const d = new Date(dateString);
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yyyy = d.getFullYear();
    return `${dd}.${mm}.${yyyy}`;
}

// ==================== KPI DISPLAY ====================

/**
 * Display KPI metrics (total issues, overall severity)
 * @param {Object} summary - Summary data from API
 */
function displayKPIs(summary) {
    console.log('[ResultPage] Displaying KPIs:', summary);
    
    if (!summary) {
        console.warn('[ResultPage] No summary data');
        return;
    }
    
    // Update total issues
    const totalElem = document.getElementById('total-issues');
    if (totalElem) {
        totalElem.textContent = summary.total_vulnerabilities || 0;
    }
    
    // Calculate overall severity
    let severity = 'Low';
    let severityClass = 'sev-low';
    
    if (summary.critical > 0) {
        severity = 'Critical';
        severityClass = 'sev-high'; // Use high class for critical
    } else if (summary.high > 0) {
        severity = 'High';
        severityClass = 'sev-high';
    } else if (summary.medium > 0) {
        severity = 'Medium';
        severityClass = 'sev-med';
    } else {
        severity = 'Low';
        severityClass = 'sev-low';
    }
    
    // Update overall severity
    const sevElem = document.getElementById('overall-sev');
    if (sevElem) {
        sevElem.textContent = severity;
        // Clear old classes and add new one
        sevElem.className = severityClass;
    }
}

// ==================== PORT SCAN DISPLAY ====================

/**
 * Display port scan results in table
 * @param {Object} portData - Port scan data from API
 */
function displayPortScan(portData) {
    console.log('[ResultPage] Displaying port scan:', portData);
    
    const tbody = document.getElementById('ports-body');
    if (!tbody) {
        console.warn('[ResultPage] Port table body not found');
        return;
    }
    
    // Clear existing content
    tbody.innerHTML = '';
    
    if (!portData || !portData.open_ports || portData.open_ports.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" style="text-align: center;">No open ports found</td></tr>';
        return;
    }
    
    // Build rows for each open port
    portData.open_ports.forEach(port => {
        const service = portData.services?.[port] || 'Unknown';
        const banner = portData.banners?.[port] || '-';
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${port}</td>
            <td>${service}</td>
            <td>${banner}</td>
        `;
        tbody.appendChild(row);
    });
    
    console.log(`[ResultPage] Displayed ${portData.open_ports.length} ports`);
}

// ==================== HTTP HEADERS DISPLAY ====================

/**
 * Display HTTP headers scan results
 * @param {Object} headersData - Headers scan data from API
 */
function displayHeadersScan(headersData) {
    console.log('[ResultPage] Displaying headers scan:', headersData);
    
    const panel = document.getElementById('acc-headers');
    if (!panel) {
        console.warn('[ResultPage] Headers panel not found');
        return;
    }
    
    // Find or create list element
    let list = panel.querySelector('.list');
    if (!list) {
        list = document.createElement('ul');
        list.className = 'list';
        panel.appendChild(list);
    }
    
    // Clear existing content
    list.innerHTML = '';
    
    if (!headersData) {
        list.innerHTML = '<li><span class="dot low"></span> No header scan data available</li>';
        return;
    }
    
    // Display present headers (good)
    if (headersData.present && headersData.present.length > 0) {
        headersData.present.forEach(header => {
            const li = document.createElement('li');
            li.innerHTML = `<span class="dot" style="background-color: #06c262;"></span> Present: ${header}`;
            list.appendChild(li);
        });
    }
    
    // Display missing headers (warning)
    if (headersData.missing && headersData.missing.length > 0) {
        headersData.missing.forEach(header => {
            const li = document.createElement('li');
            li.innerHTML = `<span class="dot medium"></span> Missing: ${header}`;
            list.appendChild(li);
        });
    }
    
    // If no headers at all
    if ((!headersData.present || headersData.present.length === 0) && 
        (!headersData.missing || headersData.missing.length === 0)) {
        list.innerHTML = '<li><span class="dot low"></span> No header information available</li>';
    }
}

// ==================== SSL/TLS DISPLAY ====================

/**
 * Display SSL/TLS scan results
 * @param {Object} sslData - SSL scan data from API
 */
function displaySSLScan(sslData) {
    console.log('[ResultPage] Displaying SSL scan:', sslData);
    
    const panel = document.getElementById('acc-ssl');
    if (!panel) {
        console.warn('[ResultPage] SSL panel not found');
        return;
    }
    
    // Find or create list element
    let list = panel.querySelector('.list');
    if (!list) {
        list = document.createElement('ul');
        list.className = 'list';
        panel.appendChild(list);
    }
    
    // Clear existing content
    list.innerHTML = '';
    
    if (!sslData) {
        list.innerHTML = '<li><span class="dot low"></span> No SSL/TLS scan data available</li>';
        return;
    }
    
    // Certificate validity
    const validIcon = sslData.valid ? '✓' : '✗';
    const validClass = sslData.valid ? 'style="background-color: #06c262;"' : 'class="high"';
    const validText = sslData.valid ? 'Valid' : 'Invalid';
    list.innerHTML += `<li><span class="dot" ${validClass}></span> Certificate: ${validIcon} ${validText}</li>`;
    
    // Issuer
    if (sslData.issuer) {
        list.innerHTML += `<li><span class="dot low"></span> Issuer: ${sslData.issuer}</li>`;
    }
    
    // Expiry date and days until expiry
    if (sslData.expires) {
        const expiryDate = formatDate(sslData.expires);
        const daysUntilExpiry = sslData.days_until_expiry || 0;
        
        let expiryClass = 'low';
        let expiryIcon = '✓';
        if (daysUntilExpiry < 30) {
            expiryClass = 'high';
            expiryIcon = '⚠';
        }
        
        list.innerHTML += `<li><span class="dot ${expiryClass}"></span> ${expiryIcon} Expires: ${expiryDate} (${daysUntilExpiry} days)</li>`;
    }
    
    // Vulnerabilities
    if (sslData.vulnerabilities && sslData.vulnerabilities.length > 0) {
        list.innerHTML += '<li><strong>Vulnerabilities:</strong></li>';
        sslData.vulnerabilities.forEach(vuln => {
            list.innerHTML += `<li style="margin-left: 20px;"><span class="dot medium"></span> ${vuln}</li>`;
        });
    } else {
        list.innerHTML += '<li><span class="dot" style="background-color: #06c262;"></span> No SSL/TLS vulnerabilities found</li>';
    }
}

// ==================== CVE DISPLAY ====================

/**
 * Display CVE vulnerabilities
 * @param {Object} cveData - CVE scan data from API
 */
function displayCVEScan(cveData) {
    console.log('[ResultPage] Displaying CVE scan:', cveData);
    
    const panel = document.getElementById('acc-cve');
    if (!panel) {
        console.warn('[ResultPage] CVE panel not found');
        return;
    }
    
    // Find or create list element
    let list = panel.querySelector('.list');
    if (!list) {
        list = document.createElement('ul');
        list.className = 'list';
        panel.appendChild(list);
    }
    
    // Clear existing content
    list.innerHTML = '';
    
    if (!cveData) {
        list.innerHTML = '<li><span class="dot low"></span> No CVE scan data available</li>';
        return;
    }
    
    // Check if vulnerabilities exist
    if (!cveData.vulnerabilities || cveData.vulnerabilities.length === 0) {
        list.innerHTML = '<li><span class="dot" style="background-color: #06c262;"></span> No known CVEs found</li>';
        return;
    }
    
    // Display each vulnerability
    cveData.vulnerabilities.forEach(vuln => {
        const severityClass = getSeverityClass(vuln.severity);
        const li = document.createElement('li');
        
        li.innerHTML = `
            <span class="dot ${severityClass}"></span>
            <strong>${vuln.cve_id}</strong> (${vuln.severity}): ${vuln.description}
            ${vuln.cvss_score ? `<br/><span style="margin-left: 20px;">CVSS: ${vuln.cvss_score}</span>` : ''}
        `;
        
        list.appendChild(li);
    });
    
    console.log(`[ResultPage] Displayed ${cveData.vulnerabilities.length} CVEs`);
}

/**
 * Map severity string to CSS class
 * @param {string} severity - Severity level (critical, high, medium, low)
 * @returns {string} - CSS class name
 */
function getSeverityClass(severity) {
    if (!severity) return 'low';
    
    const sev = severity.toLowerCase();
    if (sev === 'critical' || sev === 'high') {
        return 'high';
    } else if (sev === 'medium') {
        return 'medium';
    } else {
        return 'low';
    }
}

// ==================== ACTION FUNCTIONS ====================

/**
 * Download PDF report
 */
async function downloadPDF() {
    try {
        console.log('[ResultPage] Downloading PDF...');
        
        const exportBtn = document.getElementById('exportBtn');
        if (exportBtn) {
            exportBtn.disabled = true;
            exportBtn.textContent = 'Downloading...';
        }
        
        // Get PDF blob from API
        const blob = await API.downloadReport(scanId);
        
        // Create download link
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vasa_scan_report_${scanId}.pdf`;
        document.body.appendChild(a);
        a.click();
        
        // Cleanup
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        console.log('[ResultPage] PDF downloaded successfully');
        
        if (exportBtn) {
            exportBtn.disabled = false;
            exportBtn.textContent = 'Export to PDF';
        }
        
    } catch (error) {
        console.error('[ResultPage] Error downloading PDF:', error);
        alert(`Failed to download PDF: ${error.message}`);
        
        const exportBtn = document.getElementById('exportBtn');
        if (exportBtn) {
            exportBtn.disabled = false;
            exportBtn.textContent = 'Export to PDF';
        }
    }
}

/**
 * Navigate to homepage for new scan
 */
function startNewScan() {
    console.log('[ResultPage] Starting new scan');
    window.location.href = 'homepage.html';
}

/**
 * Re-scan the same target
 */
function rescan() {
    console.log('[ResultPage] Re-scanning target');
    
    // If we have target from scanData, pre-fill it
    if (scanData && scanData.target) {
        window.location.href = `homepage.html?target=${encodeURIComponent(scanData.target)}`;
    } else {
        window.location.href = 'homepage.html';
    }
}

// ==================== ACCORDION FUNCTIONALITY ====================

/**
 * Setup accordion expand/collapse functionality
 */
function setupAccordions() {
    const accordionButtons = document.querySelectorAll('.acc-btn');
    
    accordionButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-acc');
            const panel = document.getElementById(targetId);
            
            if (!panel) return;
            
            // Check current state
            const isOpen = panel.style.display === 'block';
            
            // Close all panels
            document.querySelectorAll('.acc-panel').forEach(p => {
                p.style.display = 'none';
            });
            
            // Reset all chevrons
            document.querySelectorAll('.acc-btn .chev').forEach(c => {
                c.textContent = '▾';
            });
            
            // Toggle current panel
            if (!isOpen) {
                panel.style.display = 'block';
                const chev = btn.querySelector('.chev');
                if (chev) {
                    chev.textContent = '▴';
                }
            }
        });
    });
    
    console.log('[ResultPage] Accordions setup complete');
}

// ==================== EVENT LISTENERS ====================

document.addEventListener('DOMContentLoaded', () => {
    console.log('[ResultPage] Initializing...');
    
    // Load results immediately
    loadResults();
    
    // Setup button listeners
    const exportBtn = document.getElementById('exportBtn');
    const anotherScanBtn = document.getElementById('anotherScanBtn');
    const rescanBtn = document.getElementById('rescanBtn');
    
    if (exportBtn) {
        exportBtn.addEventListener('click', downloadPDF);
    }
    
    if (anotherScanBtn) {
        anotherScanBtn.addEventListener('click', startNewScan);
    }
    
    if (rescanBtn) {
        rescanBtn.addEventListener('click', rescan);
    }
    
    // Setup accordions
    setupAccordions();
    
    console.log('[ResultPage] Initialization complete');
});

// ==================== ERROR RECOVERY ====================

/**
 * Handle page unload - cleanup
 */
window.addEventListener('beforeunload', () => {
    console.log('[ResultPage] Page unloading');
});

console.log('[ResultPage] Script loaded successfully');