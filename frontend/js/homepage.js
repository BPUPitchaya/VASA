/**
 * VASA Homepage - Scan Initiation Logic
 * Handles user input, validation, scan initiation, and progress tracking
 * 
 * @requires api.js - Must be loaded before this script
 */

// ==================== STATE MANAGEMENT ====================

let currentScanId = null;
let pollInterval = null;
let isPaused = false;

// ==================== DOM ELEMENT REFERENCES ====================

// Form elements
let targetInput;
let modeRadios;
let startBtn;
let pauseBtn;
let stopBtn;

// Display elements
let progressSection;
let progressFill;
let progressText;
let issueCount;
let overallSeverity;
let resultTarget;
let resultMode;
let resultDate;
let resultsTable;
let noResult;

// ==================== INITIALIZATION ====================

/**
 * Initialize all DOM references and event listeners
 */
document.addEventListener('DOMContentLoaded', () => {
    console.log('[Homepage] Initializing...');
    
    // Cache DOM elements
    targetInput = document.getElementById('target');
    modeRadios = document.getElementsByName('mode');
    startBtn = document.getElementById('start');
    pauseBtn = document.getElementById('pause');
    stopBtn = document.getElementById('stop');
    
    progressSection = document.getElementById('progress-section');
    progressFill = document.getElementById('progress-fill');
    progressText = document.getElementById('progress-text');
    issueCount = document.getElementById('issue-count');
    overallSeverity = document.getElementById('overall-severity');
    resultTarget = document.getElementById('result-target');
    resultMode = document.getElementById('result-mode');
    resultDate = document.getElementById('result-date');
    resultsTable = document.getElementById('results-table');
    noResult = document.getElementById('no-result');
    
    // Attach event listeners
    startBtn.addEventListener('click', handleStartScan);
    pauseBtn.addEventListener('click', handlePauseScan);
    stopBtn.addEventListener('click', handleStopScan);
    
    // Allow Enter key to submit
    targetInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleStartScan();
        }
    });
    
    console.log('[Homepage] Initialization complete');
});

// ==================== INPUT VALIDATION ====================

/**
 * Validate target input (URL or IP address)
 * @param {string} target - User input to validate
 * @returns {{valid: boolean, error: string|null}} - Validation result
 */
function validateTarget(target) {
    // Check if empty
    if (!target || target.trim().length === 0) {
        return { valid: false, error: 'Please enter a target URL or IP address' };
    }
    
    target = target.trim();
    
    // Check length
    if (target.length > 255) {
        return { valid: false, error: 'Target is too long (max 255 characters)' };
    }
    
    // Check for dangerous characters
    const dangerousChars = /[<>\"'`]/;
    if (dangerousChars.test(target)) {
        return { valid: false, error: 'Target contains invalid characters' };
    }
    
    // Validate IP address format (xxx.xxx.xxx.xxx)
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(target)) {
        // Check each octet is 0-255
        const octets = target.split('.');
        const validOctets = octets.every(octet => {
            const num = parseInt(octet, 10);
            return num >= 0 && num <= 255;
        });
        
        if (validOctets) {
            return { valid: true, error: null };
        } else {
            return { valid: false, error: 'Invalid IP address format (octets must be 0-255)' };
        }
    }
    
    // Validate domain/hostname format
    // Allow: example.com, sub.example.com, example.co.uk, localhost
    const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/;
    if (domainPattern.test(target)) {
        return { valid: true, error: null };
    }
    
    // Also accept URLs with protocol (strip it)
    const urlPattern = /^https?:\/\/(.+)$/i;
    const urlMatch = target.match(urlPattern);
    if (urlMatch) {
        return validateTarget(urlMatch[1]); // Validate without protocol
    }
    
    return { valid: false, error: 'Invalid URL or IP address format' };
}

/**
 * Get currently selected scan mode
 * @returns {string} - "Active" or "Passive"
 */
function getSelectedMode() {
    for (const radio of modeRadios) {
        if (radio.checked) {
            return radio.value;
        }
    }
    return 'Active'; // Default fallback
}

// ==================== SCAN WORKFLOW ====================

/**
 * Handle start scan button click
 */
async function handleStartScan() {
    try {
        console.log('[Homepage] Start scan clicked');
        
        // Get input values
        const target = targetInput.value;
        const mode = getSelectedMode();
        
        // Validate input
        const validation = validateTarget(target);
        if (!validation.valid) {
            alert(`Error: ${validation.error}`);
            targetInput.focus();
            return;
        }
        
        // Set loading state
        setLoadingState(true);
        
        // Update display
        resultTarget.textContent = target;
        resultMode.textContent = mode;
        resultDate.textContent = formatDate();
        
        // Hide "no result" message
        if (noResult) {
            noResult.classList.add('hidden');
        }
        
        // Start scan via API
        console.log(`[Homepage] Starting scan: target=${target}, mode=${mode}`);
        const response = await API.startScan(target, mode.toLowerCase());
        
        currentScanId = response.scan_id;
        console.log(`[Homepage] Scan started with ID: ${currentScanId}`);
        
        // Show progress section
        showProgressSection();
        
        // Start polling for progress
        startPolling();
        
    } catch (error) {
        console.error('[Homepage] Error starting scan:', error);
        alert(`Failed to start scan: ${error.message}`);
        setLoadingState(false);
    }
}

/**
 * Start polling scan status
 */
function startPolling() {
    console.log('[Homepage] Starting status polling');
    
    // Clear any existing interval
    if (pollInterval) {
        clearInterval(pollInterval);
    }
    
    // Initial progress
    updateProgress(0, 'Initializing scan...');
    
    // Poll every 2 seconds
    pollInterval = setInterval(async () => {
        if (isPaused) {
            console.log('[Homepage] Polling paused');
            return;
        }
        
        try {
            const status = await API.getScanStatus(currentScanId);
            console.log('[Homepage] Poll status:', status);
            
            if (status.status === 'in_progress' || status.status === 'running') {
                // Update progress
                const progress = status.progress || 0;
                const message = status.current_step || 'Scanning...';
                updateProgress(progress, message);
                
            } else if (status.status === 'completed') {
                // Scan complete
                console.log('[Homepage] Scan completed');
                updateProgress(100, 'Scan complete!');
                stopPolling();
                
                // Get results to display summary
                try {
                    const results = await API.getScanResults(currentScanId);
                    displayQuickSummary(results);
                } catch (error) {
                    console.error('[Homepage] Failed to get results:', error);
                }
                
                // Redirect to results page after 1.5 seconds
                setTimeout(() => {
                    console.log('[Homepage] Redirecting to results page');
                    window.location.href = `resultpage.html?scan_id=${currentScanId}`;
                }, 1500);
                
            } else if (status.status === 'failed') {
                // Scan failed
                console.error('[Homepage] Scan failed');
                stopPolling();
                alert(`Scan failed: ${status.error || 'Unknown error'}`);
                setLoadingState(false);
                hideProgressSection();
            }
            
        } catch (error) {
            console.error('[Homepage] Error polling status:', error);
            // Don't stop polling on temporary errors, but log them
        }
    }, 2000); // Poll every 2 seconds
}

/**
 * Stop polling
 */
function stopPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
        console.log('[Homepage] Polling stopped');
    }
}

/**
 * Handle pause button click
 */
function handlePauseScan() {
    isPaused = !isPaused;
    
    if (isPaused) {
        console.log('[Homepage] Scan paused');
        pauseBtn.textContent = 'Resume';
        pauseBtn.classList.add('resume');
    } else {
        console.log('[Homepage] Scan resumed');
        pauseBtn.textContent = 'Pause';
        pauseBtn.classList.remove('resume');
    }
}

/**
 * Handle stop button click
 */
function handleStopScan() {
    console.log('[Homepage] Scan stopped by user');
    
    stopPolling();
    isPaused = false;
    currentScanId = null;
    
    // Reset UI
    setLoadingState(false);
    hideProgressSection();
    updateProgress(0, '');
    
    // Show "no result" message
    if (noResult) {
        noResult.classList.remove('hidden');
    }
    if (resultsTable) {
        resultsTable.classList.add('hidden');
    }
    
    // Reset summary
    if (issueCount) issueCount.textContent = '0';
    if (overallSeverity) {
        overallSeverity.textContent = '-';
        overallSeverity.className = '';
    }
}

// ==================== UI STATE MANAGEMENT ====================

/**
 * Set loading state (disable/enable form)
 * @param {boolean} isLoading - True to disable form, false to enable
 */
function setLoadingState(isLoading) {
    startBtn.disabled = isLoading;
    targetInput.disabled = isLoading;
    
    for (const radio of modeRadios) {
        radio.disabled = isLoading;
    }
    
    if (isLoading) {
        startBtn.textContent = 'Scanning...';
        startBtn.style.opacity = '0.6';
    } else {
        startBtn.textContent = 'Start Scanning';
        startBtn.style.opacity = '1';
    }
}

/**
 * Show progress section
 */
function showProgressSection() {
    if (progressSection) {
        progressSection.classList.remove('hidden');
    }
}

/**
 * Hide progress section
 */
function hideProgressSection() {
    if (progressSection) {
        progressSection.classList.add('hidden');
    }
    
    // Reset pause button
    if (pauseBtn) {
        pauseBtn.textContent = 'Pause';
        pauseBtn.classList.remove('resume');
    }
}

/**
 * Update progress bar and text
 * @param {number} percentage - Progress percentage (0-100)
 * @param {string} message - Optional status message
 */
function updateProgress(percentage, message = '') {
    if (progressFill) {
        progressFill.style.width = `${percentage}%`;
    }
    
    if (progressText) {
        progressText.textContent = `${Math.round(percentage)}%`;
    }
    
    console.log(`[Homepage] Progress: ${percentage}% - ${message}`);
}

/**
 * Display quick summary of results before redirect
 * @param {Object} results - Scan results from API
 */
function displayQuickSummary(results) {
    if (!results || !results.summary) return;
    
    const summary = results.summary;
    
    // Update issue count
    if (issueCount) {
        issueCount.textContent = summary.total_vulnerabilities || 0;
    }
    
    // Update overall severity
    if (overallSeverity) {
        let severity = 'Low';
        if (summary.critical > 0) {
            severity = 'Critical';
        } else if (summary.high > 0) {
            severity = 'High';
        } else if (summary.medium > 0) {
            severity = 'Medium';
        }
        
        overallSeverity.textContent = severity;
        overallSeverity.className = severity.toLowerCase() + '-text';
    }
    
    // Show results table
    if (resultsTable) {
        resultsTable.classList.remove('hidden');
    }
    
    console.log('[Homepage] Summary displayed:', summary);
}

// ==================== UTILITY FUNCTIONS ====================

/**
 * Format current date as DD.MM.YYYY
 * @returns {string} - Formatted date
 */
function formatDate() {
    const d = new Date();
    const day = String(d.getDate()).padStart(2, '0');
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const year = d.getFullYear();
    return `${day}.${month}.${year}`;
}

// ==================== ERROR RECOVERY ====================

/**
 * Handle page unload - cleanup
 */
window.addEventListener('beforeunload', () => {
    stopPolling();
});

console.log('[Homepage] Script loaded successfully');