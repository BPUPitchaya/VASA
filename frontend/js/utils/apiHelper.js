/**
 * API Helper Module for VASA Backend Integration
 * Backend: Flask running on http://localhost:5000
 * Version: 1.0 - Debug Mode Enabled
 */

const API_CONFIG = {
  BASE_URL: 'http://localhost:5000/api',  // Keep as localhost:5000 (direct backend)
  TIMEOUT: 60000, // 60 seconds
  POLL_INTERVAL: 2000, // 2 seconds
  MAX_POLL_ATTEMPTS: 30, // Reduce to 1 minute (30 * 2s) for testing
  DEBUG: true  // Enable debug mode
};

/**
 * Debug logger
 */
function debugLog(category, message, data) {
  if (API_CONFIG.DEBUG) {
    const timestamp = new Date().toISOString();
    console.group(`🔍 [${timestamp}] ${category}`);
    console.log(message);
    if (data) {
      console.log('Data:', JSON.stringify(data, null, 2));
    }
    console.groupEnd();
  }
}

/**
 * Make API call with proper error handling
 */
async function callAPI(endpoint, options = {}) {
  const url = `${API_CONFIG.BASE_URL}${endpoint}`;
  
  debugLog('API CALL', `Making ${options.method || 'GET'} request to: ${url}`, {
    endpoint,
    method: options.method || 'GET',
    hasBody: !!options.body
  });
  
  const config = {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...options.headers
    },
    credentials: 'include',
    signal: options.signal
  };
  
  if (options.body) {
    config.body = JSON.stringify(options.body);
  }
  
  try {
    const response = await fetch(url, config);
    
    debugLog('API RESPONSE', `Response received from ${endpoint}`, {
      status: response.status,
      statusText: response.statusText,
      ok: response.ok
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      debugLog('API ERROR', 'Request failed', {
        status: response.status,
        error
      });
      throw new Error(error.error || error.message || `HTTP ${response.status}`);
    }
    
    const data = await response.json();
    debugLog('API SUCCESS', 'Response data received', data);
    
    return data;
  } catch (error) {
    debugLog('API EXCEPTION', 'Exception caught', {
      message: error.message,
      stack: error.stack
    });
    console.error('API Error:', error);
    throw error;
  }
}

/**
 * Start a vulnerability scan
 * @param {Object} scanRequest - Scan configuration
 * @returns {Promise<Object>} Scan response with scan_id
 */
async function startScan(scanRequest) {
  debugLog('START SCAN', 'Initiating scan request', scanRequest);
  
  // CRITICAL: Use correct endpoint /api/scan (NOT /api/scan/ports or /api/scan/full)
  const response = await callAPI('/scan', {
    method: 'POST',
    body: {
      target: scanRequest.target,
      mode: scanRequest.mode || 'quick', // 'quick', 'standard', 'full', or 'custom'
      authorized: scanRequest.authorized || false,
      modules: scanRequest.modules || {
        port_scan: true,
        http_headers: true,
        ssl_scan: true,
        cve_check: false
      }
    }
  });
  
  debugLog('START SCAN RESPONSE', 'Scan started successfully', {
    scanId: response.scan_id,
    fullResponse: response
  });
  
  return response;
}

/**
 * Check scan status
 * @param {string} scanId - The scan ID
 * @returns {Promise<Object>} Current scan status
 */
async function checkScanStatus(scanId) {
  debugLog('CHECK STATUS', `Checking status for scan: ${scanId}`);
  
  const response = await callAPI(`/scan/status/${scanId}`);
  
  debugLog('CHECK STATUS RESPONSE', 'Status response received', {
    scanId,
    status: response.status || response.state,
    fullResponse: response
  });
  
  return response;
}

/**
 * Poll scan status until completion
 * @param {string} scanId - The scan ID
 * @param {Function} onProgress - Callback for progress updates
 * @returns {Promise<Object>} Final scan results
 */
async function pollScanStatus(scanId, onProgress) {
  let attempts = 0;
  
  debugLog('POLLING START', `Starting to poll scan: ${scanId}`, {
    scanId,
    maxAttempts: API_CONFIG.MAX_POLL_ATTEMPTS,
    interval: API_CONFIG.POLL_INTERVAL
  });
  
  while (attempts < API_CONFIG.MAX_POLL_ATTEMPTS) {
    attempts++;
    
    try {
      debugLog('POLL ATTEMPT', `Attempt ${attempts}/${API_CONFIG.MAX_POLL_ATTEMPTS}`, {
        scanId,
        attempt: attempts
      });
      
      const status = await checkScanStatus(scanId);
      
      debugLog('POLL RESPONSE', 'Received status response', {
        fullResponse: status,
        statusField: status.status,
        stateField: status.state,
        completedField: status.completed,
        allFields: Object.keys(status)
      });
      
      // Call progress callback if provided
      if (onProgress) {
        onProgress(status);
      }
      
      // CRITICAL: Check multiple possible completion indicators
      const isCompleted = (
        status.status === 'completed' ||
        status.status === 'complete' ||
        status.state === 'completed' ||
        status.state === 'complete' ||
        status.completed === true
      );
      
      if (isCompleted) {
        debugLog('POLL SUCCESS', '✅ Scan completed successfully!', {
          attempts,
          finalStatus: status
        });
        return status;
      }
      
      // Check for failure states
      const isFailed = (
        status.status === 'failed' ||
        status.status === 'error' ||
        status.state === 'failed' ||
        status.state === 'error' ||
        status.error
      );
      
      if (isFailed) {
        debugLog('POLL ERROR', '❌ Scan failed', {
          attempts,
          errorStatus: status
        });
        throw new Error(status.error || status.message || 'Scan failed');
      }
      
      // Check if still running
      const isRunning = (
        status.status === 'running' ||
        status.status === 'in_progress' ||
        status.status === 'pending' ||
        status.status === 'queued' ||
        status.state === 'running' ||
        status.state === 'in_progress'
      );
      
      if (isRunning) {
        debugLog('POLL PROGRESS', '⏳ Scan still running...', {
          attempts,
          status: status.status || status.state,
          progress: status.progress,
          hasResults: !!status.results,
          resultsKeys: status.results ? Object.keys(status.results) : []
        });
        
        // WORKAROUND: If status stuck on "running" but has results, consider it done
        if (attempts > 10 && status.results && Object.keys(status.results).length > 0) {
          debugLog('POLL WORKAROUND', '🔧 Status stuck on "running" but has results - treating as complete', {
            attempts,
            status: status.status,
            hasResults: true
          });
          return status;
        }
      } else {
        debugLog('POLL WARNING', '⚠️ Unknown status received', {
          attempts,
          receivedStatus: status,
          thisIsAProblem: 'Status field not recognized'
        });
      }
      
      // Wait before next poll
      debugLog('POLL WAIT', `Waiting ${API_CONFIG.POLL_INTERVAL}ms before next attempt...`);
      await sleep(API_CONFIG.POLL_INTERVAL);
      
    } catch (error) {
      debugLog('POLL ERROR', '❌ Error during polling', {
        attempts,
        error: error.message,
        stack: error.stack
      });
      
      // Don't throw immediately, let it retry
      if (attempts >= API_CONFIG.MAX_POLL_ATTEMPTS) {
        throw error;
      }
      
      // Wait before retry
      await sleep(API_CONFIG.POLL_INTERVAL);
    }
  }
  
  // Max attempts reached
  debugLog('POLL TIMEOUT', '❌ Maximum polling attempts reached', {
    maxAttempts: API_CONFIG.MAX_POLL_ATTEMPTS,
    totalTime: (API_CONFIG.MAX_POLL_ATTEMPTS * API_CONFIG.POLL_INTERVAL) / 1000 + ' seconds'
  });
  
  throw new Error('Scan timeout - exceeded maximum wait time');
}

/**
 * Get scan report PDF
 * @param {string} scanId - The scan ID
 * @returns {Promise<Blob>} PDF blob
 */
async function getScanReport(scanId) {
  const response = await fetch(`${API_CONFIG.BASE_URL}/scan/${scanId}/report`, {
    credentials: 'include'
  });
  
  if (!response.ok) {
    throw new Error('Failed to download report');
  }
  
  return await response.blob();
}

/**
 * Sleep utility
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Format error message for display
 */
function formatErrorMessage(error) {
  if (error.message.includes('Failed to fetch')) {
    return 'Unable to connect to server. Please check if Backend is running.';
  }
  
  if (error.message.includes('timeout')) {
    return 'Scan took too long. Please try again.';
  }
  
  return error.message || 'An unexpected error occurred';
}

// Export functions
window.VASA_API = {
  startScan,
  checkScanStatus,
  pollScanStatus,
  getScanReport,
  formatErrorMessage,
  API_CONFIG
};

console.log('✅ VASA API Helper loaded');
