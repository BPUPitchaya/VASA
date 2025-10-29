/**
 * VASA API Client
 * Handles all communication with the Flask backend
 * 
 * @author VASA Team
 * @version 1.0.0
 */

const API_BASE_URL = 'http://localhost:5000';

/**
 * Helper function for fetch with comprehensive error handling
 * @param {string} url - Full URL to fetch
 * @param {Object} options - Fetch options
 * @returns {Promise<Response>} - Fetch response
 * @throws {Error} - If response is not OK or network error
 */
async function fetchWithErrorHandling(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            },
        });

        if (!response.ok) {
            // Try to parse error message from backend
            const errorData = await response.json().catch(() => ({}));
            const errorMessage = errorData.message || errorData.error || `HTTP ${response.status}: ${response.statusText}`;
            throw new Error(errorMessage);
        }

        return response;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Main API object with all endpoint methods
 */
const API = {
    /**
     * Start a new vulnerability scan
     * @param {string} target - URL or IP address to scan (e.g., "example.com" or "192.168.1.1")
     * @param {string} scanType - Type of scan: "full", "quick", "port", "ssl", "headers"
     * @returns {Promise<{scan_id: string, status: string, message: string}>}
     * @throws {Error} - If target is invalid or server error
     * 
     * @example
     * const result = await API.startScan('example.com', 'full');
     * console.log(result.scan_id); // "abc123def456"
     */
    startScan: async (target, scanType = 'full') => {
        try {
            console.log(`[API] Starting scan for target: ${target}, type: ${scanType}`);
            
            const response = await fetchWithErrorHandling(`${API_BASE_URL}/api/scan`, {
                method: 'POST',
                body: JSON.stringify({
                    target: target,
                    scan_type: scanType
                })
            });

            const data = await response.json();
            console.log('[API] Scan started successfully:', data);
            return data;
        } catch (error) {
            console.error('[API] Failed to start scan:', error);
            throw new Error(`Failed to start scan: ${error.message}`);
        }
    },

    /**
     * Get the current status of a scan
     * @param {string} scanId - The scan ID returned from startScan()
     * @returns {Promise<{scan_id: string, status: string, progress: number, current_step: string}>}
     * @throws {Error} - If scan ID not found or server error
     * 
     * @example
     * const status = await API.getScanStatus('abc123');
     * console.log(status.progress); // 75
     * console.log(status.status); // "in_progress" | "completed" | "failed"
     */
    getScanStatus: async (scanId) => {
        try {
            console.log(`[API] Fetching scan status for ID: ${scanId}`);
            
            const response = await fetchWithErrorHandling(
                `${API_BASE_URL}/api/scan/${scanId}/status`
            );

            const data = await response.json();
            console.log('[API] Scan status:', data);
            return data;
        } catch (error) {
            console.error('[API] Failed to get scan status:', error);
            throw new Error(`Failed to get scan status: ${error.message}`);
        }
    },

    /**
     * Get the complete results of a finished scan
     * @param {string} scanId - The scan ID
     * @returns {Promise<Object>} - Complete scan results including all vulnerability data
     * @throws {Error} - If scan not complete or server error
     * 
     * @example
     * const results = await API.getScanResults('abc123');
     * console.log(results.results.port_scan.open_ports); // [80, 443]
     * console.log(results.summary.total_vulnerabilities); // 8
     */
    getScanResults: async (scanId) => {
        try {
            console.log(`[API] Fetching scan results for ID: ${scanId}`);
            
            const response = await fetchWithErrorHandling(
                `${API_BASE_URL}/api/scan/${scanId}/results`
            );

            const data = await response.json();
            console.log('[API] Scan results retrieved:', data);
            return data;
        } catch (error) {
            console.error('[API] Failed to get scan results:', error);
            throw new Error(`Failed to get scan results: ${error.message}`);
        }
    },

    /**
     * Download PDF report for a scan
     * @param {string} scanId - The scan ID
     * @returns {Promise<Blob>} - PDF file as Blob (can be used to trigger download)
     * @throws {Error} - If report generation fails or server error
     * 
     * @example
     * const pdfBlob = await API.downloadReport('abc123');
     * const url = window.URL.createObjectURL(pdfBlob);
     * const a = document.createElement('a');
     * a.href = url;
     * a.download = 'scan_report.pdf';
     * a.click();
     */
    downloadReport: async (scanId) => {
        try {
            console.log(`[API] Downloading report for scan ID: ${scanId}`);
            
            const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}/report`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/pdf'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const blob = await response.blob();
            console.log('[API] Report downloaded successfully, size:', blob.size);
            return blob;
        } catch (error) {
            console.error('[API] Failed to download report:', error);
            throw new Error(`Failed to download report: ${error.message}`);
        }
    },

    /**
     * Get history of all scans
     * @returns {Promise<{scans: Array<Object>}>} - List of all scans with summary info
     * @throws {Error} - If server error
     * 
     * @example
     * const history = await API.getScanHistory();
     * history.scans.forEach(scan => {
     *   console.log(`${scan.target}: ${scan.vulnerabilities_count} issues`);
     * });
     */
    getScanHistory: async () => {
        try {
            console.log('[API] Fetching scan history');
            
            const response = await fetchWithErrorHandling(`${API_BASE_URL}/api/scans`);

            const data = await response.json();
            console.log('[API] Scan history retrieved:', data);
            return data;
        } catch (error) {
            console.error('[API] Failed to get scan history:', error);
            throw new Error(`Failed to get scan history: ${error.message}`);
        }
    }
};

/**
 * Utility function to extract URL parameters
 * @param {string} name - Parameter name
 * @returns {string|null} - Parameter value or null if not found
 * 
 * @example
 * // URL: resultpage.html?scan_id=abc123
 * const scanId = getUrlParam('scan_id'); // "abc123"
 */
function getUrlParam(name) {
    const params = new URLSearchParams(window.location.search);
    return params.get(name);
}

/**
 * Utility function to trigger file download from Blob
 * @param {Blob} blob - File blob
 * @param {string} filename - Desired filename
 * 
 * @example
 * const pdfBlob = await API.downloadReport('abc123');
 * triggerDownload(pdfBlob, 'vulnerability_report.pdf');
 */
function triggerDownload(blob, filename) {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    console.log(`[API] Download triggered: ${filename}`);
}

// Export for use in other scripts (if using modules)
// For non-module usage, API is available globally
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { API, getUrlParam, triggerDownload };
}
