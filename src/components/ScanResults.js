import React from 'react';

function ScanResults({ results }) {
  if (!results) return null;

  const { target, timestamp, status, results: scanData } = results;
  const { port_scan, http_headers, ssl_info } = scanData || {};

  return (
    <div className="scan-results">
      <h2>Scan Results</h2>
      <div className="result-summary">
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Status:</strong> <span className={`status-${status}`}>{status}</span></p>
        <p><strong>Timestamp:</strong> {new Date(timestamp).toLocaleString()}</p>
      </div>

      {port_scan && (
        <div className="result-section">
          <h3>Port Scan Results</h3>
          <div className="result-content">
            {Object.entries(port_scan).map(([host, data]) => (
              <div key={host} className="host-result">
                <h4>Host: {host}</h4>
                <pre>{JSON.stringify(data, null, 2)}</pre>
              </div>
            ))}
          </div>
        </div>
      )}

      {http_headers && (
        <div className="result-section">
          <h3>HTTP Headers</h3>
          <div className="result-content">
            <h4>Status Code: {http_headers.status_code}</h4>
            <h5>Security Headers:</h5>
            <ul>
              {Object.entries(http_headers.security_headers || {}).map(([header, value]) => (
                <li key={header}>
                  <strong>{header}:</strong> {value || 'Not set'}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {ssl_info && !ssl_info.error && (
        <div className="result-section">
          <h3>SSL/TLS Information</h3>
          <div className="result-content">
            <p><strong>Version:</strong> {ssl_info.version}</p>
            <p><strong>Cipher:</strong> {ssl_info.cipher?.join(' ')}</p>
            <p><strong>Issuer:</strong> {Object.values(ssl_info.issuer || {}).join(', ')}</p>
            <p><strong>Expires:</strong> {new Date(ssl_info.expiry).toLocaleDateString()} 
              ({ssl_info.days_until_expiry} days remaining)</p>
            <p><strong>Valid:</strong> {ssl_info.is_valid ? '✅' : '❌'}</p>
          </div>
        </div>
      )}

      {status === 'failed' && (
        <div className="error">
          <h3>Error During Scan</h3>
          <p>{results.error || 'An unknown error occurred'}</p>
        </div>
      )}
    </div>
  );
}

export default ScanResults;
