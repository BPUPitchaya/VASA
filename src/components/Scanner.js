import React, { useState } from 'react';
import axios from 'axios';
import './Scanner.css';

const Scanner = () => {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('quick');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!target) {
      setError('Please enter a target');
      return;
    }

    setIsScanning(true);
    setError('');
    setResults(null);

    try {
      const endpoint = scanType === 'full' ? '/api/scan/full' : '/api/scan/ports';
      const response = await axios.post(`http://localhost:5000${endpoint}`, 
        { target },
        {
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          withCredentials: true
        }
      );
      console.log('API Response:', response.data); // Log the full response
      
      // If the response has port_scan, use that, otherwise use the full response
      const resultData = response.data.port_scan || response.data;
      console.log('Setting results:', resultData);
      setResults(resultData);
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred during scanning');
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const renderResults = () => {
    if (!results) return null;

    if (results.error) {
      return (
        <div className="error">
          <h3>Error</h3>
          <p>{results.error}</p>
          {results.details && <pre>{JSON.stringify(results.details, null, 2)}</pre>}
        </div>
      );
    }

    // Get open ports from the results
    const openPorts = results.open_ports || [];
    const scanStats = results.scan_stats || {};

    return (
      <div className="results">
        <h3>Scan Results for {results.target || 'Unknown Target'}</h3>
        <p>Scan completed at: {new Date(results.end_time || new Date()).toLocaleString()}</p>
        
        {openPorts.length > 0 ? (
          <div className="section">
            <h4>Open Ports ({results.open_ports.length})</h4>
            <div className="port-list">
              {results.open_ports.map((port, index) => (
                <div key={index} className="port-item">
                  <span className="port-number">{port.port}</span>
                  <span className="service-name">{port.service || 'unknown'}</span>
                  <span className="protocol">{port.protocol}</span>
                  {port.details?.banner && (
                    <div className="banner">{port.details.banner}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <p>No open ports found.</p>
        )}

        <div className="scan-stats">
          <h4>Scan Statistics</h4>
          <ul>
            <li>Total ports scanned: {scanStats.total_ports || 0}</li>
            <li>Open ports: {scanStats.open_ports || 0}</li>
            <li>Closed ports: {scanStats.closed_ports || 0}</li>
            <li>Filtered ports: {scanStats.filtered_ports || 0}</li>
            <li>Error ports: {scanStats.error_ports || 0}</li>
            <li>Scan type: {results.scan_type || 'standard'}</li>
            {results.duration_seconds && (
              <li>Duration: {results.duration_seconds.toFixed(2)} seconds</li>
            )}
          </ul>
        </div>

        {results.http_scan && (
          <div className="section">
            <h4>HTTP Security</h4>
            {results.http_scan.ssl && results.http_scan.ssl.status === 'completed' && (
              <div className="ssl-info">
                <h5>SSL Certificate</h5>
                <p>Valid until: {new Date(results.http_scan.ssl.valid_until).toLocaleDateString()}</p>
                <p>Issuer: {results.http_scan.ssl.issuer}</p>
                {results.http_scan.ssl.is_self_signed && (
                  <p className="warning">⚠️ Self-signed certificate detected</p>
                )}
              </div>
            )}
            
            {results.http_scan.headers?.missing_headers?.length > 0 && (
              <div className="security-headers">
                <h5>Missing Security Headers</h5>
                <ul>
                  {results.http_scan.headers.missing_headers.map((header, index) => (
                    <li key={index}>{header}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="scanner-container">
      <h2>Vulnerability Scanner</h2>
      
      <form onSubmit={handleSubmit} className="scan-form">
        <div className="form-group">
          <label htmlFor="target">Target (IP or domain):</label>
          <input
            type="text"
            id="target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com or 192.168.1.1"
            disabled={isScanning}
          />
        </div>
        
        <div className="form-group">
          <label>Scan Type:</label>
          <div className="scan-options">
            <label>
              <input
                type="radio"
                value="quick"
                checked={scanType === 'quick'}
                onChange={() => setScanType('quick')}
                disabled={isScanning}
              />
              Quick Scan (Common ports only)
            </label>
            <label>
              <input
                type="radio"
                value="full"
                checked={scanType === 'full'}
                onChange={() => setScanType('full')}
                disabled={isScanning}
              />
              Full Scan (1000+ ports, slower)
            </label>
          </div>
        </div>

        {error && <div className="error-message">{error}</div>}

        <button type="submit" disabled={isScanning} className="scan-button">
          {isScanning ? (
            <>
              <span className="spinner"></span>
              Scanning...
            </>
          ) : (
            'Start Scan'
          )}
        </button>
      </form>

      {isScanning && (
        <div className="scanning-message">
          <p>Scanning {target}... This may take a few moments.</p>
          <p>Scan type: {scanType === 'quick' ? 'Quick Scan' : 'Full Scan'}</p>
        </div>
      )}

      {renderResults()}
    </div>
  );
};

export default Scanner;
