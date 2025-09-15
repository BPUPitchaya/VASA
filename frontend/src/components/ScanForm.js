import React, { useState } from 'react';

function ScanForm({ onScan, loading }) {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('quick');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (target.trim()) {
      onScan({
        target,
        scanType,
        timestamp: new Date().toISOString()
      });
    }
  };

  return (
    <div className="scan-form">
      <h2>New Scan</h2>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="target">Target URL or IP:</label>
          <input
            type="text"
            id="target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com or 192.168.1.1"
            required
            disabled={loading}
          />
        </div>
        
        <div className="form-group">
          <label>Scan Type:</label>
          <div className="radio-group">
            <label>
              <input
                type="radio"
                value="quick"
                checked={scanType === 'quick'}
                onChange={() => setScanType('quick')}
                disabled={loading}
              />
              Quick Scan
            </label>
            <label>
              <input
                type="radio"
                value="full"
                checked={scanType === 'full'}
                onChange={() => setScanType('full')}
                disabled={loading}
              />
              Full Scan
            </label>
          </div>
        </div>
        
        <button type="submit" disabled={loading || !target.trim()}>
          {loading ? 'Scanning...' : 'Start Scan'}
        </button>
      </form>
    </div>
  );
}

export default ScanForm;
