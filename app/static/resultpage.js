//  Config 
const API_BASE = window.API_BASE || "/api";

//  Utilities 
function formatDate(d) {
  const dd = String(d.getDate()).padStart(2, "0");
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const yyyy = d.getFullYear();
  return `${dd}.${mm}.${yyyy}`;
}

function sevCell(level) {
  const L = String(level || "low").toLowerCase();
  if (L === "high")   return '<span class="dot high"></span> High';
  if (L === "medium") return '<span class="dot medium"></span> Medium';
  return '<span class="dot low"></span> Low';
}

function sevDot(cls, text) {
  return `<span class="dot ${cls}"></span>${text || ""}`;
}

function catSeverity(name, count) {
  if (name === "headers") {
    if (count >= 7) return "High";
    if (count >= 3) return "Medium";
    return "Low";
  }
  if (name === "ports") return count > 0 ? "Medium" : "Low";
  if (name === "ssl")   return count > 0 ? "High"   : "Low";
  if (name === "cve")   return count > 0 ? "High"   : "Low";
  return "Low";
}

async function fetchStatus(scanId) {
  const r = await fetch(`${API_BASE}/scan/status/${encodeURIComponent(scanId)}`);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

function cleanHeaderIssues(arr) {
  return (arr || [])
    .map(x => (typeof x === "string" ? x : (x.issue || x.header || String(x))))
    .filter(txt => !/^failed to connect/i.test(txt));
}

/** Flatten backend shape into what we need to render */
/** Flatten backend shape into what we need to render */
function normaliseResults(doc) {
  // Prefer the new async shape: doc.results.modules (same as homepage.js)
  const modules = (doc && doc.results && doc.results.modules) || {};

  if (Object.keys(modules).length > 0) {
    // Ports
    const portsMod = modules.port_scan || {};
    const ports    = portsMod.open_ports || portsMod.services || [];

    // HTTP headers
    const hdrRes   = (modules.http_headers && modules.http_headers.results) || {};
    const missing  = hdrRes.missing_headers || [];
    const hdrIssuesRaw = hdrRes.security_issues || [];
    const hdrIssuesTxt = cleanHeaderIssues(hdrIssuesRaw);  // turn dicts into strings

    const httpIssues = [
      // label missing headers nicely
      ...missing.map(h => `Missing ${h}`),
      ...hdrIssuesTxt
    ];

    // SSL
    const sslRes    = (modules.ssl_scan && modules.ssl_scan.results) || {};
    const sslIssues = sslRes.vulnerabilities || sslRes.issues || [];

    // CVE
    const cveRes    = modules.cve_check || {};
    const cves      = cveRes.cves_found || [];

    return {
      open_ports:          ports,
      http_headers_issues: httpIssues,
      ssl_issues:          sslIssues,
      cve_matches:         cves
    };
  }

  // Fallback for simple port only scans (old behaviour)
  const ports = doc && doc.open_ports ? doc.open_ports : [];
  return {
    open_ports:          ports,
    http_headers_issues: [],
    ssl_issues:          [],
    cve_matches:         []
  };
}

/** Get remediation advice for issues */
function getRemediationAdvice(issueType, issue) {
  const advice = {
    'port': {
      '22': 'SSH port is open. Consider disabling SSH or enforcing key-based authentication.',
      '21': 'FTP port is open. Consider using SFTP or FTPS instead for secure file transfer.',
      '23': 'Telnet port is open. Telnet is insecure - use SSH instead.',
      '25': 'SMTP port is open. Ensure proper authentication and encryption are in place.',
      '80': 'HTTP port is open. Consider redirecting to HTTPS for secure communication.',
      '443': 'HTTPS port is open. Ensure you have a valid SSL/TLS certificate installed.',
      '3389': 'RDP port is open. Restrict access to trusted IPs and enable Network Level Authentication.',
      'default': 'Ensure this port is necessary for your application. If not, close it in your firewall.'
    },
    'ssl': {
      'weak_cipher': 'Update to use strong encryption ciphers (e.g., AES with 256-bit keys)',
      'ssl2': 'Disable SSL 2.0 as it is insecure',
      'ssl3': 'Disable SSL 3.0 as it is vulnerable to POODLE attack',
      'tls1': 'Consider disabling TLS 1.0 as it is considered weak',
      'tls1_1': 'Consider disabling TLS 1.1 as it is being phased out',
      'default': 'Ensure your server uses TLS 1.2 or higher with strong ciphers'
    },
    'header': {
      'missing': (header) => `Add the ${header} header with appropriate security values`,
      'insecure': (header) => `The ${header} header has an insecure configuration. Update its value to a more secure setting.`
    }
  };

  if (issueType === 'port') {
    return advice.port[issue.port] || advice.port['default'];
  } else if (issueType === 'ssl') {
    return advice.ssl[issue] || advice.ssl['default'];
  } else if (issueType === 'header') {
    if (issue.startsWith('Missing')) {
      const header = issue.replace('Missing ', '');
      return advice.header.missing(header);
    }
    return advice.header.insecure(issue);
  }
  return 'Review the security configuration for this issue.';
}

/** Update the results display with remediation advice */
function updateResultsDisplay(flat) {
  console.log('Updating results display with data:', flat); // Debug log
  
  // Update ports table
  const portsBody = document.getElementById("ports-body");
  if (portsBody) {
    if (flat.open_ports && flat.open_ports.length > 0) {
      const rows = flat.open_ports.map(p => {
        const port = p.port || p;
        const svc = p.service || (p.details && p.details.service) || "unknown";
        const badge = sevCell(catSeverity("ports", flat.open_ports.length));
        const remediation = getRemediationAdvice('port', { port: port.toString() });
        console.log(`Port ${port} remediation:`, remediation); // Debug log
        return `
          <tr>
            <td>${port}</td>
            <td>${svc}</td>
            <td>Open</td>
            <td>${badge}</td>
            <td class="remediation">${remediation}</td>
          </tr>`;
      });
      portsBody.innerHTML = rows.join('');
    } else {
      portsBody.innerHTML = '<tr><td colspan="5">No open ports detected</td></tr>';
    }
  } else {
    console.error('Could not find ports-body element');
  }
  
  // Force a reflow to ensure styles are applied
  document.body.offsetHeight;
}

/** Roll-up severity for the KPI */
function overallSeverity(flat) {
  const hi  = (flat.cve_matches?.length || 0) + (flat.ssl_issues?.length || 0);
  const med = (flat.http_headers_issues?.length || 0) + ((flat.open_ports?.length || 0) ? 1 : 0);
  if (hi > 0)  return "High";
  if (med > 0) return "Medium";
  return "Low";
}

// -------- Boot --------
document.addEventListener("DOMContentLoaded", async () => {
  // Meta
  const scanTargetEl = document.getElementById("scan-target");
  const scanModeEl   = document.getElementById("scan-mode");
  const scanDateEl   = document.getElementById("scan-date");
  const totalIssuesEl= document.getElementById("total-issues");
  const overallSevEl = document.getElementById("overall-sev");

  scanDateEl.textContent = formatDate(new Date());

  // Accordions (collapsed by default)
  document.querySelectorAll(".acc-panel").forEach(p => (p.style.display = "none"));
  document.querySelectorAll(".acc-btn .chev").forEach(c => (c.textContent = "▾"));
  document.querySelectorAll(".acc-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-acc");
      const panel = document.getElementById(id);
  
      const isOpen = panel.style.display === "block";
  
      // toggle ONLY this panel
      if (isOpen) {
        panel.style.display = "none";
        btn.querySelector(".chev").textContent = "▾";
      } else {
        panel.style.display = "block";
        btn.querySelector(".chev").textContent = "▴";
      }
    });
  });

  // Pull scan context
  const qs     = new URLSearchParams(window.location.search);
  const scanId = qs.get("scan_id") || sessionStorage.getItem("lastScanId");
  const target = qs.get("target")  || sessionStorage.getItem("lastTarget") || "—";
  const mode   = qs.get("mode")    || sessionStorage.getItem("lastMode")   || "—";
  const date   = qs.get("date")    || sessionStorage.getItem("lastDate")   || formatDate(new Date());

  scanTargetEl.textContent = target;
  scanModeEl.textContent   = mode;
  scanDateEl.textContent   = date;

  // Early exit if no id
  if (!scanId) {
    totalIssuesEl.textContent = "0";
    overallSevEl.textContent  = "—";
    document.getElementById("ports-body").innerHTML   = '<tr><td colspan="4">No vulnerability to display.</td></tr>';
    document.getElementById("headers-list").innerHTML = "<li>No vulnerability to display.</li>";
    document.getElementById("ssl-list").innerHTML     = "<li>No vulnerability to display.</li>";
    document.getElementById("cve-list").innerHTML     = "<li>No vulnerability to display.</li>";
    document.getElementById("breakdown-body").innerHTML =
      `<tr><td>Open Port & Services</td><td>0</td><td>${sevCell("Low")}</td></tr>
       <tr><td>Insecure HTTP Headers</td><td>0</td><td>${sevCell("Low")}</td></tr>
       <tr><td>SSL/TLS Misconfigurations</td><td>0</td><td>${sevCell("Low")}</td></tr>
       <tr><td>CVE Matches</td><td>0</td><td>${sevCell("Low")}</td></tr>`;
    wireButtons(target, mode, scanId);
    return;
  }

  // Fetch & render
  try {
    const doc  = await fetchStatus(scanId);
    const flat = normaliseResults(doc);
    
    // Update the display with remediation advice
    updateResultsDisplay(flat);

    // KPIs
    const total =
      (flat.open_ports?.length || 0) +
      (flat.http_headers_issues?.length || 0) +
      (flat.ssl_issues?.length || 0) +
      (flat.cve_matches?.length || 0);

    totalIssuesEl.textContent = String(total);

    const sev = overallSeverity(flat);
    overallSevEl.textContent = sev;
    overallSevEl.className = "kpi-value " + (sev === "High" ? "sev-high" : sev === "Medium" ? "sev-medium" : "sev-low");

    // Update other panels
    const headersList = document.getElementById("headers-list");
    const sslList = document.getElementById("ssl-list");
    const cveList = document.getElementById("cve-list");
    const breakdownBody = document.getElementById("breakdown-body");

    // Headers panel
    const hdrN = flat.http_headers_issues?.length || 0;
    const hdrSev = catSeverity("headers", hdrN).toLowerCase();
    if (headersList) {
      headersList.innerHTML = (flat.http_headers_issues || [])
        .map(issue => `<li>${sevDot(hdrSev)} ${issue}</li>`)
        .join("") || "<li>No insecure headers detected</li>";
    }

    // SSL panel
    const sslN = flat.ssl_issues?.length || 0;
    const sslSev = catSeverity("ssl", sslN).toLowerCase();
    if (sslList) {
      sslList.innerHTML = (flat.ssl_issues || [])
        .map(issue => `<li>${sevDot(sslSev)} ${issue}</li>`)
        .join("") || "<li>No SSL/TLS misconfigurations detected</li>";
    }

    // CVE panel
    const cveN = flat.cve_matches?.length || 0;
    const cveSev = catSeverity("cve", cveN).toLowerCase();
    if (cveList) {
      cveList.innerHTML = (flat.cve_matches || [])
        .map(cve => `<li>${sevDot(cveSev)} ${cve}</li>`)
        .join("") || "<li>No CVE matches detected</li>";
    }

    // Breakdown table (severity per category)
    const rows = [
      ["Open Port & Services", flat.open_ports?.length || 0, catSeverity("ports", flat.open_ports?.length || 0)],
      ["Insecure HTTP Headers", hdrN, catSeverity("headers", hdrN)],
      ["SSL/TLS Misconfigurations", sslN, catSeverity("ssl", sslN)],
      ["CVE Matches", cveN, catSeverity("cve", cveN)]
    ];
    document.getElementById("breakdown-body").innerHTML =
      rows.map(([label, count, s]) => `<tr><td>${label}</td><td>${count}</td><td>${sevCell(s)}</td></tr>`).join("");

  } catch (e) {
    console.error("[resultpage] load failed:", e);
    totalIssuesEl.textContent = "0";
    overallSevEl.textContent  = "—";
    overallSevEl.className    = "kpi-value";
    document.getElementById("ports-body").innerHTML   = '<tr><td colspan="4">Failed to load results</td></tr>';
    document.getElementById("headers-list").innerHTML = "<li>Failed to load</li>";
    document.getElementById("ssl-list").innerHTML     = "<li>Failed to load</li>";
    document.getElementById("cve-list").innerHTML     = "<li>Failed to load</li>";
    document.getElementById("breakdown-body").innerHTML = '<tr><td colspan="3">Failed to load</td></tr>';
  }

  wireButtons(target, mode, scanId);
});

// -------- Buttons --------
function wireButtons(target, mode, scanId) {
  const pdfBtn = document.getElementById("pdf-report");
  if (pdfBtn) {
    pdfBtn.onclick = async () => {
      if (!scanId) {
        alert("No scan available to export. Run a scan first.");
        return;
      }

      try {
        const res = await fetch(`${API_BASE}/scan/${encodeURIComponent(scanId)}/pdf`);
        if (!res.ok) throw new Error(await res.text());

        const blob = await res.blob();
        const url  = window.URL.createObjectURL(blob);

        const a = document.createElement("a");
        a.href = url;
        a.download = `vasa_scan_${scanId}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();

        window.URL.revokeObjectURL(url);
      } catch (err) {
        console.error("PDF download failed:", err);
        alert("Failed to download PDF report.");
      }
    };
  }

  const rescanBtn = document.getElementById("rescanBtn");
  if (rescanBtn) {
    rescanBtn.onclick = () => {
      sessionStorage.setItem("autoStart", "true");
      sessionStorage.setItem("lastTarget", target || "");
      sessionStorage.setItem("lastMode", mode || "Active");
      window.location.href = "/static/homepage.html";
    };
  }

  const anotherBtn = document.getElementById("anotherScanBtn");
  if (anotherBtn) {
    anotherBtn.onclick = () => {
      window.location.href = "/static/homepage.html";
    };
  }
}