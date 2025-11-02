// Simple page bootstrap
function formatDate(d){
    const dd = String(d.getDate()).padStart(2,'0');
    const mm = String(d.getMonth()+1).padStart(2,'0');
    const yyyy = d.getFullYear();
    return `${dd}.${mm}.${yyyy}`;
  }
  
  document.addEventListener('DOMContentLoaded', () => {
    // Fill date
    document.getElementById('scan-date').textContent = formatDate(new Date());
  
    // Demo data for Ports panel (matches your screenshot)
    const ports = [
      { port: 22, service: 'SSH',  status: 'Open', sev: 'Medium' },
      { port: 80, service: 'HTTP', status: 'Open', sev: 'Low'    },
    ];
    const tbody = document.getElementById('ports-body');
    tbody.innerHTML = ports.map(p => `
      <tr>
        <td>${p.port}</td>
        <td>${p.service}</td>
        <td>${p.status}</td>
        <td>${sevCell(p.sev)}</td>
      </tr>
    `).join('');
  
    // Accordions
    document.querySelectorAll('.acc-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-acc');
        const panel = document.getElementById(id);
        const open = panel.style.display === 'block';
        closeAll();
        if (!open) {
          panel.style.display = 'block';
          btn.querySelector('.chev').textContent = '▴';
        }
      });
    });
  
    function closeAll(){
      document.querySelectorAll('.acc-panel').forEach(p => p.style.display = 'none');
      document.querySelectorAll('.acc-btn .chev').forEach(c => c.textContent = '▾');
    }
  
    // Buttons
    document.getElementById('rescanBtn').addEventListener('click', () => {
      // Replace with an API call to trigger a new scan, then refresh the page with new data.
      location.reload();
    });
  
    document.getElementById('anotherScanBtn').addEventListener('click', () => {
      // Navigate back to your home page
      window.location.href = 'index.html';
    });
  
    document.getElementById('exportBtn').addEventListener('click', () => {
      // Quick export: browser print to PDF
      window.print();
    });
  });
  
  // Helpers
  function sevCell(level){
    const map = {
      'Low'   : '<span class="dot low"></span> Low',
      'Medium': '<span class="dot medium"></span> Medium',
      'High'  : '<span class="dot high"></span> High'
    };
    return map[level] || level;
  }