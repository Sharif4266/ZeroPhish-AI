const API_BASE = 'https://zerophish-ai-uxyb.onrender.com';

// ── DOM refs ──────────────────────────────────────────────────────────────────
const urlInput      = document.getElementById('url-input');
const btnScan       = document.getElementById('btn-scan');
const btnClear      = document.getElementById('btn-clear');
const btnCurrentTab = document.getElementById('btn-current-tab');
const btnClearResult= document.getElementById('btn-clear-result');
const loadingWrap   = document.getElementById('loading');
const resultCard    = document.getElementById('result-card');
const errorBox      = document.getElementById('error-box');
const authAction    = document.getElementById('auth-action');
const emailSection   = document.getElementById('email-shield-section');
const emailLinksList = document.getElementById('email-links-list');
const linksContainer = document.getElementById('links-container');
const btnScanEmail   = document.getElementById('btn-scan-email');

// ── Helpers ───────────────────────────────────────────────────────────────────
function getRiskClass(result) {
  if (result === 'High Risk')   return 'high';
  if (result === 'Medium Risk') return 'medium';
  if (result === 'Low Risk')    return 'low';
  return 'safe';
}

function getVerdictClass(result) {
  if (result === 'High Risk')   return 'verdict-high';
  if (result === 'Medium Risk') return 'verdict-medium';
  if (result === 'Low Risk')    return 'verdict-low';
  return 'verdict-safe';
}

function getRiskIcon(cls) {
  const icons = {
    high:   `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    medium: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
    low:    `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
    safe:   `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`,
  };
  return icons[cls] || icons.safe;
}

function showError(msg) {
  errorBox.textContent = msg;
  errorBox.classList.add('visible');
  loadingWrap.classList.remove('visible');
  resultCard.classList.remove('visible');
  btnScan.disabled = false;
}

function hideError() {
  errorBox.classList.remove('visible');
}

function setLoading(on) {
  loadingWrap.classList.toggle('visible', on);
  btnScan.disabled = on;
  if (on) {
    resultCard.classList.remove('visible');
    hideError();
  }
}

function displayResult(data) {
  const cls = getRiskClass(data.result);
  const header = document.getElementById('result-header');
  const icon   = document.getElementById('risk-icon');
  const verdict= document.getElementById('result-verdict');
  const scoreEl= document.getElementById('score-pct');
  const barEl  = document.getElementById('score-bar');
  const detailEl=document.getElementById('result-details');
  const flagList=document.getElementById('flag-list');

  header.className = `result-header ${cls}`;
  icon.className   = `risk-icon ${cls}`;
  icon.innerHTML   = getRiskIcon(cls);
  verdict.className= `result-verdict ${getVerdictClass(data.result)}`;
  verdict.textContent = data.result;

  const score = data.risk_score ?? 0;
  scoreEl.textContent = `${score}%`;
  barEl.style.width = `${score}%`;
  barEl.className = `score-bar-fill fill-${cls}`;

  detailEl.textContent = data.details || 'No additional details.';

  flagList.innerHTML = '';
  const flags = data.heuristic_flags || [];
  flags.forEach(f => {
    const pill = document.createElement('span');
    pill.className = 'flag-pill';
    pill.textContent = f;
    flagList.appendChild(pill);
  });

  resultCard.classList.add('visible');
  setLoading(false);
}

// ── Auth Status ───────────────────────────────────────────────────────────────
function updateAuthBanner() {
  const token = null; // Extension stores token separately
  chrome.storage.local.get(['zp_token', 'zp_user'], (data) => {
    if (data.zp_token) {
      authBanner.classList.remove('logged-out');
      authBanner.classList.add('logged-in');
      authDot.classList.remove('yellow');
      authDot.classList.add('green');
      const name = data.zp_user ? JSON.parse(data.zp_user).full_name || 'User' : 'User';
      authText.innerHTML = `Logged in as <strong>${name.split(' ')[0]}</strong>`;
      authAction.textContent = 'Dashboard →';
      authAction.href = `${API_BASE}/dashboard`;
    } else {
      authBanner.classList.remove('logged-in');
      authBanner.classList.add('logged-out');
      authDot.classList.remove('green');
      authDot.classList.add('yellow');
      authText.innerHTML = `Not logged in — <strong>results won't be saved</strong>`;
      authAction.textContent = 'Login →';
      authAction.href = `${API_BASE}/login`;
    }
  });
}

// ── Scan Function ─────────────────────────────────────────────────────────────
async function doScan(url) {
  if (!url || !url.trim()) {
    showError('Please enter a URL to scan.');
    return;
  }

  // Normalise URL
  let target = url.trim();
  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    target = 'https://' + target;
  }

  setLoading(true);

  try {
    chrome.storage.local.get(['zp_token'], async (data) => {
      const token = data.zp_token;
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      let response;
      try {
        response = await fetch(`${API_BASE}/api/scan`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ content: target, scan_type: 'URL' })
        });
      } catch (networkErr) {
        showError('Cannot reach ZeroPhish AI server. Check your internet connection.');
        return;
      }

      if (!response.ok) {
        if (response.status === 401) {
          // Clear stale token
          chrome.storage.local.remove(['zp_token', 'zp_user']);
          updateAuthBanner();
          // Retry without auth
          try {
            response = await fetch(`${API_BASE}/api/scan`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ content: target, scan_type: 'URL' })
            });
          } catch (e) {
            showError('Scan failed. Please try again.');
            return;
          }
        }
        if (!response.ok) {
          const err = await response.json().catch(() => ({}));
          showError(err.detail || `Server error: ${response.status}`);
          return;
        }
      }

      const result = await response.json();
      displayResult(result);

      // Save last scan to storage
      chrome.storage.local.set({ last_scan: { url: target, result } });
    });
  } catch (e) {
    showError('Unexpected error: ' + e.message);
  }
}

// ── Event Listeners ───────────────────────────────────────────────────────────
btnScan.addEventListener('click', () => doScan(urlInput.value));

urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doScan(urlInput.value);
});

urlInput.addEventListener('input', () => {
  btnClear.classList.toggle('visible', urlInput.value.length > 0);
});

btnClear.addEventListener('click', () => {
  urlInput.value = '';
  btnClear.classList.remove('visible');
  urlInput.focus();
});

btnCurrentTab.addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) {
      urlInput.value = tabs[0].url;
      btnClear.classList.add('visible');
      doScan(tabs[0].url);
    }
  });
});

btnScanEmail.addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]) return;
    
    // Disable button during scan
    btnScanEmail.disabled = true;
    btnScanEmail.textContent = 'Scanning...';
    emailLinksList.style.display = 'block';
    linksContainer.innerHTML = '<div style="padding: 10px; text-align:center; color:#64748b;">Extracting links from email...</div>';

    chrome.tabs.sendMessage(tabs[0].id, { action: "extract_links" }, async (response) => {
      if (chrome.runtime.lastError || !response || !response.links || response.links.length === 0) {
        linksContainer.innerHTML = '<div style="padding: 10px; text-align:center; color:#64748b;">No external links found in this email.</div>';
        btnScanEmail.disabled = false;
        btnScanEmail.textContent = 'Scan Email';
        return;
      }

      linksContainer.innerHTML = '';
      const links = response.links.slice(0, 8); // Scan up to 8 links for performance
      
      for (const link of links) {
        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.alignItems = 'center';
        row.style.justifyContent = 'space-between';
        row.style.padding = '6px 0';
        row.style.borderBottom = '1px solid #334155';
        
        const linkDisplay = link.href.replace('https://', '').replace('http://', '').substring(0, 25) + '...';
        row.innerHTML = `
          <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 65%; color: #94a3b8;">${linkDisplay}</div>
          <div style="font-size: 0.6rem; color: #475569;">Analyzing...</div>
        `;
        linksContainer.appendChild(row);

        try {
          const res = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: link.href, scan_type: 'URL' })
          });
          const data = await res.json();
          const color = data.result === 'Safe' ? '#10b981' : (data.result === 'High Risk' ? '#ef4444' : '#f59e0b');
          row.lastElementChild.innerHTML = `<span style="color: ${color}; font-weight: 700; font-size: 0.65rem;">${data.result.toUpperCase()}</span>`;
        } catch (e) {
          row.lastElementChild.textContent = 'Error';
        }
      }
      
      btnScanEmail.disabled = false;
      btnScanEmail.textContent = 'Scan Again';
    });
  });
});

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  updateAuthBanner();

  // Auto-detect mail services
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) {
      const url = tabs[0].url;
      if (url.includes('mail.google.com') || url.includes('outlook.live.com') || url.includes('outlook.office.com')) {
        emailSection.style.display = 'block';
      }
      
      if (!url.startsWith('chrome://')) {
        urlInput.value = url;
        btnClear.classList.add('visible');
      }
    }
  });

  // Restore last result
  chrome.storage.local.get(['last_scan'], (data) => {
    if (data.last_scan && data.last_scan.result) {
      displayResult(data.last_scan.result);
    }
  });
});
