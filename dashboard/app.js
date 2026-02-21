/* ============================================================
   SENTINEL SIEM — app.js
   Vanilla JS — no build step required
   ============================================================ */

'use strict';

// ============================================================
// DATA
// ============================================================

const aiAlerts = []; // Will use liveState.aiRisks
const agents = []; // Will use liveState.agents
const vulnData = []; // Will use new liveState.vulns
const cves = []; // Will use new liveState.vulns
const activeTechniques = [];
const observedTechniques = [];

const tactics = [
  { name: 'Initial Access', techniques: ['Drive-by Compromise', 'Public-Facing App', 'External Remote Services', 'Hardware Additions', 'Phishing', 'Replication Through Removable Media', 'Valid Accounts'] },
  { name: 'Execution', techniques: ['Command and Scripting Interpreter', 'Container Administration Command', 'Deploy Container', 'Exploitation for Client Execution', 'Inter-Process Communication', 'Native API', 'Scheduled Task/Job', 'Serverless Execution', 'Shared Modules', 'Software Deployment Tools', 'System Services', 'User Execution', 'Windows Management Instrumentation'] },
  { name: 'Persistence', techniques: ['Account Manipulation', 'BITS Jobs', 'Boot or Logon Autostart Execution', 'Boot or Logon Initialization Scripts', 'Browser Extensions', 'Compromise Client Software Binary', 'Create Account', 'Create or Modify System Process', 'Event Triggered Execution', 'External Remote Services', 'Hijack Execution Flow', 'Office Application Startup', 'Pre-OS Execution', 'Scheduled Task/Job', 'Serverless Execution', 'Traffic Signaling', 'Valid Accounts'] },
  { name: 'Privilege Escalation', techniques: ['Abuse Operating System Features', 'Access Token Manipulation', 'Boot or Logon Autostart Execution', 'Boot or Logon Initialization Scripts', 'Create or Modify System Process', 'Domain Policy Modification', 'Event Triggered Execution', 'Exploitation for Privilege Escalation', 'Hijack Execution Flow', 'Process Injection', 'Scheduled Task/Job', 'Valid Accounts'] },
  { name: 'Defense Evasion', techniques: ['Abuse Operating System Features', 'Access Token Manipulation', 'BITS Jobs', 'Build Image on Host', 'Debugger Evasion', 'Deobfuscate/Decode Files or Information', 'Deploy Container', 'Direct Volume Access', 'Execution Guardrails', 'Exploitation for Defense Evasion', 'File and Directory Permissions Modification', 'Hide Artifacts', 'Hijack Execution Flow', 'Impair Defenses', 'Indicator Removal', 'Indirect Command Execution', 'Masquerading', 'Modify Cloud Compute Infrastructure', 'Modify System Image', 'Network Boundary Bridging', 'Obfuscated Files or Information', 'Plist File Modification', 'Pre-OS Execution', 'Process Injection', 'Subvert Trust Controls', 'System Binary Proxy Execution', 'System Script Proxy Execution', 'Template Injection', 'Traffic Signaling', 'Virtualization/Sandbox Evasion', 'Web Shell'] },
  { name: 'Credential Access', techniques: ['Adversary-in-the-Middle', 'Brute Force', 'Credentials from Password Stores', 'Exploitation for Credential Access', 'Forced Authentication', 'Forge Receipts', 'Input Capture', 'Modify Authentication Process', 'Multi-Factor Authentication Provider', 'Network Sniffing', 'OS Credential Dumping', 'Steal Application Access Token', 'Steal or Forge Kerberos Tickets', 'Steal Web Session Cookie', 'Unsecured Credentials'] },
  { name: 'Discovery', techniques: ['Account Discovery', 'Application Window Discovery', 'Browser Information Discovery', 'Cloud Infrastructure Discovery', 'Cloud Service Dashboard', 'Cloud Service Discovery', 'Cloud Storage Object Discovery', 'Container and Resource Discovery', 'Debugger Evasion', 'Device Driver Discovery', 'Domain Trust Discovery', 'File and Directory Discovery', 'Group Policy Discovery', 'Network Service Discovery', 'Network Share Discovery', 'Network Sniffing', 'Operating System Discovery', 'Password Policy Discovery', 'Peripheral Device Discovery', 'Permission Groups Discovery', 'Process Discovery', 'Query Registry', 'Remote System Discovery', 'Software Discovery', 'System Information Discovery', 'System Network Configuration Discovery', 'System Network Connections Discovery', 'System Owner/User Discovery', 'System Service Discovery', 'System Time Discovery', 'Virtualization/Sandbox Evasion'] },
  { name: 'Lateral Movement', techniques: ['Exploitation of Remote Services', 'Internal Spearphishing', 'Lateral Tool Transfer', 'Remote Service Session Hijacking', 'Remote Services', 'Replication Through Removable Media', 'Software Deployment Tools', 'Taint Shared Content', 'Use Alternate Authentication Material'] },
  { name: 'Collection', techniques: ['Adversary-in-the-Middle', 'Archive Collected Data', 'Audio Capture', 'Automated Collection', 'Browser Information Discovery', 'Clipboard Data', 'Data from Cloud Storage', 'Data from Information Repositories', 'Data from Local System', 'Data from Network Shared Drive', 'Data from Removable Media', 'Data Staged', 'Email Collection', 'Input Capture', 'Screen Capture', 'Video Capture'] },
  { name: 'Command and Control', techniques: ['Application Layer Protocol', 'Communication Through Removable Media', 'Data Encoding', 'Data Obfuscation', 'Dynamic Resolution', 'Encrypted Channel', 'Fallback Channels', 'Ingress Tool Transfer', 'Multi-hop Proxy', 'Non-Application Layer Protocol', 'Non-Standard Port', 'Protocol Tunneling', 'Proxy', 'Remote Access Software', 'Traffic Signaling', 'Web Service'] },
  { name: 'Exfiltration', techniques: ['Exfiltration Over Alternative Protocol', 'Exfiltration Over C2 Channel', 'Exfiltration Over Other Network Medium', 'Exfiltration Over Physical Medium', 'Scheduled Transfer', 'Transfer Data to Cloud Storage'] },
  { name: 'Impact', techniques: ['Account Access Removal', 'Data Destruction', 'Data Encrypted for Impact', 'Data Manipulation', 'Defacement', 'Disk Wipe', 'Endpoint Denial of Service', 'Firmware Corruption', 'Inhibit System Recovery', 'Network Denial of Service', 'Resource Hijacking', 'Service Stop', 'System Shutdown/Reboot'] },
];



// ============================================================
// STATE
// ============================================================
let activeTab = 'nexus';
let selectedAlertId = 1;
let hunterGaugeChart = null;
let shieldChart = null;
let sparklineChart = null;

// ============================================================
// LIVE API SERVICE
// ============================================================
const API = {
  MANAGER: '/wazuh-api',
  INDEXER: '/indexer-api',
  AI_DATA: '/data/ai_risks.json',
  MGR_USER: 'wazuh-wui',
  MGR_PASS: 'MyS3cr37P450r.*-',
  IDX_USER: 'admin',
  IDX_PASS: 'SecretPassword',
  // Key is injected server-side by nginx envsubst — never exposed to browser
  GEMINI_URL: '/gemini-api/v1beta/models/gemini-2.0-flash:generateContent',
};

let liveState = {
  mgrToken: '',
  agents: [],   // raw Wazuh agent objects
  alerts: [],   // raw Indexer hits
  aiRisks: {},   // ai_risks.json object
  mitreTechniques: [], // active technique names from live alerts
  vulns: [],    // aggregated vulnerability data
  cveStats: { critical: 0, high: 0, medium: 0, low: 0 },
};

async function apiAuth() {
  try {
    const creds = btoa(`${API.MGR_USER}:${API.MGR_PASS}`);
    const res = await fetch(`${API.MANAGER}/security/user/authenticate`, {
      method: 'POST',
      headers: { Authorization: `Basic ${creds}` },
    });
    if (res.ok) {
      const d = await res.json();
      liveState.mgrToken = d.data.token;
    }
  } catch (e) { /* manager offline — graceful fallback */ }
}

async function apiFetchAgents() {
  if (!liveState.mgrToken) return;
  try {
    const res = await fetch(`${API.MANAGER}/agents?limit=500&pretty=true`, {
      headers: { Authorization: `Bearer ${liveState.mgrToken}` },
    });
    if (!res.ok) return;
    const d = await res.json();
    liveState.agents = d.data.affected_items || [];
  } catch (e) { /* offline */ }
}

async function apiFetchAlerts() {
  try {
    const query = {
      size: 200,
      sort: [{ '@timestamp': 'desc' }],
      query: { range: { 'rule.level': { gte: 3 } } },
      aggs: {
        by_level: { terms: { field: 'rule.level', size: 20 } },
        mitre_techniques: { terms: { field: 'rule.mitre.technique', size: 50 } },
      },
    };
    const creds = btoa(`${API.IDX_USER}:${API.IDX_PASS}`);
    const res = await fetch(`${API.INDEXER}/wazuh-alerts-*/_search`, {
      method: 'POST',
      headers: { Authorization: `Basic ${creds}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(query),
    });
    if (!res.ok) return;
    const d = await res.json();
    liveState.alerts = d.hits?.hits || [];
    // Extract MITRE techniques from aggregation
    const buckets = d.aggregations?.mitre_techniques?.buckets || [];
    liveState.mitreTechniques = buckets.map(b => b.key);
  } catch (e) { /* offline */ }
}

async function apiFetchAiRisks() {
  try {
    const res = await fetch(API.AI_DATA);
    if (!res.ok) {
      console.warn('AI Engine data fetch failed:', res.status);
      return;
    }
    liveState.aiRisks = await res.json();
  } catch (e) {
    console.warn('AI Engine not ready or network error:', e);
  }
}

async function apiFetchVulnerabilities() {
  if (!liveState.mgrToken) return;
  try {
    // Fetch vulnerability summary for all agents
    const res = await fetch(`${API.MANAGER}/vulnerability/000?limit=1`, { // Check generic info first
      headers: { Authorization: `Bearer ${liveState.mgrToken}` },
    });
    // In a real deployment we'd aggregate across all agents. 
    // For now, let's fetch the last 50 vulnerabilities from ALL agents (using specific endpoint if available, else query alerts)

    // Better approach: Query wazuh-alerts for vulnerability-detector alerts
    const query = {
      size: 100,
      sort: [{ '@timestamp': 'desc' }],
      query: { term: { 'rule.groups': 'vulnerability-detector' } }
    };
    const creds = btoa(`${API.IDX_USER}:${API.IDX_PASS}`);
    const res2 = await fetch(`${API.INDEXER}/wazuh-alerts-*/_search`, {
      method: 'POST',
      headers: { Authorization: `Basic ${creds}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(query),
    });

    if (res2.ok) {
      const d = await res2.json();
      const hits = d.hits?.hits || [];
      liveState.vulns = hits.map(h => {
        const s = h._source || {};
        return {
          cve: s.data?.vulnerability?.cve || 'UNKNOWN',
          severity: s.data?.vulnerability?.severity || 'Low',
          package: s.data?.vulnerability?.package?.name || 'unknown',
          agent: s.agent?.name || '—',
          score: s.data?.vulnerability?.score || 0,
          status: 'Active'
        };
      });

      // aggregations
      let c = 0, h = 0, m = 0, l = 0;
      liveState.vulns.forEach(v => {
        const sev = v.severity.toLowerCase();
        if (sev === 'critical') c++;
        else if (sev === 'high') h++;
        else if (sev === 'medium') m++;
        else l++;
      });
      liveState.cveStats = { critical: c, high: h, medium: m, low: l };
    }
  } catch (e) { console.error(e); }
}

async function refreshLiveData() {
  await Promise.all([apiFetchAgents(), apiFetchAlerts(), apiFetchAiRisks(), apiFetchVulnerabilities()]);
  // Re-render active tab with fresh data
  const content = document.getElementById('tab-content');
  if (content) {
    renderTab(activeTab);
    content.classList.add('visible');
  }
  updateFooterStatus();
  updateTopBarEps();
}

function updateFooterStatus() {
  const footer = document.getElementById('footer');
  if (!footer) return;
  const mgrOnline = !!liveState.mgrToken;
  const idxOnline = liveState.alerts.length > 0;

  // FIX: Check status field, not just agents array
  const aiStatus = liveState.aiRisks.status;
  const aiOnline = aiStatus === 'OK' || aiStatus === 'LEARNING' || aiStatus === 'DEGRADED';

  const mgrDot = mgrOnline ? '<span class="footer-dot"></span>' : '<span class="footer-dot" style="background:#FF2E63"></span>';
  const idxDot = idxOnline ? '<span class="footer-dot"></span>' : '<span class="footer-dot" style="background:#FF2E63"></span>';
  const aiDot = aiOnline ? '<span class="footer-dot cyan"></span>' : '<span class="footer-dot" style="background:#f97316"></span>';

  footer.innerHTML = `
    <div class="footer-left">
      <div class="footer-item">${mgrDot}<span>MGR_API: ${mgrOnline ? 'ONLINE' : 'OFFLINE'}</span></div>
      <div class="footer-item">${idxDot}<span>INDEXER: ${idxOnline ? 'STREAMING' : 'OFFLINE'}</span></div>
      <div class="footer-item">${aiDot}<span>AI_ENGINE: ${aiStatus || 'OFFLINE'}</span></div>
    </div>
    <div class="footer-right">
      <span>AGENTS: ${liveState.agents.length || '—'}</span>
      <span>ALERTS: ${liveState.alerts.length || '—'}</span>
      <span class="footer-version">SENTINEL OS v4.0.2</span>
    </div>
  `;
}

function updateTopBarEps() {
  const epsEl = document.getElementById('topbar-eps-val') || document.querySelector('.topbar-eps-value');
  if (!epsEl || liveState.alerts.length === 0) return;
  // Rough EPS estimate from alert count
  epsEl.textContent = `${(liveState.alerts.length * 12).toLocaleString()} EPS`;
}

// ============================================================
// BOOT LOADER
// ============================================================
function runBootLoader() {
  const bootEl = document.getElementById('boot-loader');
  const logBox = document.getElementById('boot-log-box');
  const progressBar = document.getElementById('boot-progress-bar');
  const progressPct = document.getElementById('boot-progress-pct');

  // CLEANUP: Professional boot sequence, less "hacker" style
  const bootLogs = [
    'Initializing System Modules...',
    'Loading Security Configuration...',
    'Connecting to Data Sources...',
    'System Ready.'
  ];

  let idx = 0;
  const step = () => {
    if (idx < bootLogs.length) {
      const p = document.createElement('p');
      p.className = 'boot-log-line';
      p.innerHTML = `<span class="prompt">></span> ${bootLogs[idx]}`;
      logBox.appendChild(p);
      logBox.scrollTop = logBox.scrollHeight;
      idx++;
      const pct = Math.min(Math.round((idx / bootLogs.length) * 100), 100);
      progressBar.style.width = pct + '%';
      progressPct.textContent = pct + '%';
      setTimeout(step, 400); // Slower, more deliberate pace
    } else {
      setTimeout(() => {
        bootEl.classList.add('fade-out');
        setTimeout(() => {
          bootEl.classList.add('hidden');
          initApp();
        }, 500);
      }, 500);
    }
  };
  setTimeout(step, 200);
}

// ============================================================
// INIT APP
// ============================================================
async function initApp() {
  renderSidebar();
  renderTopBar();
  renderFooter();
  setActiveTab('nexus');

  // Launch floating AI chat panel
  setTimeout(() => initChatPanel(), 300);

  // Kick off live data (auth first, then fetch)
  await apiAuth();
  await refreshLiveData();

  // Poll every 10 seconds
  setInterval(refreshLiveData, 10000);
}


// ============================================================
// SIDEBAR
// ============================================================
const navItems = [
  { id: 'nexus', label: 'Nexus', icon: 'home' },
  { id: 'hunter', label: 'Hunter', icon: 'radar' },
  { id: 'fleet', label: 'Fleet', icon: 'server' },
  { id: 'shield', label: 'Shield', icon: 'shield' },
  { id: 'matrix', label: 'Matrix', icon: 'grid-2x2' },
];

function renderSidebar() {
  const sidebar = document.getElementById('sidebar');
  const isPurple = (id) => id === 'matrix' || id === 'hunter';

  sidebar.innerHTML = `
    <div class="sidebar-logo">S</div>
    <nav class="sidebar-nav" id="sidebar-nav"></nav>
    <div class="sidebar-bottom">
      <button class="sidebar-logout" title="Logout" onclick="handleLogout()">
        ${lucideIcon('log-out', 20)}
      </button>
    </div>
  `;

  const nav = document.getElementById('sidebar-nav');
  navItems.forEach(item => {
    const div = document.createElement('div');
    div.className = `nav-item${isPurple(item.id) ? ' purple' : ''}`;
    div.id = `nav-${item.id}`;
    div.innerHTML = `
      <div class="active-indicator"></div>
      <button class="nav-btn" title="${item.label}">
        ${lucideIcon(item.icon, 20)}
      </button>
      <div class="nav-tooltip">${item.label}</div>
    `;
    div.querySelector('.nav-btn').addEventListener('click', () => setActiveTab(item.id));
    nav.appendChild(div);
  });
}

function setActiveTab(tab) {
  activeTab = tab;

  // Update sidebar
  navItems.forEach(item => {
    const el = document.getElementById(`nav-${item.id}`);
    if (el) el.classList.toggle('active', item.id === tab);
  });

  // Update page title
  const titleEl = document.getElementById('page-title');
  if (titleEl) {
    titleEl.innerHTML = `${tab}`;
  }

  // Animate tab content out then in
  const content = document.getElementById('tab-content');
  content.classList.remove('visible');

  setTimeout(() => {
    renderTab(tab);
    content.classList.add('visible');
  }, 150);
}

// ============================================================
// TOP BAR
// ============================================================
function renderTopBar() {
  const topbar = document.getElementById('topbar');
  topbar.innerHTML = `
    <div class="topbar-brand">
      <div class="topbar-brand-dot"></div>
      <span class="topbar-brand-label">SENTINEL SIEM</span>
      <span class="topbar-brand-version">v4.0.2</span>
    </div>
    <div class="topbar-right">
      <div>
        <div class="topbar-eps-label">System Pulse</div>
        <div class="topbar-eps-value" id="topbar-eps-val">— EPS</div>
      </div>
      <canvas id="sparkline-canvas" width="96" height="40"></canvas>
      <div class="topbar-divider"></div>
      <div style="position:relative">
        <button class="topbar-bell" id="bell-btn" onclick="toggleNotifications()">
          ${lucideIcon('bell', 20)}
          <span class="topbar-bell-dot" id="bell-dot"></span>
        </button>
        <div id="notif-panel" style="display:none;position:absolute;right:0;top:calc(100% + 8px);width:320px;background:#0a0a0f;border:1px solid rgba(0,240,255,0.2);border-radius:8px;z-index:999;box-shadow:0 8px 32px rgba(0,0,0,0.6)">
          <div style="padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.07);font-size:11px;letter-spacing:1px;color:#A0A0A0">RECENT THREATS</div>
          <div id="notif-list" style="max-height:320px;overflow-y:auto"></div>
        </div>
      </div>
      <div class="topbar-user">
        <div class="topbar-avatar">${lucideIcon('user', 16)}</div>
        <div>
          <div class="topbar-user-name">Eng_Alpha_01</div>
          <div class="topbar-user-role">Level 4 Clearance</div>
        </div>
      </div>
    </div>
  `;

  // Draw sparkline
  setTimeout(() => drawSparkline(), 50);
}

function drawSparkline() {
  const canvas = document.getElementById('sparkline-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const data = Array.from({ length: 20 }, () => 800 + Math.random() * 400);
  const w = canvas.width, h = canvas.height;
  const min = Math.min(...data), max = Math.max(...data);
  const range = max - min || 1;

  ctx.clearRect(0, 0, w, h);
  ctx.beginPath();
  ctx.strokeStyle = '#00F0FF';
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';

  data.forEach((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - ((v - min) / range) * (h - 4) - 2;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
}

// ============================================================
// FOOTER
// ============================================================
function renderFooter() {
  const footer = document.getElementById('footer');
  footer.innerHTML = `
    <div class="footer-left">
      <div class="footer-item"><span class="footer-dot"></span><span>K8S_PRIMARY: ACTIVE</span></div>
      <div class="footer-item"><span class="footer-dot"></span><span>SIEM_PIPELINE: STREAMING</span></div>
      <div class="footer-item"><span class="footer-dot cyan"></span><span>AI_MODELS: v2.4.1_STABLE</span></div>
    </div>
    <div class="footer-right">
      <span>LATENCY: 12ms</span>
      <span>UPTIME: 99.999%</span>
      <span class="footer-version">SENTINEL OS v4.0.2</span>
    </div>
  `;
}

// ============================================================
// TAB ROUTER
// ============================================================
function renderTab(tab) {
  const content = document.getElementById('tab-content');
  // Destroy old charts
  if (hunterGaugeChart) { hunterGaugeChart.destroy(); hunterGaugeChart = null; }
  if (shieldChart) { shieldChart.destroy(); shieldChart = null; }

  switch (tab) {
    case 'nexus': content.innerHTML = buildNexusTab(); setTimeout(initNexusTab, 50); break;
    case 'hunter': content.innerHTML = buildHunterTab(); setTimeout(initHunterTab, 50); break;
    // Fleet: build HTML first, then run both post-DOM helpers
    case 'fleet':
      content.innerHTML = buildFleetTab();
      setTimeout(buildFleetDistribution, 50);
      break;
    case 'shield': content.innerHTML = buildShieldTab(); setTimeout(initShieldTab, 50); break;
    case 'matrix': content.innerHTML = buildMatrixTab(); break;
    default: content.innerHTML = buildNexusTab(); setTimeout(initNexusTab, 50);
  }
}

// ============================================================
// NEXUS TAB
// ============================================================
function buildNexusTab() {
  // Build real anomaly timeline: 120 one-minute buckets for the last 2 hours
  const anomalyBars = buildAnomalyBars();

  const arcs = [1, 2, 3, 4, 5].map((_, i) => {
    const left = (15 + Math.random() * 70).toFixed(1);
    const top = (15 + Math.random() * 70).toFixed(1);
    const rot = Math.floor(Math.random() * 360);
    const delay = (i * 1.2).toFixed(1);
    return `<div class="map-arc" style="left:${left}%;top:${top}%;transform:rotate(${rot}deg);animation-delay:${delay}s"></div>`;
  }).join('');


  return `
    <div class="space-y-6">
      <!-- Hero Grid -->
      <div class="nexus-grid">
        <!-- Map Card -->
        <div class="glass-card nexus-map-card">
          <div class="nexus-map-header">
            <h2 class="nexus-map-title">
              ${lucideIcon('globe', 16)} Global Ingress Monitoring
            </h2>
            <div class="nexus-active-nodes">
              <div class="ping-dot"></div>
              <span class="ping-dot-label">Active Nodes</span>
            </div>
          </div>
    <div class="nexus-map-body">
            <svg class="world" viewBox="0 0 1000 500">
              <path d="M150,150 L200,100 L300,120 L350,200 L300,300 L200,350 L100,300 Z M600,100 L700,80 L800,120 L850,250 L800,400 L700,450 L600,400 L550,250 Z M400,300 L450,250 L500,300 L450,350 Z"/>
              <circle cx="250" cy="220" r="100"/>
              <circle cx="700" cy="250" r="120"/>
              <circle cx="450" cy="400" r="60"/>
            </svg>
            
            <!-- Simplified Map Markers (Static) -->
            <div class="map-pulse-point cyan" style="top:30%;left:25%">
              <div class="dot"></div>
            </div>
            <div class="map-pulse-point crimson" style="top:45%;left:65%">
              <div class="dot"></div>
            </div>
            <div class="map-pulse-point cyan" style="top:20%;left:75%">
              <div class="dot"></div>
            </div>
            <div class="map-pulse-point purple" style="top:60%;left:40%">
              <div class="dot" style="width:6px;height:6px"></div>
            </div>
            
            <div class="map-overlay-bl" id="map-stats-overlay">
              <p>AGENTS: <span style="color:#00F0FF">${liveState.agents.length || '0'}</span></p>
              <p>ALERTS (24H): <span style="color:#FF2E63">${liveState.alerts.length || '0'}</span></p>
            </div>
            <div class="map-overlay-tr" id="map-threat-overlay" style="color:${liveState.alerts.some(h => (h._source?.rule?.level ?? 0) >= 13) ? '#FF2E63' : '#00F0FF'}">
              ${liveState.alerts.some(h => (h._source?.rule?.level ?? 0) >= 13) ? 'CRITICAL THREATS ACTIVE' : 'ALL SYSTEMS NOMINAL'}
            </div>
          </div>
        </div>

        <!-- Stats Column -->
        <div class="nexus-stats-col">
          <div class="glass-card nexus-stat-card">
            <div class="nexus-stat-header">
              <div>
                <div class="nexus-stat-label">Active Agents</div>
                <div class="nexus-stat-value">42<span class="sub">/42</span></div>
              </div>
              <div class="nexus-stat-icon emerald">${lucideIcon('globe', 20)}</div>
            </div>
            <div class="nexus-status-row">
              <div class="nexus-status-dot"></div>
              <span class="nexus-status-text">ALL SYSTEMS NOMINAL</span>
            </div>
          </div>
          <div class="glass-card nexus-stat-card">
            <div class="nexus-stat-header">
              <div>
                <div class="nexus-stat-label">Current Risk</div>
                <div class="nexus-stat-value cyan">12.4 <span class="sub">/100</span></div>
              </div>
              <div class="nexus-stat-icon cyan">${lucideIcon('shield-alert', 20)}</div>
            </div>
            <div class="nexus-risk-bar-track">
              <div class="nexus-risk-bar" id="nexus-risk-bar"></div>
            </div>
            <div class="nexus-risk-note">Low threat trajectory confirmed</div>
          </div>
        </div>
      </div>

      <!-- Anomaly Timeline -->
      <div class="glass-card anomaly-card">
        <div class="anomaly-header">
          <h2 class="anomaly-title">
            <span class="anomaly-dot"></span>
            Anomaly Horizon Timeline
          </h2>
          <div class="anomaly-legend">
            <div class="anomaly-legend-item">
              <div class="anomaly-legend-box" style="background:rgba(0,240,255,0.2)"></div>
              <span class="anomaly-legend-label">Normal</span>
            </div>
            <div class="anomaly-legend-item">
              <div class="anomaly-legend-box" style="background:#FF2E63;animation:pulse 1.5s ease-in-out infinite"></div>
              <span class="anomaly-legend-label">Threat Detected</span>
            </div>
          </div>
        </div>
        <div class="anomaly-scroll scrollbar-hide">
          <div class="anomaly-bars">${anomalyBars}</div>
        </div>
      </div>

      <!-- Activity Stream -->
      <div class="glass-card activity-card">
        <div class="activity-header">
          <h3>Recent Activity Stream</h3>
          <button class="activity-export" id="export-btn" onclick="exportLogsCSV()">EXPORT LOGS.CSV</button>
        </div>
      </div>
    </div>
  `;
}

function initNexusTab() {
  const bar = document.getElementById('nexus-risk-bar');
  // --- LIVE: use global_risk from AI engine (0–1 scale → %) ---
  const globalRisk = liveState.aiRisks.global_risk;
  if (bar) {
    const pct = globalRisk != null ? (globalRisk * 100).toFixed(1) : 12.4;
    bar.style.width = pct + '%';
    const riskNote = document.querySelector('.nexus-risk-note');
    const riskVal = document.querySelector('.nexus-stat-value.cyan');
    if (riskVal) riskVal.innerHTML = `${pct} <span class="sub">/100</span>`;
    if (riskNote) {
      const status = liveState.aiRisks.status || 'OK';
      const label = globalRisk >= 0.8 ? 'CRITICAL threat level' : globalRisk >= 0.6 ? 'HIGH risk detected' : globalRisk >= 0.4 ? 'MEDIUM risk — monitor' : 'Low threat trajectory confirmed';
      riskNote.textContent = status === 'LEARNING' ? 'AI Engine warming up — collecting baseline...' : status === 'DEGRADED' ? 'AI Engine degraded — showing last known state' : label;
    }
  }

  // --- LIVE: populate activity stream ---
  if (liveState.alerts.length > 0) {
    const streamEl = document.querySelector('.activity-card');
    if (streamEl) {
      const rows = liveState.alerts.map(hit => {
        const src = hit._source || {};
        const level = src.rule?.level ?? 0;
        const msg = src.rule?.description || 'Unknown event';
        const time = src['@timestamp'] ? new Date(src['@timestamp']).toLocaleTimeString() : '—';
        const agent = src.agent?.name || 'Manager';
        const sev = level >= 10 ? 'critical' : level >= 7 ? 'warning' : 'low';
        return `
          <div class="activity-row">
            <div class="activity-severity ${sev}"></div>
            <div style="flex:1">
              <div class="activity-msg">${msg}</div>
              <div class="activity-meta">
                <span>Source: ${agent}</span>
                <span>Time: ${time}</span>
              </div>
            </div>
            <button class="activity-inspect" onclick="showAlertDetail(arguments[0] || event, -1, this)">INSPECT</button>
          </div>`;
      }).join('');
      streamEl.innerHTML = `
        <div class="activity-header">
          <h3>Live Activity Stream</h3>
          <button class="activity-export" id="export-btn" onclick="exportLogsCSV()">EXPORT LOGS.CSV</button>
        </div>
        ${rows}`;
    }
  }

  // --- LIVE: update active agents count ---
  if (liveState.agents.length > 0) {
    const activeCount = liveState.agents.filter(a => a.status === 'active').length;
    const total = liveState.agents.length;
    const valEl = document.querySelector('.nexus-stat-value');
    if (valEl) valEl.innerHTML = `${activeCount}<span class="sub">/${total}</span>`;
    const statusEl = document.querySelector('.nexus-status-text');
    if (statusEl) statusEl.textContent = activeCount === total ? 'ALL SYSTEMS NOMINAL' : `${total - activeCount} AGENT(S) OFFLINE`;
  }
}

// ============================================================
// HUNTER TAB
// ============================================================
function buildHunterTab() {
  const agents = liveState.aiRisks.agents || [];
  const status = liveState.aiRisks.status || 'OFFLINE';

  if (agents.length === 0) {
    // FIX: Show correct status even if no agents are flagged
    const isOnline = status === 'OK' || status === 'LEARNING';
    const color = isOnline ? '#00F0FF' : '#606060';
    const iconColor = isOnline ? '#00F0FF' : '#606060';
    const message = isOnline
      ? "AI Engine is active and monitoring event streams.<br>No anomalies detected at this time."
      : "The AI Engine service appears to be offline.<br>Check container status.";

    return `
      <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:#a0a0a0;text-align:center">
        <div style="font-size:48px;margin-bottom:20px;color:${iconColor};opacity:0.8">${lucideIcon('brain', 64)}</div>
        <h2 style="color:#fff;margin-bottom:8px">AI Engine Status: <span style="color:${color}">${status}</span></h2>
        <p style="max-width:400px;line-height:1.6;color:#808080">
          ${message}
        </p>
      </div>`;
  }

  // Auto-select first if none selected, or validation check
  const selectedIdx = (typeof selectedAlertId === 'number' && selectedAlertId < agents.length) ? selectedAlertId : 0;
  selectedAlertId = selectedIdx; // Sync state
  const selected = agents[selectedIdx];

  const alertCards = agents.map((a, i) => {
    const sev = a.risk === 'CRITICAL' ? 'high' : a.risk === 'HIGH' ? 'medium' : 'low';
    const scorePct = Math.round(a.score * 100);
    return `
    <div class="glass-card hunter-alert-card ${i === selectedIdx ? 'active' : ''}"
         data-live-index="${i}" style="cursor:pointer">
      <div class="hunter-alert-top">
        <span class="hunter-score ${sev}">Score: ${scorePct}</span>
        <span class="hunter-alert-time">Live</span>
      </div>
      <div class="hunter-alert-type">${a.agent}</div>
      <div class="hunter-alert-desc">Risk: ${a.risk} — ${a.dominant_feature}</div>
    </div>`;
  }).join('');

  const scorePct = Math.round(selected.score * 100);
  const eventCount = selected.features ? Object.values(selected.features).reduce((a, b) => a + b, 0) : 0;

  return `
    <div class="hunter-grid">
      <!-- Feed -->
      <div class="hunter-feed scrollbar-hide">
        <div class="hunter-feed-title">${lucideIcon('brain', 14)} AI Analysis Feed (${status})</div>
        ${alertCards}
      </div>

      <!-- Inspector -->
      <div class="hunter-inspector scrollbar-hide">
        <div class="glass-card hunter-inspector-card">
          <div class="hunter-bg-icon">${lucideIcon('brain', 120)}</div>
          <div class="hunter-top-section">
            <!-- Gauge -->
            <div class="hunter-gauge-wrap">
              <canvas id="hunter-gauge" width="192" height="192"></canvas>
              <div class="hunter-gauge-label">
                <span class="hunter-gauge-score" id="gauge-score">${scorePct}</span>
                <span class="hunter-gauge-text">Anomaly Score</span>
              </div>
            </div>
            <!-- Details -->
            <div class="hunter-details">
              <h1 id="inspector-type">${selected.agent}</h1>
              <div class="hunter-meta-row">
                <div class="hunter-meta-box">
                  <div class="hunter-meta-box-label">Target Asset</div>
                  <div class="hunter-meta-box-value" id="inspector-target">${selected.agent}</div>
                </div>
                <div class="hunter-meta-box">
                  <div class="hunter-meta-box-label">Timestamp</div>
                  <div class="hunter-meta-box-value white" id="inspector-time">${liveState.aiRisks.timestamp || 'Just now'}</div>
                </div>
                <div class="hunter-meta-box">
                  <div class="hunter-meta-box-label">Events (Window)</div>
                  <div class="hunter-meta-box-value white" id="inspector-events">${eventCount}</div>
                </div>
              </div>
              <div class="hunter-llm-box">
                <div class="hunter-llm-icon">${lucideIcon('terminal', 16)}</div>
                <div style="flex:1">
                  <div class="hunter-llm-header">
                    <span class="hunter-llm-label">INSIGHT ENGINE</span>
                  </div>
                  <p class="hunter-llm-text">
                    <span class="hunter-cursor">_</span>
                    <span id="inspector-desc">Detected ${selected.risk} anomaly driven by <span class="highlight">${selected.dominant_feature}</span> deviation.</span>
                  </p>
                </div>
              </div>
            </div>
          </div>

          <!-- Evidence -->
          <div>
            <div class="hunter-evidence-title">${lucideIcon('search', 14)} Feature Evidence</div>
            <div class="hunter-evidence-grid">
              <div class="hunter-json-card">
                <div class="hunter-json-label">Feature Vector</div>
                <pre class="hunter-json-pre" id="inspector-raw">${JSON.stringify(selected.features, null, 2)}</pre>
              </div>
              <div class="hunter-action-card">
                <div class="hunter-action-icon">${lucideIcon('zap', 24)}</div>
                <div>
                  <div class="hunter-action-title">Recommended Action</div>
                  <div class="hunter-action-desc" id="inspector-action">
                    ${selected.risk === 'CRITICAL' ? 'Immediate isolation required.' : 'Monitor for escalation.'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

function initHunterTab() {
  const agents = liveState.aiRisks.agents || [];
  if (agents.length === 0) return;

  // Initialize Gauge Chart
  const ctx = document.getElementById('hunter-gauge');
  if (ctx && !hunterGaugeChart) {
    hunterGaugeChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Risk', 'Safe'],
        datasets: [{
          data: [0, 100], // Will update on click
          backgroundColor: ['#FF2E63', 'rgba(255,255,255,0.1)'],
          borderWidth: 0,
          cutout: '90%',
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        animation: { duration: 800 }
      }
    });
  }

  // Update chart for initial selection
  const selected = agents[selectedAlertId || 0];
  if (selected && hunterGaugeChart) {
    const sp = Math.round(selected.score * 100);
    hunterGaugeChart.data.datasets[0].data = [sp, 100 - sp];
    hunterGaugeChart.update();
  }

  // Card click listeners
  document.querySelectorAll('.hunter-alert-card').forEach(card => {
    card.addEventListener('click', () => {
      const idx = parseInt(card.dataset.liveIndex);
      if (isNaN(idx)) return;

      // Update state and re-render
      selectedAlertId = idx;
      renderTab('hunter');
      // Re-init chart after render
      setTimeout(initHunterTab, 50);
    });
  });
}

// ============================================================
// FLEET TAB
// ============================================================
function buildFleetTab() {
  const srcAgents = liveState.agents || [];

  if (srcAgents.length === 0) {
    return `
      <div class="fleet-grid">
        <div class="fleet-main">
          <div class="glass-card fleet-hive-card" style="display:flex;align-items:center;justify-content:center;flex-direction:column;gap:16px">
            <div style="font-size:48px;color:#00F0FF;opacity:0.3">${lucideIcon('server', 64)}</div>
            <h2 style="color:#e0e0e0;margin:0">No Agents Connected</h2>
            <p style="color:#606060;text-align:center;font-size:13px;max-width:320px">
              Waiting for Wazuh agents to enroll. <br>
              Ensure agents are pointing to the manager IP.
            </p>
          </div>
        </div>
        <div class="fleet-sidebar">
          <div class="glass-card fleet-dist-card" id="fleet-dist-card">
            <div class="fleet-dist-title">Fleet Distribution</div>
            <div id="fleet-dist-content"><div class="fleet-dist-item"><div class="fleet-dist-row"><span class="fleet-dist-name">No Data</span></div></div></div>
          </div>
          <div class="glass-card fleet-maint-card">
            <div class="fleet-maint-title">Maintenance Queue</div>
            ${buildMaintenanceQueue()}
          </div>
        </div>
      </div>`;
  }

  const hexes = srcAgents.map((a, i) => {
    // Wazuh returns status as 'active'/'Active'/'disconnected' etc.
    const st = (a.status || '').toLowerCase();
    const status = st === 'active' ? 'healthy'
      : st === 'disconnected' || st === 'never_connected' ? 'inactive'
        : 'inactive';

    const name = a.name || `AGT-${String(i).padStart(2, '0')}`;
    const os = a.os?.name || a.os?.platform || '—';

    const row = Math.floor(i / 7);
    const offset = row % 2 !== 0 ? 'margin-top:46px;margin-left:-4px;' : '';

    // We attach the full agent object to the DOM element dataset or just use index
    // For simplicity, we'll just pass index to showAgentModal and let it look up liveState.agents
    return `
      <div class="hex-wrap" style="${offset}">
        <div class="hex ${status}" title="${name}" onclick="showAgentModal(${i})" style="cursor:pointer">
          ${lucideIcon('activity', 12)}
          <span class="hex-num">${name.length > 8 ? name.substring(0, 6) + '..' : name}</span>
        </div>
        <div class="hex-tooltip">
          <div class="hex-tooltip-header">
            <span class="hex-tooltip-name">${name}</span>
            <span class="hex-tooltip-dot ${status}"></span>
          </div>
          <div class="hex-tooltip-row">
            <span class="hex-tooltip-key">Status</span>
            <span class="hex-tooltip-val">${status}</span>
          </div>
          <div class="hex-tooltip-row">
            <span class="hex-tooltip-key">OS</span>
            <span class="hex-tooltip-val">${os}</span>
          </div>
        </div>
      </div>
    `;
  }).join('');

  const maintItems = buildMaintenanceQueue();

  return `
    <div class="fleet-grid">
      <div class="fleet-main">
        <div class="glass-card fleet-hive-card">
          <div class="fleet-hive-header">
            <h2 class="fleet-hive-title">
              <span class="fleet-hive-title-dot"></span>
              Server Hive Fleet Status
            </h2>
            <div class="fleet-legend">
              <div class="fleet-legend-item">
                <div class="fleet-legend-box" style="background:rgba(16,185,129,0.2);border:1px solid rgba(16,185,129,0.4)"></div>
                <span class="fleet-legend-label">Healthy</span>
              </div>
              <div class="fleet-legend-item">
                <div class="fleet-legend-box" style="background:rgba(255,46,99,0.2);border:1px solid rgba(255,46,99,0.4)"></div>
                <span class="fleet-legend-label">Compromised</span>
              </div>
            </div>
          </div>
          <div class="fleet-hive-grid-wrap">
            <div class="fleet-hive-grid">${hexes}</div>
          </div>
        </div>
      </div>

      <div class="fleet-sidebar">
        <div class="glass-card fleet-dist-card" id="fleet-dist-card">
          <div class="fleet-dist-title">Fleet Distribution</div>
          <div id="fleet-dist-content"><div class="fleet-dist-item"><div class="fleet-dist-row"><span class="fleet-dist-name">Loading...</span></div></div></div>
        </div>

        <div class="glass-card fleet-maint-card">
          <div class="fleet-maint-title">Maintenance Queue</div>
          ${maintItems}
        </div>
      </div>
    </div>
  `;
}

// ── Anomaly Horizon Timeline (real per-minute buckets) ────────────────────────
function buildAnomalyBars() {
  const SLOTS = 120;
  const buckets = new Array(SLOTS).fill(0);
  const levelMap = new Array(SLOTS).fill(0);

  if (liveState.alerts.length > 0) {
    const now = Date.now();
    liveState.alerts.forEach(hit => {
      const ts = hit._source?.['@timestamp'];
      if (!ts) return;
      const age = (now - new Date(ts).getTime()) / 60000;
      const slot = SLOTS - 1 - Math.floor(age);
      if (slot >= 0 && slot < SLOTS) {
        buckets[slot]++;
        const lvl = hit._source?.rule?.level ?? 0;
        levelMap[slot] = Math.max(levelMap[slot], lvl);
      }
    });
  }

  const maxVal = Math.max(...buckets, 1);
  return buckets.map((count, i) => {
    const lvl = levelMap[i];
    const cls = lvl >= 10 ? 'anomaly' : lvl >= 7 ? 'warning' : '';
    const pct = count > 0 ? Math.max(15, Math.round((count / maxVal) * 100)) : null;
    const delay = (i * 0.02).toFixed(2);
    const style = pct
      ? `animation-delay:${delay}s;height:${pct}%;align-self:flex-end`
      : `animation-delay:${delay}s`;
    return `<div class="anomaly-bar ${cls}" style="${style}" title="${count} alert${count !== 1 ? 's' : ''} at T-${SLOTS - 1 - i}min"></div>`;
  }).join('');
}

// ── Maintenance Queue (real: disconnected agents) ─────────────────────────────
function buildMaintenanceQueue() {
  const src = liveState.agents;
  const problem = src.filter(a => a.status === 'disconnected' || a.status === 'never_connected');

  if (src.length === 0) {
    return `<div class="fleet-maint-item"><div><div class="fleet-maint-name" style="color:#A0A0A0">No live agent data</div></div></div>`;
  }
  if (problem.length === 0) {
    return `<div class="fleet-maint-item"><div><div class="fleet-maint-name" style="color:#10B981">All agents online</div><div class="fleet-maint-sub">Queue empty</div></div></div>`;
  }
  return problem.slice(0, 6).map(a => {
    const lastSeen = a.lastKeepAlive ? new Date(a.lastKeepAlive).toLocaleString() : 'Unknown';
    return `
      <div class="fleet-maint-item">
        <div class="fleet-maint-icon" style="color:#FF2E63">${lucideIcon('alert-triangle', 14)}</div>
        <div>
          <div class="fleet-maint-name">${a.name}</div>
          <div class="fleet-maint-sub">Offline &bull; Last seen: ${lastSeen}</div>
        </div>
      </div>`;
  }).join('');
}

// ── Logout ────────────────────────────────────────────────────────────────────
function handleLogout() {
  if (!confirm('Log out of SENTINEL SIEM?')) return;
  document.body.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;background:#06060a;color:#fff;font-family:sans-serif;gap:16px">
      <div style="font-size:24px;font-weight:600">SENTINEL SIEM</div>
      <div style="color:#A0A0A0;font-size:14px">You have been logged out.</div>
      <button onclick="location.reload()" style="margin-top:16px;padding:10px 24px;background:#00F0FF;border:none;border-radius:6px;color:#000;font-weight:600;cursor:pointer">Log In</button>
    </div>`;
}

// ── Bell Notifications ────────────────────────────────────────────────────────
function toggleNotifications() {
  const panel = document.getElementById('notif-panel');
  if (!panel) return;
  const isOpen = panel.style.display !== 'none';
  panel.style.display = isOpen ? 'none' : 'block';
  if (!isOpen) {
    populateNotifications();
    setTimeout(() => {
      document.addEventListener('click', function close(e) {
        if (!panel.contains(e.target) && !document.getElementById('bell-btn')?.contains(e.target)) {
          panel.style.display = 'none';
        }
        document.removeEventListener('click', close);
      });
    }, 100);
  }
}

function populateNotifications() {
  const list = document.getElementById('notif-list');
  if (!list) return;
  const high = liveState.alerts.filter(h => (h._source?.rule?.level ?? 0) >= 7).slice(0, 8);
  if (high.length === 0) {
    list.innerHTML = `<div style="padding:16px;color:#A0A0A0;font-size:12px">No high-severity alerts at this time.</div>`;
    return;
  }
  list.innerHTML = high.map(h => {
    const s = h._source || {};
    const lvl = s.rule?.level ?? 0;
    const desc = s.rule?.description || 'Unknown';
    const ag = s.agent?.name || 'Manager';
    const ts = s['@timestamp'] ? new Date(s['@timestamp']).toLocaleTimeString() : '—';
    const col = lvl >= 13 ? '#FF2E63' : lvl >= 10 ? '#f97316' : '#EAB308';
    return `<div style="padding:10px 16px;border-bottom:1px solid rgba(255,255,255,0.05);display:flex;gap:10px;align-items:flex-start">
      <div style="width:6px;height:6px;border-radius:50%;background:${col};margin-top:5px;flex-shrink:0"></div>
      <div>
        <div style="font-size:12px;color:#e0e0e0;margin-bottom:2px">${desc.substring(0, 60)}${desc.length > 60 ? '&hellip;' : ''}</div>
        <div style="font-size:11px;color:#A0A0A0">${ag} &bull; ${ts} &bull; Level ${lvl}</div>
      </div></div>`;
  }).join('');
  const dot = document.getElementById('bell-dot');
  if (dot) dot.style.display = high.length > 0 ? '' : 'none';
}

// ── Alert Inspect Bar ─────────────────────────────────────────────────────────
function showAlertDetail(e, mockIdx, btn) {
  const existing = document.getElementById('alert-detail-bar');
  if (existing) { existing.remove(); return; }

  let data = {};
  if (btn) {
    const allBtns = [...document.querySelectorAll('.activity-inspect')];
    const idx = allBtns.indexOf(btn);
    const hit = liveState.alerts[idx] || liveState.alerts[0];
    if (hit) {
      const s = hit._source || {};
      data = {
        msg: s.rule?.description || '—', agent: s.agent?.name || '—',
        time: s['@timestamp'] ? new Date(s['@timestamp']).toLocaleString() : '—',
        level: s.rule?.level ?? '—', ruleId: s.rule?.id || '—',
        srcip: s.data?.srcip || s.data?.src_ip || '—'
      };
    }
  }
  if (!data.msg) return;

  const bar = document.createElement('div');
  bar.id = 'alert-detail-bar';
  bar.style.cssText = 'position:fixed;bottom:0;left:0;right:0;background:#09090f;border-top:1px solid rgba(0,240,255,0.25);padding:14px 24px;z-index:9000;display:flex;gap:32px;align-items:center;font-size:12px;font-family:inherit;backdrop-filter:blur(12px)';
  bar.innerHTML = `
    <div style="flex:1;min-width:0">
      <div style="color:#00F0FF;font-size:10px;letter-spacing:2px;margin-bottom:4px">ALERT DETAIL</div>
      <div style="color:#e0e0e0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${data.msg}</div>
    </div>
    <div style="display:flex;gap:24px;flex-shrink:0">
      <div><div style="color:#606060;font-size:10px;margin-bottom:2px">AGENT</div><div style="color:#fff">${data.agent}</div></div>
      <div><div style="color:#606060;font-size:10px;margin-bottom:2px">RULE</div><div style="color:#fff">${data.ruleId}</div></div>
      <div><div style="color:#606060;font-size:10px;margin-bottom:2px">LEVEL</div><div style="color:#EAB308">${data.level}</div></div>
      <div><div style="color:#606060;font-size:10px;margin-bottom:2px">SRC IP</div><div style="color:#fff">${data.srcip}</div></div>
      <div><div style="color:#606060;font-size:10px;margin-bottom:2px">TIME</div><div style="color:#fff">${data.time}</div></div>
    </div>
    <button onclick="document.getElementById('alert-detail-bar').remove()" style="background:none;border:none;color:#606060;cursor:pointer;font-size:20px;padding:4px 8px;line-height:1">&times;</button>`;
  document.body.appendChild(bar);
}

// ── Agent Info Modal (Fleet hex click) ────────────────────────────────────────
function showAgentModal(agentIdx) {
  const existing = document.getElementById('agent-modal-overlay');
  if (existing) existing.remove();

  const a = liveState.agents[agentIdx];
  if (!a) return;

  // Alert count for this agent
  const alertCount = liveState.alerts.filter(h =>
    (h._source?.agent?.name || '') === a.name
  ).length;

  // AI risk from engine
  const aiEntry = (liveState.aiRisks.agents || []).find(e => e.agent === a.name);
  const riskColor = aiEntry?.risk === 'CRITICAL' ? '#FF2E63'
    : aiEntry?.risk === 'HIGH' ? '#f97316'
      : aiEntry?.risk === 'MEDIUM' ? '#EAB308' : '#10B981';

  const lastSeen = a.lastSeen && a.lastSeen !== '—'
    ? new Date(a.lastSeen).toLocaleString() : a.lastSeen;

  const overlay = document.createElement('div');
  overlay.id = 'agent-modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:8000;display:flex;align-items:center;justify-content:flex-end;backdrop-filter:blur(2px)';
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

  overlay.innerHTML = `
    <div style="width:340px;height:100%;background:#0a0a0f;border-left:1px solid rgba(0,240,255,0.2);padding:28px 24px;display:flex;flex-direction:column;gap:20px;overflow-y:auto;font-family:inherit">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div style="font-size:11px;letter-spacing:2px;color:#00F0FF">AGENT PROFILE</div>
        <button onclick="document.getElementById('agent-modal-overlay').remove()" style="background:none;border:none;color:#606060;cursor:pointer;font-size:20px;line-height:1">&times;</button>
      </div>

      <div style="display:flex;align-items:center;gap:14px">
        <div style="width:44px;height:44px;border-radius:50%;background:rgba(0,240,255,0.1);border:1px solid rgba(0,240,255,0.3);display:flex;align-items:center;justify-content:center;color:#00F0FF">${lucideIcon('server', 20)}</div>
        <div>
          <div style="font-size:16px;font-weight:600;color:#fff">${a.name}</div>
          <div style="font-size:11px;color:${a.status === 'healthy' ? '#10B981' : '#FF2E63'};letter-spacing:1px">${a.status.toUpperCase()}</div>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        ${[
      ['Wazuh ID', a.wazuhId || '—'],
      ['IP Address', a.ip || '—'],
      ['OS', a.os || '—'],
      ['Version', a.version || '—'],
      ['Alerts (live)', alertCount],
      ['Last Seen', lastSeen],
    ].map(([k, v]) => `
          <div style="background:rgba(255,255,255,0.03);border-radius:6px;padding:10px 12px">
            <div style="font-size:10px;color:#606060;margin-bottom:4px">${k}</div>
            <div style="font-size:12px;color:#e0e0e0;word-break:break-all">${v}</div>
          </div>`).join('')}
      </div>

      ${aiEntry ? `
        <div style="background:rgba(255,46,99,0.06);border:1px solid rgba(255,46,99,0.2);border-radius:8px;padding:14px">
          <div style="font-size:10px;color:#606060;margin-bottom:8px">AI RISK ASSESSMENT</div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <span style="color:${riskColor};font-weight:600;font-size:14px">${aiEntry.risk}</span>
            <span style="color:#A0A0A0;font-size:11px">Score: ${Math.round(aiEntry.score * 100)}</span>
          </div>
          <div style="font-size:11px;color:#A0A0A0">Trigger: <span style="color:#e0e0e0">${aiEntry.dominant_feature || '—'}</span></div>
          ${aiEntry.top_source_ip ? `<div style="font-size:11px;color:#A0A0A0;margin-top:4px">Top Src IP: <span style="color:#00F0FF">${aiEntry.top_source_ip}</span></div>` : ''}
        </div>` : '<div style="font-size:11px;color:#606060;text-align:center;padding:12px">No AI risk data for this agent</div>'
    }

      <div>
        <div style="font-size:10px;color:#606060;margin-bottom:8px">RECENT ALERTS</div>
        ${liveState.alerts.filter(h => (h._source?.agent?.name || '') === a.name).slice(0, 4).map(h => {
      const s = h._source || {};
      const lvl = s.rule?.level ?? 0;
      const col = lvl >= 13 ? '#FF2E63' : lvl >= 10 ? '#f97316' : lvl >= 7 ? '#EAB308' : '#10B981';
      return `<div style="padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.05);font-size:11px">
            <div style="color:#e0e0e0">${(s.rule?.description || 'Unknown').substring(0, 48)}…</div>
            <div style="color:${col};margin-top:2px">Level ${lvl}</div>
          </div>`;
    }).join('') || '<div style="font-size:11px;color:#606060">No recent alerts for this agent</div>'}
      </div>
    </div>`;

  document.body.appendChild(overlay);
}

// ── Global Search + Gemini LLM Suggestions ───────────────────────────────────
function initSearchBar() {
  const input = document.querySelector('.topbar-search');
  if (!input) return;

  let debounceTimer = null;
  const panel = createLLMPanel();

  input.addEventListener('keydown', e => {
    if (e.key === 'Escape') { closeLLMPanel(); input.value = ''; }
    if (e.key === 'Enter' && input.value.trim()) {
      e.preventDefault();
      clearTimeout(debounceTimer);
      triggerLLMSearch(input.value.trim(), panel);
    }
  });

  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    const q = input.value.trim();
    if (q.length < 2) { closeLLMPanel(); return; }
    debounceTimer = setTimeout(() => triggerLLMSearch(q, panel), 600);
  });

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') { closeLLMPanel(); input.value = ''; }
  });
}

function createLLMPanel() {
  const wrap = document.querySelector('.topbar-search-wrap');
  if (!wrap) return null;
  if (document.getElementById('llm-panel')) return document.getElementById('llm-panel');
  wrap.style.position = 'relative';
  const panel = document.createElement('div');
  panel.id = 'llm-panel';
  panel.style.cssText = 'display:none;position:absolute;top:calc(100% + 8px);left:0;right:0;background:#0b0b10;border:1px solid rgba(0,240,255,0.2);border-radius:10px;z-index:9999;box-shadow:0 12px 40px rgba(0,0,0,0.7);overflow:hidden;min-width:440px';
  wrap.appendChild(panel);
  return panel;
}

function closeLLMPanel() {
  const p = document.getElementById('llm-panel');
  if (p) p.style.display = 'none';
}

async function triggerLLMSearch(query, panel) {
  if (!panel) return;
  panel.style.display = 'block';
  panel.innerHTML = `
    <div style="padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.07);display:flex;align-items:center;justify-content:space-between">
      <span style="font-size:11px;letter-spacing:1.5px;color:#00F0FF">✦ SENTINEL LLM SUGGESTIONS</span>
      <span style="font-size:10px;color:#606060;cursor:pointer" onclick="closeLLMPanel()">ESC TO CLOSE</span>
    </div>
    <div style="padding:20px;text-align:center;color:#A0A0A0;font-size:12px">Analyzing context…</div>
    <div style="padding:10px 16px;border-top:1px solid rgba(255,255,255,0.07)">
      <span style="font-size:10px;color:#606060">PROMPT: /help for command list</span>
      <span style="float:right;font-size:10px;color:#7B61FF;background:rgba(123,97,255,0.1);padding:2px 8px;border-radius:4px">NEURAL-LINK ACTIVE</span>
    </div>`;

  const suggestions = await askGemini(query);
  renderLLMSuggestions(panel, suggestions);
}

async function askGemini(query) {
  // Build tight SIEM context
  const topAlerts = liveState.alerts.slice(0, 8).map(h => {
    const s = h._source || {};
    return `[L${s.rule?.level ?? 0}] ${s.rule?.description || '?'} on ${s.agent?.name || 'mgr'}`;
  }).join('; ') || 'No live alerts';

  const aiSummary = liveState.aiRisks.agents?.slice(0, 3).map(e =>
    `${e.agent}: ${e.risk} (${e.dominant_feature || '?'})`
  ).join(', ') || 'AI engine offline';

  const systemPrompt = `You are a concise SIEM analyst AI for SENTINEL. \nCurrent context:\n- Alerts: ${topAlerts}\n- AI risks: ${aiSummary}\n- Active agents: ${liveState.agents.length}\n\nUser query: \"${query}\"\n\nRespond with EXACTLY 4 investigation suggestions as a JSON array:\n[{\"title\":\"...\",\"category\":\"FORENSICS|THREAT HUNT|SECURITY|INVESTIGATE|AUDIT\",\"confidence\":85,\"detail\":\"one concise sentence\"}]\nKeep titles under 60 chars. No markdown, no extra text, just the JSON array.`;

  try {
    const res = await fetch('/openrouter-api/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'google/gemini-2.0-flash-001',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: query }
        ],
        temperature: 0.4,
        max_tokens: 400
      }),
    });
    if (!res.ok) throw new Error('OpenRouter API error');
    const d = await res.json();
    const text = d.choices?.[0]?.message?.content || '[]';
    // Extract JSON array from response
    const match = text.match(/\[[\s\S]*\]/);
    return match ? JSON.parse(match[0]) : [];
  } catch (err) {
    console.warn('OpenRouter error:', err);
    return [];
  }
}

// ============================================================
// AI CHAT PANEL (floating, multi-turn, SIEM-aware)
// ============================================================
let chatHistory = [];   // [{role:'user'|'model', parts:[{text}]}]
let chatOpen = false;

function initChatPanel() {
  if (document.getElementById('sentinel-chat-btn')) return;

  // Floating button
  const btn = document.createElement('button');
  btn.id = 'sentinel-chat-btn';
  btn.title = 'SENTINEL AI Chat';
  btn.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"
         fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
    </svg>
    <span class="chat-badge" id="chat-badge" style="display:none">!</span>
  `;
  btn.style.cssText = [
    'position:fixed;bottom:24px;right:24px;z-index:10000',
    'width:52px;height:52px;border-radius:50%;border:none;cursor:pointer',
    'background:linear-gradient(135deg,#00F0FF,#7B61FF)',
    'color:#000;display:flex;align-items:center;justify-content:center',
    'box-shadow:0 4px 20px rgba(0,240,255,0.4)',
    'transition:transform 0.2s,box-shadow 0.2s',
  ].join(';');
  btn.addEventListener('mouseenter', () => btn.style.transform = 'scale(1.1)');
  btn.addEventListener('mouseleave', () => btn.style.transform = 'scale(1)');
  btn.addEventListener('click', toggleChatPanel);
  document.body.appendChild(btn);

  // Chat panel
  const panel = document.createElement('div');
  panel.id = 'sentinel-chat-panel';
  panel.style.cssText = [
    'position:fixed;bottom:88px;right:24px;z-index:9999',
    'width:400px;height:540px;border-radius:14px;overflow:hidden',
    'background:#0a0a0f;border:1px solid rgba(0,240,255,0.25)',
    'box-shadow:0 20px 60px rgba(0,0,0,0.8)',
    'display:none;flex-direction:column',
    'font-family:"JetBrains Mono","Courier New",monospace',
    'transition:opacity 0.2s,transform 0.2s',
  ].join(';');
  panel.innerHTML = `
    <!-- Header -->
    <div style="display:flex;align-items:center;justify-content:space-between;
                padding:12px 16px;background:rgba(0,240,255,0.06);
                border-bottom:1px solid rgba(0,240,255,0.15);flex-shrink:0">
      <div style="display:flex;align-items:center;gap:8px">
        <div style="width:8px;height:8px;border-radius:50%;background:#00F0FF;
                    box-shadow:0 0 8px #00F0FF;animation:pulse 2s infinite"></div>
        <span style="font-size:11px;letter-spacing:1.5px;color:#00F0FF;font-weight:600">SENTINEL AI</span>
        <span style="font-size:10px;color:#606060">// NEURAL-LINK</span>
      </div>
      <div style="display:flex;gap:8px">
        <button onclick="clearChat()" title="Clear chat"
                style="background:none;border:none;color:#606060;cursor:pointer;font-size:10px;
                       letter-spacing:1px;padding:2px 6px;border-radius:4px;
                       border:1px solid rgba(255,255,255,0.06);
                       transition:color 0.2s" onmouseenter="this.style.color='#FF2E63'"
                onmouseleave="this.style.color='#606060'">CLR</button>
        <button onclick="toggleChatPanel()" title="Close"
                style="background:none;border:none;color:#606060;cursor:pointer;font-size:16px;
                       line-height:1;padding:0 2px;transition:color 0.2s"
                onmouseenter="this.style.color='#fff'"
                onmouseleave="this.style.color='#606060'">×</button>
      </div>
    </div>
    <!-- Messages -->
    <div id="chat-messages" style="flex:1;overflow-y:auto;padding:12px 14px;
         scrollbar-width:thin;scrollbar-color:rgba(0,240,255,0.2) transparent">
      <div class="chat-msg model" style="margin-bottom:12px">
        <div style="font-size:10px;color:#7B61FF;margin-bottom:4px;letter-spacing:1px">SENTINEL AI</div>
        <div style="font-size:12px;color:#C0C0C0;line-height:1.6">
          Neural link established. I have access to your live SIEM data.<br>
          Ask me about threats, alerts, anomalies, or investigation steps.
        </div>
      </div>
    </div>
    <!-- Input -->
    <div style="padding:10px 14px;border-top:1px solid rgba(255,255,255,0.07);flex-shrink:0;
               background:rgba(0,0,0,0.3)">
      <div style="display:flex;gap:8px;align-items:flex-end">
        <textarea id="chat-input" rows="1" placeholder="Ask about threats, agents, alerts..."
          style="flex:1;background:rgba(255,255,255,0.04);border:1px solid rgba(0,240,255,0.2);
                 border-radius:8px;color:#e0e0e0;font-family:inherit;font-size:12px;
                 padding:8px 12px;resize:none;outline:none;line-height:1.5;
                 max-height:80px;overflow-y:auto;
                 transition:border-color 0.2s"
          onfocus="this.style.borderColor='rgba(0,240,255,0.5)'"
          onblur="this.style.borderColor='rgba(0,240,255,0.2)'">
        </textarea>
        <button id="chat-send-btn" onclick="sendChatMessage()"
          style="width:36px;height:36px;border-radius:8px;border:none;cursor:pointer;
                 background:linear-gradient(135deg,#00F0FF,#7B61FF);
                 color:#000;display:flex;align-items:center;justify-content:center;
                 flex-shrink:0;transition:opacity 0.2s">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
               stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon
               points="22 2 15 22 11 13 2 9 22 2"/></svg>
        </button>
      </div>
      <div style="font-size:9px;color:#404040;margin-top:6px;text-align:center">
        Powered by Google AI Studio · Context-aware SIEM analysis
      </div>
    </div>
  `;
  document.body.appendChild(panel);

  // Auto-resize textarea
  const textarea = panel.querySelector('#chat-input');
  textarea.addEventListener('input', () => {
    textarea.style.height = 'auto';
    textarea.style.height = Math.min(textarea.scrollHeight, 80) + 'px';
  });
  textarea.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendChatMessage();
    }
  });
}

function toggleChatPanel() {
  const panel = document.getElementById('sentinel-chat-panel');
  if (!panel) return;
  chatOpen = !chatOpen;
  panel.style.display = chatOpen ? 'flex' : 'none';
  if (chatOpen) {
    setTimeout(() => document.getElementById('chat-input')?.focus(), 50);
    // Hide notification badge
    const badge = document.getElementById('chat-badge');
    if (badge) badge.style.display = 'none';
  }
}

function clearChat() {
  chatHistory = [];
  const msgs = document.getElementById('chat-messages');
  if (msgs) msgs.innerHTML = `
    <div class="chat-msg model" style="margin-bottom:12px">
      <div style="font-size:10px;color:#7B61FF;margin-bottom:4px;letter-spacing:1px">SENTINEL AI</div>
      <div style="font-size:12px;color:#C0C0C0;line-height:1.6">
        Chat cleared. Neural link re-established with live SIEM context.
      </div>
    </div>`;
}

async function sendChatMessage() {
  const input = document.getElementById('chat-input');
  const msgs = document.getElementById('chat-messages');
  const sendBtn = document.getElementById('chat-send-btn');
  if (!input || !msgs) return;

  const text = input.value.trim();
  if (!text) return;

  // Clear input
  input.value = '';
  input.style.height = 'auto';

  // Append user bubble
  msgs.insertAdjacentHTML('beforeend', `
    <div style="margin-bottom:12px;text-align:right">
      <div style="font-size:10px;color:#00F0FF;margin-bottom:4px;letter-spacing:1px">YOU</div>
      <div style="display:inline-block;background:rgba(0,240,255,0.08);
                  border:1px solid rgba(0,240,255,0.2);border-radius:8px;
                  padding:8px 12px;font-size:12px;color:#e0e0e0;line-height:1.6;
                  max-width:90%;text-align:left">${escapeHtml(text)}</div>
    </div>`);
  scrollChatToBottom();

  // Disable send while waiting
  if (sendBtn) sendBtn.style.opacity = '0.4';

  // Show typing indicator
  const typingId = 'typing-' + Date.now();
  msgs.insertAdjacentHTML('beforeend', `
    <div id="${typingId}" style="margin-bottom:12px">
      <div style="font-size:10px;color:#7B61FF;margin-bottom:4px;letter-spacing:1px">SENTINEL AI</div>
      <div style="display:flex;gap:4px;padding:8px 0">
        <span style="width:6px;height:6px;border-radius:50%;background:#7B61FF;
                     animation:chatDot 1.2s 0s infinite"></span>
        <span style="width:6px;height:6px;border-radius:50%;background:#7B61FF;
                     animation:chatDot 1.2s 0.2s infinite"></span>
        <span style="width:6px;height:6px;border-radius:50%;background:#7B61FF;
                     animation:chatDot 1.2s 0.4s infinite"></span>
      </div>
    </div>`);
  scrollChatToBottom();

  // Build SIEM system context
  const topAlerts = liveState.alerts.slice(0, 10).map(h => {
    const s = h._source || {};
    return `[L${s.rule?.level ?? 0}] ${s.rule?.description || '?'} — agent: ${s.agent?.name || 'mgr'}`;
  }).join('\n') || 'No live alerts';
  const aiSummary = liveState.aiRisks.agents?.slice(0, 5).map(e =>
    `${e.agent}: ${e.risk} risk (${e.dominant_feature || '?'})`
  ).join(', ') || 'AI engine offline';
  const sysCtx = `You are SENTINEL AI, an expert SIEM security analyst assistant.\nYou have real-time access to the following live data from the SENTINEL SIEM platform:\n\nLIVE ALERTS (most recent 10):\n${topAlerts}\n\nAI RISK ANALYSIS:\n${aiSummary}\n\nACTIVE AGENTS: ${liveState.agents.length}\nGLOBAL RISK SCORE: ${liveState.aiRisks.global_risk != null ? (liveState.aiRisks.global_risk * 100).toFixed(1) + '/100' : 'unknown'}\n\nProvide concise, actionable security analysis. Use plain text with clear structure. Be direct and professional.`;

  // Build conversation history (Standard OpenAI format)
  // If history is empty, prepend system context as system message
  const messages = [];
  if (chatHistory.length === 0) {
    messages.push({ role: 'system', content: sysCtx });
  } else {
    // We don't resend the system context every turn to save tokens, or we can prepend it
    // For robust context, let's prepend it as system message always
    messages.push({ role: 'system', content: sysCtx });
    // Append standard history
    messages.push(...chatHistory);
  }
  messages.push({ role: 'user', content: text });

  try {
    const res = await fetch('/openrouter-api/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'google/gemini-2.0-flash-001',
        messages: messages,
        temperature: 0.5,
        max_tokens: 800
      }),
    });

    const typing = document.getElementById(typingId);
    if (typing) typing.remove();

    if (!res.ok) {
      const errBody = await res.text();
      throw new Error(`HTTP ${res.status}: ${errBody}`);
    }

    const data = await res.json();
    const reply = data.choices?.[0]?.message?.content || '(No response)';

    // Update history
    chatHistory.push({ role: 'user', content: text });
    chatHistory.push({ role: 'assistant', content: reply }); // standard 'assistant' role

    // Keep history at most 10 turns (20 messages)
    if (chatHistory.length > 20) chatHistory = chatHistory.slice(-20);

    msgs.insertAdjacentHTML('beforeend', `
      <div style="margin-bottom:12px">
        <div style="font-size:10px;color:#7B61FF;margin-bottom:4px;letter-spacing:1px">SENTINEL AI</div>
        <div style="font-size:12px;color:#C0C0C0;line-height:1.7;white-space:pre-wrap;
                    word-break:break-word">${formatChatReply(reply)}</div>
      </div>`);

  } catch (err) {
    const typing = document.getElementById(typingId);
    if (typing) typing.remove();
    console.error('Chat error:', err);
    const isProxy = err.message.includes('Failed to fetch') || err.message.includes('NetworkError');
    msgs.insertAdjacentHTML('beforeend', `
      <div style="margin-bottom:12px">
        <div style="font-size:10px;color:#FF2E63;margin-bottom:4px;letter-spacing:1px">NEURAL LINK ERROR</div>
        <div style="font-size:12px;color:#FF6B6B;line-height:1.7">
          ${isProxy
        ? 'Cannot reach the AI proxy. Run: <code style="background:rgba(255,255,255,0.06);padding:2px 6px;border-radius:4px;color:#00F0FF">docker compose down && docker compose up -d</code>'
        : escapeHtml(err.message)}
        </div>
      </div>`);
  }

  if (sendBtn) sendBtn.style.opacity = '1';
  scrollChatToBottom();
}

function scrollChatToBottom() {
  const msgs = document.getElementById('chat-messages');
  if (msgs) msgs.scrollTop = msgs.scrollHeight;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatChatReply(text) {
  // Basic markdown-like formatting: **bold**, `code`, bullet points
  return escapeHtml(text)
    .replace(/\*\*(.+?)\*\*/g, '<strong style="color:#e0e0e0">$1</strong>')
    .replace(/`([^`]+)`/g, '<code style="background:rgba(0,240,255,0.07);padding:1px 4px;border-radius:3px;color:#00F0FF">$1</code>')
    .replace(/^(\s*[-•]\s+)/gm, '<span style="color:#7B61FF">▸ </span>')
    .replace(/^(\s*\d+\.\s+)/gm, '<span style="color:#7B61FF">$1</span>');
}

const categoryIcons = {
  'FORENSICS': 'brain', 'THREAT HUNT': 'zap', 'SECURITY': 'shield',
  'INVESTIGATE': 'search', 'AUDIT': 'terminal', 'DEFAULT': 'activity',
};
const categoryColors = {
  'FORENSICS': '#00F0FF', 'THREAT HUNT': '#FF2E63', 'SECURITY': '#7B61FF',
  'INVESTIGATE': '#EAB308', 'AUDIT': '#10B981', 'DEFAULT': '#A0A0A0',
};

function renderLLMSuggestions(panel, suggestions) {
  if (!panel) return;
  const header = panel.children[0]?.outerHTML || '';
  const footer = panel.children[panel.children.length - 1]?.outerHTML || '';

  const cards = suggestions.length > 0 ? suggestions.map(s => {
    const cat = (s.category || 'DEFAULT').toUpperCase();
    const icon = categoryIcons[cat] || categoryIcons.DEFAULT;
    const col = categoryColors[cat] || categoryColors.DEFAULT;
    return `
      <div style="display:flex;gap:14px;align-items:flex-start;padding:14px 16px;border-bottom:1px solid rgba(255,255,255,0.05);cursor:pointer;transition:background 0.15s" onmouseenter="this.style.background='rgba(255,255,255,0.03)'" onmouseleave="this.style.background='transparent'">
        <div style="width:36px;height:36px;border-radius:8px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);display:flex;align-items:center;justify-content:center;color:${col};flex-shrink:0">${lucideIcon(icon, 16)}</div>
        <div style="flex:1;min-width:0">
          <div style="font-size:13px;color:#e0e0e0;margin-bottom:4px;font-weight:500">${s.title}</div>
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:4px">
            <span style="font-size:10px;color:#606060;letter-spacing:1px">CATEGORY: <span style="color:${col}">${cat}</span></span>
            <span style="font-size:10px;color:#606060">CONFIDENCE: <span style="color:#10B981">${s.confidence}%</span></span>
          </div>
          ${s.detail ? `<div style="font-size:11px;color:#808080">${s.detail}</div>` : ''}
        </div>
      </div>`;
  }).join('') : `<div style="padding:20px;text-align:center;color:#606060;font-size:12px">No suggestions — try a more specific query</div>`;

  panel.innerHTML = `
    ${header}
    ${cards}
    ${footer}`;
}

// ── Fleet Distribution (real from Wazuh agent OS data) ────────────────────────
function buildFleetDistribution() {
  const el = document.getElementById('fleet-dist-content');
  if (!el) return;

  const source = liveState.agents.length > 0 ? liveState.agents : agents;
  const counts = {};
  source.forEach(a => {
    const name = (liveState.agents.length > 0)
      ? (a.os?.name || a.os?.platform || 'Unknown')
      : (a.os || 'Unknown');
    const key = name.includes('Windows') ? 'Windows' :
      name.includes('Linux') ? 'Linux' :
        name.includes('Darwin') ? 'macOS' : name;
    counts[key] = (counts[key] || 0) + 1;
  });

  const total = Object.values(counts).reduce((s, v) => s + v, 0) || 1;
  const palette = ['cyan', 'purple', 'green', 'orange'];
  let html = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([os, n], i) => {
      const pct = Math.round((n / total) * 100);
      const col = palette[i % palette.length];
      return `
        <div class="fleet-dist-item">
          <div class="fleet-dist-row">
            <span class="fleet-dist-name">${os} Nodes</span>
            <span class="fleet-dist-count ${col}">${n}</span>
          </div>
          <div class="fleet-dist-track">
            <div class="fleet-dist-bar ${col}" style="width:${pct}%"></div>
          </div>
        </div>`;
    }).join('');

  if (!html) html = '<div class="fleet-dist-item"><div class="fleet-dist-row"><span class="fleet-dist-name">No agents detected</span></div></div>';
  el.innerHTML = html;
}

// ── MITRE Alert Banner (dynamic) ──────────────────────────────────────────────
function buildMitreAlertBanner() {
  const live = activeTechniques.filter(t =>
    liveState.mitreTechniques.includes(t)
  );
  const hasThreat = live.length > 0;

  const desc = hasThreat
    ? `Sentinel detected <strong>${live.length}</strong> active technique(s) correlated from live Wazuh events: ${live.slice(0, 5).map(t => `<span class="highlight">${t}</span>`).join(', ')}.`
    : `No confirmed active tactic chains from live events. Static baseline techniques (<span class="highlight">Brute Force</span>, <span class="highlight">Valid Accounts</span>) remain in watchlist.`;

  const title = hasThreat ? 'Active Tactic Chain Detected' : 'No Live Tactic Chain';
  const icon = hasThreat ? 'shield-alert' : 'shield';

  return `
    <div class="glass-card matrix-alert-card">
      <div class="matrix-alert-inner">
        <div class="matrix-alert-icon">${lucideIcon(icon, 24)}</div>
        <div>
          <div class="matrix-alert-title">${title}</div>
          <p class="matrix-alert-desc">${desc}</p>
          <div class="matrix-alert-actions">
            <button class="matrix-btn-secondary">VIEW FULL ATTACK PATH</button>
          </div>
        </div>
      </div>
    </div>`;
}

// ── Export CSV (real data) ────────────────────────────────────────────────────
function exportLogsCSV() {
  const rows = [['Timestamp', 'Agent', 'Rule ID', 'Level', 'Severity', 'Description']];

  const alerts = liveState.alerts;
  if (alerts.length > 0) {
    alerts.forEach(hit => {
      const src = hit._source || {};
      const ts = src['@timestamp'] || '';
      const agent = src.agent?.name || 'Manager';
      const ruleId = src.rule?.id || '';
      const level = src.rule?.level ?? '';
      const sev = level >= 13 ? 'Critical' : level >= 10 ? 'High' : level >= 7 ? 'Medium' : 'Low';
      const desc = (src.rule?.description || '').replace(/"/g, '""');
      rows.push([ts, agent, ruleId, level, sev, `"${desc}"`]);
    });
  } else {
    rows.push(['No live data — connect to Wazuh for real logs.', '', '', '', '', '']);
  }

  const csv = rows.map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sentinel-logs-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ============================================================
// SHIELD TAB
// ============================================================
function buildShieldTab() {
  // Use live vulnerability data if available, else empty state
  const cveRows = (liveState.vulns.length > 0 ? liveState.vulns : []).map(cve => `
    <tr>
      <td class="cve-id">${cve.cve}</td>
      <td class="cve-pkg">${cve.package}</td>
      <td><span class="cve-severity-badge ${cve.severity.toLowerCase()}">${cve.severity}</span></td>
      <td class="cve-score">${cve.score}</td>
      <td class="cve-status">${cve.status}</td>
      <td class="cve-action"><button class="cve-patch-btn">INSPECT</button></td>
    </tr>
  `).join('') || '<tr><td colspan="6" style="text-align:center;padding:20px;color:#606060">No vulnerabilities detected (or connect to Wazuh)</td></tr>';

  const stats = liveState.cveStats;
  const legendData = [
    { name: 'Critical', value: stats.critical, color: '#FF2E63' },
    { name: 'High', value: stats.high, color: '#F97316' },
    { name: 'Medium', value: stats.medium, color: '#EAB308' },
    { name: 'Low', value: stats.low, color: '#00F0FF' },
  ];

  const legendItems = legendData.map(v => `
    <div class="shield-legend-item">
      <div class="shield-legend-dot" style="background:${v.color}"></div>
      <span class="shield-legend-label">${v.name}: ${v.value}</span>
    </div>
  `).join('');

  return `
    <div class="space-y-6">
      <div class="shield-top-grid">
        <!-- Vuln Chart -->
        <div class="glass-card shield-vuln-card">
          <div class="shield-vuln-header">
            <h2 class="shield-vuln-title">
              ${lucideIcon('shield-alert', 20)} Vulnerability Landscape
            </h2>
          </div>
          <div class="shield-chart-area">
            <canvas id="shield-chart" width="280" height="280"></canvas>
            <div class="shield-legend">${legendItems}</div>
          </div>
        </div>

        <!-- Right column -->
        <div class="shield-right-col">
          <div class="glass-card shield-compliance-card">
            <div class="shield-compliance-title">Posture Indicators</div>
            <div class="shield-compliance-score" id="posture-score">—</div>
            <div class="shield-compliance-label">Alert-Based Risk Score</div>
            <div class="shield-compliance-row">
              <span class="shield-compliance-key">Critical Alerts</span>
              <span class="shield-compliance-val" id="posture-critical" style="color:#FF2E63">—</span>
            </div>
            <div class="shield-compliance-row">
              <span class="shield-compliance-key">High Alerts</span>
              <span class="shield-compliance-val" id="posture-high" style="color:#f97316">—</span>
            </div>
            <div class="shield-compliance-row">
              <span class="shield-compliance-key">AI Risk Level</span>
              <span class="shield-compliance-val" id="posture-ai">—</span>
            </div>
          </div>
          <div class="glass-card shield-reco-card">
            <div class="shield-reco-title">Hardening Recommendations</div>
            <div class="shield-reco-item">
              <div class="shield-reco-icon" style="color:#7B61FF">${lucideIcon('terminal', 14)}</div>
              <p class="shield-reco-text">Disable root SSH login on all nodes in <span class="highlight">PROD-ZONE-B</span>.</p>
            </div>
            <div class="shield-reco-item">
              <div class="shield-reco-icon" style="color:#f97316">${lucideIcon('alert-triangle', 14)}</div>
              <p class="shield-reco-text">Review open ports on <span class="highlight">K8S-LB</span>.</p>
            </div>
          </div>
        </div>
      </div>

      <!-- CVE Table -->
      <div class="glass-card shield-cve-card">
        <div class="shield-cve-header">
          <h3>Top Critical CVEs</h3>
          <div class="shield-live-badge">
            <div class="shield-live-dot"></div>
            <span class="shield-live-label">Live Feed</span>
          </div>
        </div>
        <div style="overflow-x:auto">
          <table class="cve-table">
            <thead>
              <tr>
                <th>CVE ID</th><th>Impacted Package</th><th>Severity</th>
                <th>CVSS Score</th><th>Status</th><th>Action</th>
              </tr>
            </thead>
            <tbody>${cveRows}</tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function initShieldTab() {
  // --- LIVE: compute vuln counts from alert levels ---
  if (liveState.alerts.length > 0) {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    liveState.alerts.forEach(hit => {
      const lvl = hit._source?.rule?.level ?? 0;
      if (lvl >= 13) counts.Critical++;
      else if (lvl >= 10) counts.High++;
      else if (lvl >= 7) counts.Medium++;
      else counts.Low++;
    });
    // --- Update CVE stats already fetched ---
    // no-op here since liveState.cveStats is used directly in buildShieldTab()
    // but we can update the posture scores:

    // Update CVE table with live alert descriptions
    const tbody = document.querySelector('.cve-table tbody');
    if (tbody && liveState.alerts.length > 0) {
      const liveRows = liveState.alerts.slice(0, 5).map(hit => {
        const src = hit._source || {};
        const lvl = src.rule?.level ?? 0;
        const desc = src.rule?.description || 'Unknown';
        const agent = src.agent?.name || 'Manager';
        const sev = lvl >= 13 ? 'Critical' : lvl >= 10 ? 'High' : lvl >= 7 ? 'Medium' : 'Low';
        const ruleId = src.rule?.id || '—';
        return `<tr>
          <td class="cve-id">RULE-${ruleId}</td>
          <td class="cve-pkg">${agent}</td>
          <td><span class="cve-severity-badge ${sev.toLowerCase()}">${sev}</span></td>
          <td class="cve-score">${lvl}</td>
          <td class="cve-status">${desc.substring(0, 40)}${desc.length > 40 ? '…' : ''}</td>
          <td class="cve-action"><button class="cve-patch-btn">INSPECT</button></td>
        </tr>`;
      }).join('');
      tbody.innerHTML = liveRows;
    }

    // --- LIVE: populate Posture Indicators card ---
    const critEl = document.getElementById('posture-critical');
    const highEl = document.getElementById('posture-high');
    const scoreEl = document.getElementById('posture-score');
    const aiEl = document.getElementById('posture-ai');
    if (critEl) critEl.textContent = counts.Critical;
    if (highEl) highEl.textContent = counts.High;
    const totalAlerts = liveState.alerts.length || 1;
    const riskPct = Math.min(100, Math.round(((counts.Critical * 3 + counts.High * 2) / totalAlerts) * 50));
    if (scoreEl) scoreEl.textContent = riskPct + '%';
    const aiRisk = liveState.aiRisks?.global_risk;
    if (aiEl) aiEl.textContent = aiRisk != null ? liveState.aiRisks.agents?.[0]?.risk || '—' : '—';
  }

  const canvas = document.getElementById('shield-chart');
  if (!canvas) return;
  if (shieldChart) shieldChart.destroy();

  shieldChart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [liveState.cveStats.critical, liveState.cveStats.high, liveState.cveStats.medium, liveState.cveStats.low],
        backgroundColor: ['#FF2E63', '#F97316', '#EAB308', '#00F0FF'],
        borderWidth: 0,
        hoverOffset: 8,
      }]
    },
    options: {
      cutout: '55%',
      animation: { duration: 800 },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed}`
          },
          backgroundColor: '#121212',
          borderColor: 'rgba(255,255,255,0.1)',
          borderWidth: 1,
          titleColor: '#fff',
          bodyColor: '#A0A0A0',
        }
      }
    }
  });
}

// ============================================================
// MATRIX TAB → THREAT INTELLIGENCE HUB
// ============================================================
function buildMatrixTab() {
  // --- Merge live MITRE techniques ---
  if (liveState.mitreTechniques.length > 0) {
    liveState.mitreTechniques.forEach(t => {
      if (!activeTechniques.includes(t)) activeTechniques.push(t);
    });
  }

  // --- Tactic coverage cards ---
  const tacticCards = tactics.map(tactic => {
    const active = tactic.techniques.filter(t => activeTechniques.includes(t)).length;
    const observed = tactic.techniques.filter(t => observedTechniques.includes(t) && !activeTechniques.includes(t)).length;
    const clean = tactic.techniques.length - active - observed;
    const hasThreat = active > 0;
    const borderCol = hasThreat ? 'rgba(255,46,99,0.35)' : observed > 0 ? 'rgba(123,97,255,0.3)' : 'rgba(255,255,255,0.06)';
    const dotCol = hasThreat ? '#FF2E63' : observed > 0 ? '#7B61FF' : '#10B981';
    const pct = Math.round((active / Math.max(tactic.techniques.length, 1)) * 100);
    return `
      <div class="glass-card" style="padding:14px 16px;border:1px solid ${borderCol};position:relative;overflow:hidden">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">
          <div>
            <div style="font-size:11px;font-weight:600;color:#e0e0e0;margin-bottom:2px">${tactic.name}</div>
            <div style="font-size:10px;color:#606060">${tactic.techniques.length} techniques</div>
          </div>
          <div style="width:8px;height:8px;border-radius:50%;background:${dotCol};margin-top:2px;${hasThreat ? 'box-shadow:0 0 6px ' + dotCol : ''}"></div>
        </div>
        <div style="display:flex;gap:8px;font-size:10px;margin-bottom:8px">
          <span style="color:#FF2E63">${active} active</span>
          <span style="color:#7B61FF">${observed} observed</span>
          <span style="color:#606060">${clean} clean</span>
        </div>
        <div style="height:3px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden">
          <div style="height:100%;width:${pct}%;background:${hasThreat ? '#FF2E63' : '#7B61FF'};border-radius:2px;transition:width 0.4s"></div>
        </div>
        <div style="position:absolute;bottom:0;right:0;font-size:48px;font-weight:700;color:rgba(255,255,255,0.02);line-height:1;pointer-events:none">${pct}</div>
      </div>`;
  }).join('');

  // --- Top Fired Rules from live alerts ---
  const ruleCounts = {};
  liveState.alerts.forEach(h => {
    const s = h._source || {};
    const id = s.rule?.id || '?';
    const desc = s.rule?.description || 'Unknown';
    const lvl = s.rule?.level ?? 0;
    const key = id;
    if (!ruleCounts[key]) ruleCounts[key] = { id, desc, lvl, count: 0, agents: new Set() };
    ruleCounts[key].count++;
    ruleCounts[key].agents.add(s.agent?.name || 'mgr');
  });
  const topRules = Object.values(ruleCounts)
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  const ruleRows = topRules.length > 0 ? topRules.map(r => {
    const col = r.lvl >= 13 ? '#FF2E63' : r.lvl >= 10 ? '#f97316' : r.lvl >= 7 ? '#EAB308' : '#10B981';
    return `
      <tr>
        <td style="padding:8px 12px;color:#606060;font-size:11px">${r.id}</td>
        <td style="padding:8px 12px;color:#e0e0e0;font-size:12px;max-width:280px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${r.desc}</td>
        <td style="padding:8px 12px;text-align:center"><span style="color:${col};font-weight:600;font-size:12px">${r.lvl}</span></td>
        <td style="padding:8px 12px;color:#00F0FF;font-size:12px;font-weight:600">${r.count}</td>
        <td style="padding:8px 12px;color:#A0A0A0;font-size:11px">${[...r.agents].slice(0, 2).join(', ')}${r.agents.size > 2 ? ` +${r.agents.size - 2}` : ''}</td>
      </tr>`;
  }).join('') : `<tr><td colspan="5" style="padding:20px;text-align:center;color:#606060;font-size:12px">No live alert data — connect to Wazuh Indexer</td></tr>`;

  // --- Threat actor summary from AI engine ---
  const aiAgents = liveState.aiRisks.agents || [];
  const critCountAI = aiAgents.filter(a => a.risk === 'CRITICAL').length;
  const highCountAI = aiAgents.filter(a => a.risk === 'HIGH').length;

  return `
    <div style="display:flex;flex-direction:column;gap:20px">

      <!-- Header row -->
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <h2 style="font-size:18px;font-weight:700;color:#fff;margin:0;display:flex;align-items:center;gap:8px">${lucideIcon('crosshair', 20)} Threat Intelligence Hub</h2>
          <p style="font-size:12px;color:#606060;margin:4px 0 0">Live ATT&amp;CK tactic coverage · Top fired rules · ML risk summary</p>
        </div>
        <div style="display:flex;gap:12px">
          <div style="background:rgba(255,46,99,0.1);border:1px solid rgba(255,46,99,0.3);border-radius:6px;padding:8px 14px;text-align:center">
            <div style="font-size:18px;font-weight:700;color:#FF2E63">${critCountAI || liveState.alerts.filter(h => (h._source?.rule?.level ?? 0) >= 13).length}</div>
            <div style="font-size:10px;color:#606060">CRITICAL</div>
          </div>
          <div style="background:rgba(249,115,22,0.1);border:1px solid rgba(249,115,22,0.3);border-radius:6px;padding:8px 14px;text-align:center">
            <div style="font-size:18px;font-weight:700;color:#f97316">${highCountAI || liveState.alerts.filter(h => { const l = (h._source?.rule?.level ?? 0); return l >= 10 && l < 13; }).length}</div>
            <div style="font-size:10px;color:#606060">HIGH</div>
          </div>
          <div style="background:rgba(0,240,255,0.08);border:1px solid rgba(0,240,255,0.2);border-radius:6px;padding:8px 14px;text-align:center">
            <div style="font-size:18px;font-weight:700;color:#00F0FF">${activeTechniques.length}</div>
            <div style="font-size:10px;color:#606060">ACTIVE TTPs</div>
          </div>
        </div>
      </div>

      <!-- Tactic Grid -->
      <div class="glass-card" style="padding:18px 20px">
        <div style="font-size:11px;letter-spacing:1.5px;color:#A0A0A0;margin-bottom:14px">ATT&amp;CK TACTIC COVERAGE</div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px">${tacticCards}</div>
      </div>

      <!-- Top Rules + AI Risk row -->
      <div style="display:grid;grid-template-columns:1fr 320px;gap:16px">

        <!-- Top Fired Rules -->
        <div class="glass-card" style="padding:18px 20px">
          <div style="font-size:11px;letter-spacing:1.5px;color:#A0A0A0;margin-bottom:14px">TOP FIRED RULES (LIVE)</div>
          <div style="overflow-x:auto">
            <table style="width:100%;border-collapse:collapse">
              <thead>
                <tr style="border-bottom:1px solid rgba(255,255,255,0.07)">
                  ${['RULE ID', 'DESCRIPTION', 'LVL', 'COUNT', 'AGENTS'].map(h => `<th style="padding:6px 12px;text-align:left;font-size:10px;color:#606060;font-weight:400;letter-spacing:1px">${h}</th>`).join('')}
                </tr>
              </thead>
              <tbody>${ruleRows}</tbody>
            </table>
          </div>
        </div>

        <!-- AI Risk Leaderboard -->
        <div class="glass-card" style="padding:18px 20px">
          <div style="font-size:11px;letter-spacing:1.5px;color:#A0A0A0;margin-bottom:14px">AI RISK LEADERBOARD</div>
          ${aiAgents.length > 0
      ? aiAgents.sort((a, b) => b.score - a.score).slice(0, 7).map(e => {
        const col = e.risk === 'CRITICAL' ? '#FF2E63' : e.risk === 'HIGH' ? '#f97316' : e.risk === 'MEDIUM' ? '#EAB308' : '#10B981';
        const pct = Math.round(e.score * 100);
        return `
                <div style="margin-bottom:10px">
                  <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <span style="font-size:12px;color:#e0e0e0">${e.agent}</span>
                    <span style="font-size:11px;color:${col};font-weight:600">${e.risk}</span>
                  </div>
                  <div style="height:4px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden">
                    <div style="height:100%;width:${pct}%;background:${col};border-radius:2px"></div>
                  </div>
                </div>`;
      }).join('')
      : '<div style="font-size:12px;color:#606060;text-align:center;padding:20px">AI engine offline<br><span style="font-size:10px">Run ai-engine service to see risk scores</span></div>'
    }
        </div>
      </div>

      <!-- MITRE alert banner -->
      ${buildMitreAlertBanner()}
    </div>
  `;
}

// ============================================================
// LUCIDE ICON HELPER
// ============================================================
// We use the Lucide CDN (loaded in index.html) and call lucide.icons
// to get SVG strings for inline use.
function lucideIcon(name, size = 16) {
  // Lucide icons are available via window.lucide after CDN load
  if (window.lucide && window.lucide.icons) {
    const icon = window.lucide.icons[toCamelCase(name)];
    if (icon) {
      const [tag, attrs, children] = icon;
      const attrStr = Object.entries({ ...attrs, width: size, height: size, stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', fill: 'none' })
        .map(([k, v]) => `${k}="${v}"`).join(' ');
      const childStr = (children || []).map(([t, a]) => {
        const as = Object.entries(a || {}).map(([k, v]) => `${k}="${v}"`).join(' ');
        return `<${t} ${as}/>`;
      }).join('');
      return `<svg ${attrStr}>${childStr}</svg>`;
    }
  }
  // Fallback: inline SVG for key icons
  return fallbackIcon(name, size);
}

function toCamelCase(str) {
  return str.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
}

function fallbackIcon(name, size) {
  const s = size;
  const icons = {
    'home': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`,
    'radar': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19.07 4.93A10 10 0 0 0 6.99 3.34"/><path d="M4 6h.01"/><path d="M2.29 9.62A10 10 0 1 0 21.31 8.35"/><path d="M16.24 7.76A6 6 0 1 0 8.23 16.67"/><path d="M12 18h.01"/><path d="M17.99 11.66A6 6 0 0 1 15.77 16.67"/><circle cx="12" cy="12" r="2"/><path d="m13.41 10.59 5.66-5.66"/></svg>`,
    'server': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>`,
    'shield': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    'grid-2x2': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="10" height="10" x="2" y="2" rx="2"/><rect width="10" height="10" x="12" y="2" rx="2"/><rect width="10" height="10" x="2" y="12" rx="2"/><rect width="10" height="10" x="12" y="12" rx="2"/></svg>`,
    'log-out': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>`,
    'search': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>`,
    'bell': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>`,
    'user': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
    'globe': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" x2="22" y1="12" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
    'shield-alert': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>`,
    'brain': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5a3 3 0 1 0-5.997.125 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18Z"/><path d="M12 5a3 3 0 1 1 5.997.125 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18Z"/><path d="M15 13a4.5 4.5 0 0 1-3-4 4.5 4.5 0 0 1-3 4"/><path d="M17.599 6.5a3 3 0 0 0 .399-1.375"/><path d="M6.003 5.125A3 3 0 0 0 6.401 6.5"/><path d="M3.477 10.896a4 4 0 0 1 .585-.396"/><path d="M19.938 10.5a4 4 0 0 1 .585.396"/><path d="M6 18a4 4 0 0 1-1.967-.516"/><path d="M19.967 17.484A4 4 0 0 1 18 18"/></svg>`,
    'terminal': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/></svg>`,
    'search-code': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m13 13.5 2-2.5-2-2.5"/><path d="m21 21-4.3-4.3"/><path d="M9 8.5 7 11l2 2.5"/><circle cx="11" cy="11" r="8"/></svg>`,
    'zap': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
    'activity': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
    'cpu': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>`,
    'crosshair': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="22" x2="18" y1="12" y2="12"/><line x1="6" x2="2" y1="12" y2="12"/><line x1="12" x2="12" y1="6" y2="2"/><line x1="12" x2="12" y1="22" y2="18"/></svg>`,
    'alert-triangle': `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>`,
  };
  return icons[name] || `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>`;
}

// ============================================================
// BOOT
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  runBootLoader();
});
