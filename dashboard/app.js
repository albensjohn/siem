/* ============================================================
   SENTINEL SIEM — app.js
   Vanilla JS — no build step required
   ============================================================ */

'use strict';

// ============================================================
// DATA
// ============================================================
const recentLogs = [
  { id: 1, severity: 'critical', msg: 'Unauthorized shell access attempt from 192.168.1.45', time: '12:45:01', source: 'K8S-NODE-03' },
  { id: 2, severity: 'warning', msg: 'Multiple failed SSH logins: root', time: '12:44:22', source: 'AUTH-SRV' },
  { id: 3, severity: 'low', msg: 'Configuration file changed: /etc/nginx/nginx.conf', time: '12:43:55', source: 'WEB-PROXY-01' },
  { id: 4, severity: 'low', msg: 'New container deployed: redis-cache-temp', time: '12:40:10', source: 'PROD-CLUSTER' },
  { id: 5, severity: 'critical', msg: 'Data exfiltration signature detected on outbound port 443', time: '12:38:44', source: 'FW-CORE-01' },
];

const aiAlerts = [
  {
    id: 1, score: 92, type: 'Brute Force Detection', time: '2 mins ago', severity: 'high',
    description: 'Detected brute-force pattern. 15 failed root logins followed by successful shell access. MITRE T1078.',
    details: {
      sourceIp: '185.12.5.210', target: 'PROD-DATABASE-01', eventsCount: 42,
      raw: '{"timestamp": "2026-02-17T12:45:01Z",\n "event_type": "ssh_login",\n "status": "failed",\n "user": "root",\n "src_ip": "185.12.5.210"}'
    }
  },
  {
    id: 2, score: 78, type: 'Data Exfiltration', time: '14 mins ago', severity: 'medium',
    description: 'Anomalous outbound traffic volume detected to unauthorized cloud storage endpoint.',
    details: {
      sourceIp: '10.0.1.55', target: 'AWS-S3-GLO-01', eventsCount: 15,
      raw: '{"timestamp": "2026-02-17T12:31:22Z",\n "traffic_mb": 1450,\n "destination": "ext-storage.io"}'
    }
  }
];

const agents = Array.from({ length: 35 }, (_, i) => ({
  id: i,
  status: i === 5 || i === 12 ? 'threat' : i % 8 === 0 ? 'inactive' : 'healthy',
  name: `SRV-${String(i).padStart(2, '0')}`,
  cpu: Math.floor(20 + Math.random() * 60),
  ram: Math.floor(30 + Math.random() * 50),
}));

const vulnData = [
  { name: 'Critical', value: 12, color: '#FF2E63' },
  { name: 'High', value: 25, color: '#F97316' },
  { name: 'Medium', value: 48, color: '#EAB308' },
  { name: 'Low', value: 110, color: '#00F0FF' },
];

const cves = [
  { id: 'CVE-2024-21626', pkg: 'runc', severity: 'Critical', score: 9.8, status: 'Patch Pending' },
  { id: 'CVE-2023-48795', pkg: 'openssh', severity: 'High', score: 7.5, status: 'Assessing' },
  { id: 'CVE-2024-0567', pkg: 'gnutls', severity: 'High', score: 7.8, status: 'Mitigated' },
  { id: 'CVE-2023-44487', pkg: 'http2', severity: 'Critical', score: 9.1, status: 'Reboot Required' },
  { id: 'CVE-2024-21626', pkg: 'libcontainer', severity: 'Critical', score: 9.8, status: 'Patch Pending' },
];

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

const activeTechniques = ['Brute Force', 'Valid Accounts', 'Phishing', 'Process Injection', 'Data Encrypted for Impact', 'Web Shell', 'Cloud Infrastructure Discovery'];
const observedTechniques = ['Phishing', 'Command and Scripting Interpreter'];

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
};

let liveState = {
  mgrToken: '',
  agents: [],   // raw Wazuh agent objects
  alerts: [],   // raw Indexer hits
  aiRisks: {},   // ai_risks.json object
  mitreTechniques: [], // active technique names from live alerts
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
      size: 10,
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
    if (!res.ok) return;
    liveState.aiRisks = await res.json();
  } catch (e) { /* ai engine not ready */ }
}

async function refreshLiveData() {
  await Promise.all([apiFetchAgents(), apiFetchAlerts(), apiFetchAiRisks()]);
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
  const aiOnline = Object.keys(liveState.aiRisks).length > 0;
  const mgrDot = mgrOnline ? '<span class="footer-dot"></span>' : '<span class="footer-dot" style="background:#FF2E63"></span>';
  const idxDot = idxOnline ? '<span class="footer-dot"></span>' : '<span class="footer-dot" style="background:#FF2E63"></span>';
  const aiDot = aiOnline ? '<span class="footer-dot cyan"></span>' : '<span class="footer-dot" style="background:#f97316"></span>';
  footer.innerHTML = `
    <div class="footer-left">
      <div class="footer-item">${mgrDot}<span>MGR_API: ${mgrOnline ? 'ONLINE' : 'OFFLINE'}</span></div>
      <div class="footer-item">${idxDot}<span>INDEXER: ${idxOnline ? 'STREAMING' : 'OFFLINE'}</span></div>
      <div class="footer-item">${aiDot}<span>AI_ENGINE: ${aiOnline ? 'v2.4.1_STABLE' : 'STARTING'}</span></div>
    </div>
    <div class="footer-right">
      <span>AGENTS: ${liveState.agents.length || '—'}</span>
      <span>ALERTS: ${liveState.alerts.length || '—'}</span>
      <span class="footer-version">SENTINEL OS v4.0.2</span>
    </div>
  `;
}

function updateTopBarEps() {
  const epsEl = document.querySelector('.topbar-eps-value');
  if (!epsEl || liveState.alerts.length === 0) return;
  // Rough EPS estimate from alert count
  epsEl.textContent = `${liveState.alerts.length * 12} EPS`;
}

// ============================================================
// BOOT LOADER
// ============================================================
function runBootLoader() {
  const bootEl = document.getElementById('boot-loader');
  const logBox = document.getElementById('boot-log-box');
  const progressBar = document.getElementById('boot-progress-bar');
  const progressPct = document.getElementById('boot-progress-pct');

  const bootLogs = [
    'INITIALIZING SENTINEL OS v4.0.2...',
    'LOADING KERNEL MODULES...',
    'ESTABLISHING SECURE TUNNEL [AES-256]...',
    'MOUNTING K8S_PRIMARY CLUSTER...',
    'SYNCING THREAT INTELLIGENCE FEEDS...',
    'INITIALIZING AI FORENSIC ENGINE...',
    'VERIFYING LEVEL 4 CLEARANCE...',
    'SYSTEM READY.',
  ];

  let idx = 0;
  const step = () => {
    if (idx < bootLogs.length) {
      const p = document.createElement('p');
      p.className = 'boot-log-line';
      p.innerHTML = `<span class="prompt">[&gt;]</span> ${bootLogs[idx]}`;
      logBox.appendChild(p);
      logBox.scrollTop = logBox.scrollHeight;
      idx++;
      const pct = Math.min(Math.round((idx / bootLogs.length) * 100), 100);
      progressBar.style.width = pct + '%';
      progressPct.textContent = pct + '%';
      setTimeout(step, 320);
    } else {
      setTimeout(() => {
        bootEl.classList.add('fade-out');
        setTimeout(() => {
          bootEl.classList.add('hidden');
          initApp();
        }, 500);
      }, 400);
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
      <button class="sidebar-logout" title="Logout">
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
    titleEl.innerHTML = `${tab} <span>// OPERATIONAL_INTEL</span>`;
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
    <div class="topbar-search-wrap">
      <div class="topbar-search-icon">
        <span>&gt;</span>
        ${lucideIcon('search', 16)}
      </div>
      <input class="topbar-search" type="text" placeholder="search logs, threats, or assets..." />
    </div>
    <div class="topbar-right">
      <div>
        <div class="topbar-eps-label">System Pulse</div>
        <div class="topbar-eps-value">1,240 EPS</div>
      </div>
      <canvas id="sparkline-canvas" width="96" height="40"></canvas>
      <div class="topbar-divider"></div>
      <button class="topbar-bell">
        ${lucideIcon('bell', 20)}
        <span class="topbar-bell-dot"></span>
      </button>
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
    case 'fleet': content.innerHTML = buildFleetTab(); break;
    case 'shield': content.innerHTML = buildShieldTab(); setTimeout(initShieldTab, 50); break;
    case 'matrix': content.innerHTML = buildMatrixTab(); break;
    default: content.innerHTML = buildNexusTab(); setTimeout(initNexusTab, 50);
  }
}

// ============================================================
// NEXUS TAB
// ============================================================
function buildNexusTab() {
  const anomalyBars = Array.from({ length: 120 }, (_, i) => {
    const isAnomaly = Math.random() > 0.95;
    const isWarning = !isAnomaly && Math.random() > 0.9;
    const cls = isAnomaly ? 'anomaly' : isWarning ? 'warning' : '';
    const delay = (i * 0.02).toFixed(2);
    return `<div class="anomaly-bar ${cls}" style="animation-delay:${delay}s"></div>`;
  }).join('');

  const arcs = [1, 2, 3, 4, 5].map((_, i) => {
    const left = (15 + Math.random() * 70).toFixed(1);
    const top = (15 + Math.random() * 70).toFixed(1);
    const rot = Math.floor(Math.random() * 360);
    const delay = (i * 1.2).toFixed(1);
    return `<div class="map-arc" style="left:${left}%;top:${top}%;transform:rotate(${rot}deg);animation-delay:${delay}s"></div>`;
  }).join('');

  const activityRows = recentLogs.map(log => `
    <div class="activity-row">
      <div class="activity-severity ${log.severity}"></div>
      <div style="flex:1">
        <div class="activity-msg">${log.msg}</div>
        <div class="activity-meta">
          <span>Source: ${log.source}</span>
          <span>Time: ${log.time}</span>
        </div>
      </div>
      <button class="activity-inspect">INSPECT</button>
    </div>
  `).join('');

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
            ${arcs}
            <div class="map-pulse-point cyan" style="top:30%;left:25%">
              <div class="dot"></div><div class="ring"></div>
            </div>
            <div class="map-pulse-point crimson" style="top:45%;left:65%">
              <div class="dot"></div><div class="ring"></div>
            </div>
            <div class="map-pulse-point cyan" style="top:20%;left:75%">
              <div class="dot"></div>
            </div>
            <div class="map-pulse-point purple" style="top:60%;left:40%">
              <div class="dot" style="width:6px;height:6px"></div>
            </div>
            <div class="map-overlay-bl">
              <p>LAT: 37.7749 // LON: -122.4194</p>
              <p>REGION: US-WEST-2 (ACTIVE)</p>
            </div>
            <div class="map-overlay-tr">[!] HIGH_VOLUME_INGRESS_DETECTED</div>
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
          <button class="activity-export">EXPORT LOGS.CSV</button>
        </div>
        ${activityRows}
      </div>
    </div>
  `;
}

function initNexusTab() {
  const bar = document.getElementById('nexus-risk-bar');
  if (bar) bar.style.width = '12.4%';

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
            <button class="activity-inspect">INSPECT</button>
          </div>`;
      }).join('');
      streamEl.innerHTML = `
        <div class="activity-header">
          <h3>Live Activity Stream</h3>
          <button class="activity-export">EXPORT LOGS.CSV</button>
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
  const alert = aiAlerts.find(a => a.id === selectedAlertId) || aiAlerts[0];

  const alertCards = aiAlerts.map(a => `
    <div class="glass-card hunter-alert-card ${a.id === selectedAlertId ? 'active' : ''}"
         data-alert-id="${a.id}" style="cursor:pointer">
      <div class="hunter-alert-top">
        <span class="hunter-score ${a.severity}">Score: ${a.score}</span>
        <span class="hunter-alert-time">${a.time}</span>
      </div>
      <div class="hunter-alert-type">${a.type}</div>
      <div class="hunter-alert-desc">${a.description}</div>
    </div>
  `).join('');

  return `
    <div class="hunter-grid">
      <!-- Feed -->
      <div class="hunter-feed scrollbar-hide">
        <div class="hunter-feed-title">${lucideIcon('brain', 14)} AI Analysis Feed</div>
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
                <span class="hunter-gauge-score" id="gauge-score">${alert.score}</span>
                <span class="hunter-gauge-text">Isolation Score</span>
              </div>
            </div>
            <!-- Details -->
            <div class="hunter-details">
              <h1 id="inspector-type">${alert.type}</h1>
              <div class="hunter-meta-row">
                <div class="hunter-meta-box">
                  <div class="hunter-meta-box-label">Target Asset</div>
                  <div class="hunter-meta-box-value" id="inspector-target">${alert.details.target}</div>
                </div>
                <div class="hunter-meta-box">
                  <div class="hunter-meta-box-label">Source IP</div>
                  <div class="hunter-meta-box-value white" id="inspector-ip">${alert.details.sourceIp}</div>
                </div>
                <div class="hunter-meta-box">
                  <div class="hunter-meta-box-label">Events</div>
                  <div class="hunter-meta-box-value white" id="inspector-events">${alert.details.eventsCount}</div>
                </div>
              </div>
              <div class="hunter-llm-box">
                <div class="hunter-llm-icon">${lucideIcon('terminal', 16)}</div>
                <div style="flex:1">
                  <div class="hunter-llm-header">
                    <span class="hunter-llm-label">LLM INSIGHT ENGINE</span>
                  </div>
                  <p class="hunter-llm-text"><span class="hunter-cursor">_</span> <span id="inspector-desc">${alert.description}</span></p>
                </div>
              </div>
            </div>
          </div>

          <!-- Evidence -->
          <div>
            <div class="hunter-evidence-title">${lucideIcon('search', 14)} Evidence &amp; Forensics</div>
            <div class="hunter-evidence-grid">
              <div class="hunter-json-card">
                <div class="hunter-json-label">Raw JSON Payload</div>
                <pre class="hunter-json-pre" id="inspector-raw">${alert.details.raw}</pre>
              </div>
              <div class="hunter-action-card">
                <div class="hunter-action-icon">${lucideIcon('zap', 24)}</div>
                <div>
                  <div class="hunter-action-title">Recommended Action</div>
                  <div class="hunter-action-desc" id="inspector-action">Auto-isolate host and revoke temporary credentials for source IP ${alert.details.sourceIp}</div>
                </div>
                <button class="hunter-isolate-btn">EXECUTE ISOLATION</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

function initHunterTab() {
  // --- LIVE: inject AI risk cards from ai_risks.json ---
  const feedEl = document.querySelector('.hunter-feed');
  if (feedEl && Object.keys(liveState.aiRisks).length > 0) {
    const riskEntries = Object.entries(liveState.aiRisks).filter(([k]) => k !== 'System');
    if (riskEntries.length > 0) {
      const liveCards = riskEntries.map(([agent, risk], i) => {
        const sev = risk.status === 'CRITICAL' ? 'high' : risk.status === 'HIGH' ? 'medium' : 'low';
        const isActive = i === 0 && selectedAlertId === 1;
        return `
          <div class="glass-card hunter-alert-card ${isActive ? 'active' : ''}" data-alert-id="live-${i}" style="cursor:pointer">
            <div class="hunter-alert-top">
              <span class="hunter-score ${sev}">Score: ${risk.risk_score}</span>
              <span class="hunter-alert-time">live</span>
            </div>
            <div class="hunter-alert-type">${agent}</div>
            <div class="hunter-alert-desc">${risk.description || `Status: ${risk.status} — Anomalies: ${risk.anomalies}`}</div>
          </div>`;
      }).join('');
      feedEl.innerHTML = `<div class="hunter-feed-title">${lucideIcon('brain', 14)} AI Analysis Feed (Live)</div>${liveCards}`;

      // Update inspector with first live risk
      const [firstAgent, firstRisk] = riskEntries[0];
      const typeEl = document.getElementById('inspector-type');
      const descEl = document.getElementById('inspector-desc');
      const targetEl = document.getElementById('inspector-target');
      const eventsEl = document.getElementById('inspector-events');
      const rawEl = document.getElementById('inspector-raw');
      const actionEl = document.getElementById('inspector-action');
      const scoreEl = document.getElementById('gauge-score');
      if (typeEl) typeEl.textContent = firstAgent;
      if (descEl) descEl.textContent = firstRisk.description || `Status: ${firstRisk.status}`;
      if (targetEl) targetEl.textContent = firstAgent;
      if (eventsEl) eventsEl.textContent = firstRisk.anomalies;
      if (rawEl) rawEl.textContent = JSON.stringify(firstRisk, null, 2);
      if (actionEl) actionEl.textContent = firstRisk.status === 'CRITICAL'
        ? `Isolate ${firstAgent} immediately — risk score ${firstRisk.risk_score}/100`
        : `Monitor ${firstAgent} — risk score ${firstRisk.risk_score}/100`;
      if (scoreEl) scoreEl.textContent = firstRisk.risk_score;
    }
  }

  // Wire alert card clicks
  document.querySelectorAll('.hunter-alert-card').forEach(card => {
    card.addEventListener('click', () => {
      selectedAlertId = parseInt(card.dataset.alertId) || 1;
      renderTab('hunter');
      setTimeout(initHunterTab, 50);
    });
  });

  // Draw gauge
  drawHunterGauge();
}

function drawHunterGauge() {
  const canvas = document.getElementById('hunter-gauge');
  if (!canvas) return;
  const alert = aiAlerts.find(a => a.id === selectedAlertId) || aiAlerts[0];
  const score = alert.score;

  if (hunterGaugeChart) hunterGaugeChart.destroy();

  hunterGaugeChart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [score, 100 - score],
        backgroundColor: ['#FF2E63', 'rgba(255,255,255,0.05)'],
        borderWidth: 0,
      }]
    },
    options: {
      cutout: '75%',
      rotation: -135,
      circumference: 270,
      animation: { duration: 600 },
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
    }
  });
}

// ============================================================
// FLEET TAB
// ============================================================
function buildFleetTab() {
  // Merge live agents into the agents array if available
  if (liveState.agents.length > 0) {
    // Replace mock agents with live data
    agents.length = 0;
    liveState.agents.forEach((a, i) => {
      agents.push({
        id: i,
        status: a.status === 'active' ? 'healthy' : a.status === 'disconnected' ? 'inactive' : 'inactive',
        name: a.name || `SRV-${String(i).padStart(2, '0')}`,
        cpu: Math.floor(20 + Math.random() * 60),
        ram: Math.floor(30 + Math.random() * 50),
      });
    });
  }
  // Original buildFleetTab body below:
  const hexes = agents.map((agent, i) => {
    const row = Math.floor(i / 7);
    const offset = row % 2 !== 0 ? 'margin-top:46px;margin-left:-4px;' : '';
    return `
      <div class="hex-wrap" style="${offset}">
        <div class="hex ${agent.status}" title="${agent.name}">
          ${lucideIcon('activity', 12)}
          <span class="hex-num">${agent.name.split('-')[1]}</span>
        </div>
        <div class="hex-tooltip">
          <div class="hex-tooltip-header">
            <span class="hex-tooltip-name">${agent.name}</span>
            <span class="hex-tooltip-dot ${agent.status}"></span>
          </div>
          <div class="hex-tooltip-row">
            <span class="hex-tooltip-key">CPU Load</span>
            <span class="hex-tooltip-val">${agent.cpu}%</span>
          </div>
          <div class="hex-tooltip-row">
            <span class="hex-tooltip-key">Memory</span>
            <span class="hex-tooltip-val">${agent.ram}%</span>
          </div>
        </div>
      </div>
    `;
  }).join('');

  const maintItems = [1, 2, 3].map(i => `
    <div class="fleet-maint-item">
      <div class="fleet-maint-icon">${lucideIcon('cpu', 14)}</div>
      <div>
        <div class="fleet-maint-name">Kernel Patch Required</div>
        <div class="fleet-maint-sub">SRV-0${i} • v5.15.0-76</div>
      </div>
    </div>
  `).join('');

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
        <div class="glass-card fleet-dist-card">
          <div class="fleet-dist-title">Fleet Distribution</div>
          <div class="fleet-dist-item">
            <div class="fleet-dist-row">
              <span class="fleet-dist-name">Linux Nodes</span>
              <span class="fleet-dist-count cyan">24</span>
            </div>
            <div class="fleet-dist-track">
              <div class="fleet-dist-bar cyan" style="width:70%"></div>
            </div>
          </div>
          <div class="fleet-dist-item">
            <div class="fleet-dist-row">
              <span class="fleet-dist-name">Windows Nodes</span>
              <span class="fleet-dist-count purple">18</span>
            </div>
            <div class="fleet-dist-track">
              <div class="fleet-dist-bar purple" style="width:45%"></div>
            </div>
          </div>
        </div>

        <div class="glass-card fleet-maint-card">
          <div class="fleet-maint-title">Maintenance Queue</div>
          ${maintItems}
        </div>
      </div>
    </div>
  `;
}

// ============================================================
// SHIELD TAB
// ============================================================
function buildShieldTab() {
  const cveRows = cves.map(cve => `
    <tr>
      <td class="cve-id">${cve.id}</td>
      <td class="cve-pkg">${cve.pkg}</td>
      <td><span class="cve-severity-badge ${cve.severity.toLowerCase()}">${cve.severity}</span></td>
      <td class="cve-score">${cve.score}</td>
      <td class="cve-status">${cve.status}</td>
      <td class="cve-action"><button class="cve-patch-btn">PATCH_ASSET</button></td>
    </tr>
  `).join('');

  const legendItems = vulnData.map(v => `
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
            <div class="shield-compliance-title">Compliance Score</div>
            <div class="shield-compliance-score">84%</div>
            <div class="shield-compliance-label">Overall Hardening</div>
            <div class="shield-compliance-row">
              <span class="shield-compliance-key">SOC2 Type II</span>
              <span class="shield-compliance-val pass">PASS</span>
            </div>
            <div class="shield-compliance-row">
              <span class="shield-compliance-key">HIPAA</span>
              <span class="shield-compliance-val warn">WARNING</span>
            </div>
            <div class="shield-compliance-row">
              <span class="shield-compliance-key">NIST SP 800-53</span>
              <span class="shield-compliance-val enforced">ENFORCED</span>
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
              <p class="shield-reco-text">Rotation of TLS certificates on <span class="highlight">K8S-LB</span> is 5 days overdue.</p>
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
    vulnData[0].value = counts.Critical || vulnData[0].value;
    vulnData[1].value = counts.High || vulnData[1].value;
    vulnData[2].value = counts.Medium || vulnData[2].value;
    vulnData[3].value = counts.Low || vulnData[3].value;

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
  }

  const canvas = document.getElementById('shield-chart');
  if (!canvas) return;
  if (shieldChart) shieldChart.destroy();

  shieldChart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: vulnData.map(v => v.name),
      datasets: [{
        data: vulnData.map(v => v.value),
        backgroundColor: vulnData.map(v => v.color),
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
// MATRIX TAB
// ============================================================
function buildMatrixTab() {
  // --- LIVE: overlay real MITRE techniques from Indexer aggregation ---
  if (liveState.mitreTechniques.length > 0) {
    // Merge live techniques into activeTechniques
    liveState.mitreTechniques.forEach(t => {
      if (!activeTechniques.includes(t)) activeTechniques.push(t);
    });
  }
  const cols = tactics.map(tactic => {
    const techs = tactic.techniques.map(tech => {
      const isActive = activeTechniques.includes(tech);
      const isObserved = observedTechniques.includes(tech);
      const cls = isActive ? 'active' : isObserved ? 'observed' : 'inactive';
      return `<div class="matrix-technique ${cls}">${tech}</div>`;
    }).join('');

    return `
      <div class="matrix-col">
        <div class="matrix-col-header">
          <div class="matrix-col-name">${tactic.name}</div>
          <div class="matrix-col-count">${tactic.techniques.length} Techniques</div>
        </div>
        ${techs}
      </div>
    `;
  }).join('');

  return `
    <div>
      <div class="matrix-header">
        <div>
          <h2 class="matrix-title">${lucideIcon('crosshair', 24)} MITRE ATT&amp;CK® Matrix</h2>
          <p class="matrix-subtitle">Real-time threat mapping based on recent log activity and behavioral analysis.</p>
        </div>
        <div class="matrix-legend">
          <div class="matrix-legend-item">
            <div class="matrix-legend-box" style="background:#FF2E63;box-shadow:0 0 8px #FF2E63"></div>
            <span class="matrix-legend-label">Active Threat</span>
          </div>
          <div class="matrix-legend-item">
            <div class="matrix-legend-box" style="background:rgba(123,97,255,0.4)"></div>
            <span class="matrix-legend-label">Observed</span>
          </div>
          <div class="matrix-legend-item">
            <div class="matrix-legend-box" style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.1)"></div>
            <span class="matrix-legend-label">Inactive</span>
          </div>
        </div>
      </div>

      <div class="matrix-scroll scrollbar-hide">
        <div class="matrix-grid">${cols}</div>
      </div>

      <div class="glass-card matrix-alert-card">
        <div class="matrix-alert-inner">
          <div class="matrix-alert-icon">${lucideIcon('shield-alert', 24)}</div>
          <div>
            <div class="matrix-alert-title">Active Tactic Chain Detected</div>
            <p class="matrix-alert-desc">
              Sentinel has correlated activity matching a known Ransomware-as-a-Service (RaaS) playbook.
              The chain involves <span class="highlight">Valid Accounts (T1078)</span> followed by
              <span class="highlight"> Brute Force (T1110)</span> and
              <span class="highlight"> Data Encrypted for Impact (T1486)</span>.
            </p>
            <div class="matrix-alert-actions">
              <button class="matrix-btn-primary">INITIATE INCIDENT RESPONSE</button>
              <button class="matrix-btn-secondary">VIEW FULL ATTACK PATH</button>
            </div>
          </div>
        </div>
      </div>
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
