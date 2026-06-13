// SilenceAI - Core Frontend Logic and Real-Time Dashboard Controller

// WebSocket and State
let socket = null;
let autoDefenseActive = true;
let anomalySensitivity = 65;
let activeAttackType = null;
let packets = [];
let chartInstance = null;

// Dynamic Metrics Baseline
let currentAnomaly = 1.2;
let currentTraffic = 342;

// Nodes definition
let nodes = {
  attacker: { id: 'attacker', name: 'Xaker (185.220.101.5)', type: 'attacker', x: 120, y: 70, status: 'disconnected', label: 'Tashqi Tahdid' },
  router: { id: 'router', name: 'Gateway Ruter', type: 'router', x: 380, y: 70, status: 'normal', label: 'Ruter (Gateway)' },
  switch: { id: 'switch', name: 'Core Switch', type: 'switch', x: 380, y: 190, status: 'normal', label: 'Core Switch' },
  web_server: { id: 'web_server', name: 'Veb Server (Web)', type: 'server', x: 200, y: 290, status: 'normal', label: 'Web Server' },
  database: { id: 'database', name: 'Ma\'lumotlar Bazasi', type: 'db', x: 560, y: 290, status: 'normal', label: 'Database SQL' },
  cctv: { id: 'cctv', name: 'NVR / CCTV Kamera', type: 'cctv', x: 180, y: 400, status: 'normal', label: 'NVR / CCTV' },
  pc1: { id: 'pc1', name: 'Moliya Bo\'limi PC', type: 'workstation', x: 380, y: 400, status: 'normal', label: 'Moliya PC' },
  pc2: { id: 'pc2', name: 'Menejer Noutbuki', type: 'workstation', x: 580, y: 400, status: 'normal', label: 'Menejer PC' },
  local_host_agent: { id: 'local_host_agent', name: 'Endpoint Host PC', type: 'agent', x: 280, y: 120, status: 'normal', label: 'Host Agent' }
};

// Connections definition
let connections = [
  { source: 'attacker', target: 'router', status: 'severed', id: 'link-attacker-router' },
  { source: 'router', target: 'switch', status: 'active', id: 'link-router-switch' },
  { source: 'switch', target: 'web_server', status: 'active', id: 'link-switch-web' },
  { source: 'switch', target: 'database', status: 'active', id: 'link-switch-db' },
  { source: 'switch', target: 'cctv', status: 'active', id: 'link-switch-cctv' },
  { source: 'switch', target: 'pc1', status: 'active', id: 'link-switch-pc1' },
  { source: 'switch', target: 'pc2', status: 'active', id: 'link-switch-pc2' }
];

// Document Elements
const kpiAnomaly = document.getElementById('kpi-anomaly');
const kpiAnomalyTrend = document.getElementById('kpi-anomaly-trend');
const kpiTraffic = document.getElementById('kpi-traffic');
const kpiTrafficTrend = document.getElementById('kpi-traffic-trend');
const kpiNodes = document.getElementById('kpi-nodes');
const kpiNodesTrend = document.getElementById('kpi-nodes-trend');
const kpiThreats = document.getElementById('kpi-threats');

const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const alertBanner = document.getElementById('alert-banner');
const alertSolveBtn = document.getElementById('alert-solve-btn');
const terminalLogs = document.getElementById('terminal-logs');

const btnSimulateDdos = document.getElementById('btn-simulate-ddos');
const btnSimulateBruteforce = document.getElementById('btn-simulate-bruteforce');
const btnSimulateSqli = document.getElementById('btn-simulate-sqli');
const btnSimulateRansomware = document.getElementById('btn-simulate-ransomware');
const btnSimulatePortscan = document.getElementById('btn-simulate-portscan');
const btnSimulateMitm = document.getElementById('btn-simulate-mitm');
const btnSimulateFile = document.getElementById('btn-simulate-file');
const btnReset = document.getElementById('btn-reset');
const btnClearLogs = document.getElementById('btn-clear-logs');
const btnResetBlocks = document.getElementById('btn-reset-blocks');
const btnResetDb = document.getElementById('btn-reset-db');

const toggleAutoDefense = document.getElementById('toggle-auto-defense');
const sensitivitySlider = document.getElementById('sensitivity-slider');
const sensitivityVal = document.getElementById('sensitivity-val');

// Page View DOM Elements
const pages = {
  dashboard: document.getElementById('page-dashboard'),
  threats: document.getElementById('page-threats'),
  logs: document.getElementById('page-logs'),
  devices: document.getElementById('page-devices'),
  settings: document.getElementById('page-settings')
};

// Sidebar Menu Links
const navItems = {
  dashboard: document.getElementById('nav-dashboard'),
  threats: document.getElementById('nav-threats'),
  logs: document.getElementById('nav-logs'),
  devices: document.getElementById('nav-devices'),
  settings: document.getElementById('nav-settings')
};

// Initialize Application
window.addEventListener('DOMContentLoaded', () => {
  // 1. Setup Navigation Routing
  initRouting();

  // 2. Setup Notion Block drag and drop
  initNotionBlocks();

  // 3. Connect WebSockets
  connectWS();

  // 4. Load initial logs/metrics charts
  initChart();
  initLogTerminal();
  
  // Start drawing frames
  setInterval(spawnPackets, 450);
  requestAnimationFrame(animatePackets);

  // Setup Event Listeners
  btnSimulateDdos.addEventListener('click', () => triggerAttackSimulation('ddos'));
  btnSimulateBruteforce.addEventListener('click', () => triggerAttackSimulation('brute_force'));
  btnSimulateSqli.addEventListener('click', () => triggerAttackSimulation('sql_injection'));
  btnSimulateRansomware.addEventListener('click', () => triggerAttackSimulation('ransomware'));
  btnSimulatePortscan.addEventListener('click', () => triggerAttackSimulation('port_scan'));
  btnSimulateMitm.addEventListener('click', () => triggerAttackSimulation('mitm'));
  btnSimulateFile.addEventListener('click', () => openModal('modal-file-sim'));
  btnReset.addEventListener('click', resetSystemState);
  
  if (btnClearLogs) {
    btnClearLogs.addEventListener('click', () => {
      terminalLogs.innerHTML = '';
      addLog('info', 'Tizim', 'Terminal loglari tozalandi.');
    });
  }

  if (btnResetDb) {
    btnResetDb.addEventListener('click', () => {
      if (confirm('Barcha ma\'lumotlar bazasi jurnallari o\'chirib tashlanadi. Ishonchingiz komilmi?')) {
        resetSystemState();
      }
    });
  }

  // File Simulation Submit
  document.getElementById('btn-submit-file-sim').addEventListener('click', submitFileSimulation);

  // Config adjustments listeners
  toggleAutoDefense.addEventListener('change', (e) => {
    updateRemoteConfig({ autoDefenseActive: e.target.checked });
  });

  sensitivitySlider.addEventListener('input', (e) => {
    sensitivityVal.textContent = `${e.target.value}%`;
  });
  
  sensitivitySlider.addEventListener('change', (e) => {
    updateRemoteConfig({ sensitivity: Number(e.target.value) });
  });

  // AI Chat Copilot Listeners
  initAiCopilot();
});

// ---------------- SIDEBAR ROUTING ---------------- //
function initRouting() {
  function handleRoute() {
    const hash = window.location.hash.substring(1) || 'dashboard';
    
    // Deactivate all pages and navs
    Object.values(pages).forEach(p => p.classList.remove('active'));
    Object.values(navItems).forEach(n => n.classList.remove('active'));
    
    // Activate current page
    if (pages[hash]) {
      pages[hash].classList.add('active');
    }
    if (navItems[hash]) {
      navItems[hash].classList.add('active');
    }

    // Update Breadcrumb Path
    document.getElementById('breadcrumb-current').textContent = hash.charAt(0).toUpperCase() + hash.slice(1);

    // Refresh Data for specific pages
    if (hash === 'threats') {
      loadThreatsData();
    } else if (hash === 'logs') {
      loadLogsData();
    } else if (hash === 'devices') {
      loadDevicesData();
    } else if (hash === 'settings') {
      loadSettingsData();
    }
  }

  window.addEventListener('hashchange', handleRoute);
  // Trigger initial routing
  handleRoute();
}

// ---------------- NOTION BLOCK SYSTEM ---------------- //
function initNotionBlocks() {
  const container = document.getElementById('dashboard-blocks-container');
  
  // Default blocks order
  const defaultOrder = ['block-kpis', 'block-topology', 'block-chart', 'block-about'];

  // Load Saved Order
  let savedOrder = localStorage.getItem('silence_ai_block_order');
  if (savedOrder) {
    try {
      const order = JSON.parse(savedOrder);
      // Re-order DOM elements based on order array
      order.forEach(id => {
        const el = document.getElementById(id);
        if (el) container.appendChild(el);
      });
    } catch (e) {
      console.error(e);
    }
  }

  // Drag Event Listeners
  let draggedEl = null;

  container.addEventListener('dragstart', (e) => {
    const block = e.target.closest('.notion-block');
    if (block) {
      draggedEl = block;
      block.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
    }
  });

  container.addEventListener('dragend', (e) => {
    const block = e.target.closest('.notion-block');
    if (block) {
      block.classList.remove('dragging');
    }
  });

  container.addEventListener('dragover', (e) => {
    e.preventDefault();
    const afterElement = getDragAfterElement(container, e.clientY);
    const dragging = document.querySelector('.dragging');
    if (dragging) {
      if (afterElement == null) {
        container.appendChild(dragging);
      } else {
        container.insertBefore(dragging, afterElement);
      }
    }
  });

  container.addEventListener('drop', (e) => {
    e.preventDefault();
    // Save new order
    const blocks = Array.from(container.querySelectorAll('.notion-block'));
    const orderIds = blocks.map(b => b.id);
    localStorage.setItem('silence_ai_block_order', JSON.stringify(orderIds));
    addLog('info', 'Notion-Dvigatel', 'Bloklar tartibi yangilandi va JSON formatda saqlandi.');
  });

  btnResetBlocks.addEventListener('click', () => {
    defaultOrder.forEach(id => {
      const el = document.getElementById(id);
      if (el) container.appendChild(el);
    });
    localStorage.removeItem('silence_ai_block_order');
    addLog('info', 'Notion-Dvigatel', 'Bloklar boshlang\'ich holatga tiklandi.');
  });
}

function getDragAfterElement(container, y) {
  const draggableElements = [...container.querySelectorAll('.notion-block:not(.dragging)')];

  return draggableElements.reduce((closest, child) => {
    const box = child.getBoundingClientRect();
    const offset = y - box.top - box.height / 2;
    if (offset < 0 && offset > closest.offset) {
      return { offset: offset, element: child };
    } else {
      return closest;
    }
  }, { offset: Number.NEGATIVE_INFINITY }).element;
}

// ---------------- WEBSOCKETS LAYER ---------------- //
function connectWS() {
  const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  // If loaded directly from filesystem, connect to default localhost:3000 port
  const wsHost = window.location.host || 'localhost:3000';
  const wsUrl = `${wsProto}//${wsHost}/ws`;

  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    document.getElementById('backend-status-dot').className = 'status-dot green';
    document.getElementById('backend-status-text').textContent = 'Server: Ulandi';
    addLog('info', 'WebSocket', 'Backend real-time server bilan aloqa o\'rnatildi.');
  };

  socket.onclose = () => {
    document.getElementById('backend-status-dot').className = 'status-dot red';
    document.getElementById('backend-status-text').textContent = 'Server: Uzildi';
    addLog('danger', 'WebSocket', 'Server bilan aloqa uzildi. 3 soniyadan so\'ng qayta ulanadi...');
    setTimeout(connectWS, 3000);
  };

  socket.onerror = (err) => {
    console.error('WS Error:', err);
  };

  socket.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      handleWsMessage(payload);
    } catch (e) {
      console.error(e);
    }
  };
}

function handleWsMessage(payload) {
  switch (payload.type) {
    case 'INIT':
      autoDefenseActive = payload.config.autoDefenseActive;
      anomalySensitivity = payload.config.sensitivity;
      syncConfigUI();
      
      currentAnomaly = payload.metrics.currentAnomalyRate;
      currentTraffic = payload.metrics.currentTrafficRate;
      updateKpis();
      break;

    case 'METRICS_UPDATE':
      currentAnomaly = payload.metrics.currentAnomalyRate;
      currentTraffic = payload.metrics.currentTrafficRate;
      updateKpis();
      pushChartData(currentAnomaly, currentTraffic);
      break;

    case 'CONFIG_UPDATE':
      autoDefenseActive = payload.config.autoDefenseActive;
      anomalySensitivity = payload.config.sensitivity;
      syncConfigUI();
      break;

    case 'AGENT_HEARTBEAT':
      // Register or update agent node
      const agent = payload.data;
      if (!nodes[agent.device_id]) {
        nodes[agent.device_id] = {
          id: agent.device_id,
          name: agent.name,
          type: 'agent',
          x: 280,
          y: 120,
          status: 'normal',
          label: agent.name
        };
        // Add dynamic switch connection to the agent
        if (!connections.some(c => c.target === agent.device_id)) {
          connections.push({ source: 'switch', target: agent.device_id, status: 'active', id: `link-switch-${agent.device_id}` });
        }
        addLog('info', 'Agent', `Yangi tugun qo'shildi: ${agent.name}`);
      }

      nodes[agent.device_id].status = agent.risk_level > 50 ? 'suspicious' : 'normal';
      
      // Update UI if viewing Devices or Logs page
      if (window.location.hash === '#devices') {
        loadDevicesData();
      }

      // Update KPI
      const activeCount = Object.values(nodes).filter(n => n.id !== 'attacker' && n.status !== 'disconnected').length;
      document.getElementById('active-agents-count').textContent = `Tugunlar: ${activeCount} ta faol`;
      break;

    case 'AGENT_ALERT':
      // Dynamic Alert banner
      alertBanner.classList.add('active');
      document.getElementById('attacker-ip').textContent = payload.alert.ip;
      
      if (nodes[payload.device_id]) {
        nodes[payload.device_id].status = 'attacked';
      }
      renderTopology();
      
      addLog('danger', 'Agent Alarmi', `Tugun: ${payload.device_id} - ${payload.alert.type}. Risk Score: ${payload.alert.riskScore}%`);
      break;

    case 'ATTACK_START':
      activeAttackType = payload.attack;
      kpiThreats.textContent = Number(kpiThreats.textContent) + 1;
      
      // Apply visual connections/nodes changes based on attack
      if (payload.attack === 'ddos') {
        nodes.attacker.status = 'attacked';
        nodes.router.status = 'suspicious';
        nodes.web_server.status = 'attacked';
        
        connections.find(c => c.id === 'link-attacker-router').status = 'under-threat';
        connections.find(c => c.id === 'link-router-switch').status = 'under-threat';
        connections.find(c => c.id === 'link-switch-web').status = 'under-threat';
        
        alertBanner.classList.add('active');
        document.getElementById('attacker-ip').textContent = payload.attackerIp;
        
        statusDot.className = 'status-dot danger';
        statusText.textContent = 'DDoS Hujum Ostida!';
      } 
      else if (payload.attack === 'brute_force') {
        nodes.attacker.status = 'attacked';
        nodes.router.status = 'suspicious';
        nodes.cctv.status = 'attacked';
        connections.find(c => c.id === 'link-attacker-router').status = 'under-threat';
        connections.find(c => c.id === 'link-router-switch').status = 'under-threat';
        connections.find(c => c.id === 'link-switch-cctv').status = 'under-threat';
        
        statusDot.className = 'status-dot warning';
        statusText.textContent = 'CCTV Brute-Force aniqlandi!';
      }
      else if (payload.attack === 'sql_injection') {
        nodes.attacker.status = 'attacked';
        nodes.router.status = 'suspicious';
        nodes.database.status = 'attacked';
        connections.find(c => c.id === 'link-attacker-router').status = 'under-threat';
        connections.find(c => c.id === 'link-router-switch').status = 'under-threat';
        connections.find(c => c.id === 'link-switch-db').status = 'under-threat';
        
        statusDot.className = 'status-dot danger';
        statusText.textContent = 'SQL Injection aniqlandi!';
      }
      else if (payload.attack === 'ransomware') {
        nodes.attacker.status = 'attacked';
        nodes.router.status = 'suspicious';
        if (nodes.local_host_agent) nodes.local_host_agent.status = 'attacked';
        nodes.database.status = 'suspicious';
        connections.find(c => c.id === 'link-attacker-router').status = 'under-threat';
        connections.find(c => c.id === 'link-router-switch').status = 'under-threat';
        
        statusDot.className = 'status-dot danger';
        statusText.textContent = 'Ransomware tahdidi!';
      }
      else if (payload.attack === 'port_scan') {
        nodes.attacker.status = 'attacked';
        nodes.router.status = 'suspicious';
        connections.find(c => c.id === 'link-attacker-router').status = 'under-threat';
        
        statusDot.className = 'status-dot warning';
        statusText.textContent = 'Port skanerlash aniqlandi!';
      }
      else if (payload.attack === 'mitm') {
        nodes.attacker.status = 'attacked';
        nodes.router.status = 'attacked';
        nodes.switch.status = 'suspicious';
        connections.find(c => c.id === 'link-attacker-router').status = 'under-threat';
        connections.find(c => c.id === 'link-router-switch').status = 'under-threat';
        
        statusDot.className = 'status-dot danger';
        statusText.textContent = 'MITM Spoofing!';
      }
      
      renderTopology();
      addLog('alert', 'ML Tahlilchi', `Anomaliya aniqlandi. Tahdid turi: ${payload.alert.type}. Risk: ${payload.alert.riskScore}%`);
      
      // Refresh Lists
      if (window.location.hash === '#threats') loadThreatsData();
      break;
 
    case 'ATTACK_MITIGATED':
      addLog('success', 'Response Layer', `Tahdid bartaraf etildi. Hujum qiluvchi IP ruter tomonidan bloklandi.`);
      
      // Reset all nodes to normal except attacker which is disconnected (blocked)
      nodes.attacker.status = 'disconnected';
      nodes.router.status = 'normal';
      nodes.switch.status = 'normal';
      nodes.web_server.status = 'normal';
      nodes.database.status = 'normal';
      nodes.cctv.status = 'normal';
      if (nodes.local_host_agent) nodes.local_host_agent.status = 'normal';
      
      connections.forEach(c => {
        if (c.id === 'link-attacker-router') c.status = 'severed';
        else c.status = 'active';
      });
      
      alertBanner.classList.remove('active');
      statusDot.className = 'status-dot';
      statusText.textContent = 'Tizim holati: Barqaror';
      activeAttackType = null;
      renderTopology();
      
      if (window.location.hash === '#threats') loadThreatsData();
      break;

    case 'RESET':
      // Re-initialize default node states
      nodes.attacker.status = 'disconnected';
      nodes.router.status = 'normal';
      nodes.switch.status = 'normal';
      nodes.web_server.status = 'normal';
      nodes.database.status = 'normal';
      nodes.cctv.status = 'normal';
      nodes.pc1.status = 'normal';
      nodes.pc2.status = 'normal';
      
      if (nodes.local_host_agent) {
        nodes.local_host_agent.status = 'normal';
      }

      connections.find(c => c.id === 'link-attacker-router').status = 'severed';
      connections.find(c => c.id === 'link-router-switch').status = 'active';
      connections.find(c => c.id === 'link-switch-web').status = 'active';
      connections.find(c => c.id === 'link-switch-db').status = 'active';
      connections.find(c => c.id === 'link-switch-cctv').status = 'active';
      connections.find(c => c.id === 'link-switch-pc1').status = 'active';
      connections.find(c => c.id === 'link-switch-pc2').status = 'active';

      packets = [];
      activeAttackType = null;
      alertBanner.classList.remove('active');
      statusDot.className = 'status-dot';
      statusText.textContent = 'Tizim holati: Barqaror';
      
      renderTopology();
      addLog('success', 'SOC Boshqaruv', 'Ma\'lumotlar bazasi va topologiya muvaffaqiyatli tiklandi.');
      
      if (window.location.hash === '#threats') loadThreatsData();
      if (window.location.hash === '#logs') loadLogsData();
      break;
  }
}

// ---------------- REST FETCH API CALLS ---------------- //
function getAuthHeaders() {
  return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + localStorage.getItem('silence_token') };
}

function loadThreatsData() {
  // 1. Fetch Alerts Table
  fetch('/api/alerts', { headers: getAuthHeaders() })
    .then(r => r.json())
    .then(alerts => {
      const body = document.getElementById('alerts-table-body');
      body.innerHTML = '';
      alerts.forEach(a => {
        const row = document.createElement('tr');
        const scoreClass = a.risk_score > 80 ? 'danger-txt' : (a.risk_score > 40 ? 'warning-txt' : '');
        const badgeClass = a.status === 'active' ? 'badge-danger' : 'badge-normal';
        row.innerHTML = `
          <td>#${a.id}</td>
          <td>${new Date(a.timestamp).toLocaleTimeString()}</td>
          <td>${a.type}</td>
          <td><code>${a.ip}</code></td>
          <td class="${scoreClass} font-mono" style="font-weight:700;">${a.risk_score}%</td>
          <td><span class="badge ${badgeClass}">${a.status === 'active' ? 'Faol' : 'Hal qilingan'}</span></td>
        `;
        body.appendChild(row);
      });
      
      // Update threats count badge
      const activeCount = alerts.filter(a => a.status === 'active').length;
      document.getElementById('threats-badge').textContent = activeCount;
    });

  // 2. Fetch Blocked IPs
  fetch('/api/blocked-ips', { headers: getAuthHeaders() })
    .then(r => r.json())
    .then(ips => {
      const grid = document.getElementById('blocked-ips-list');
      grid.innerHTML = '';
      if (ips.length === 0) {
        grid.innerHTML = '<div class="no-data-msg">Faol bloklangan IP manzillar mavjud emas.</div>';
        return;
      }
      ips.forEach(ip => {
        const card = document.createElement('div');
        card.className = 'blocked-ip-card';
        card.innerHTML = `
          <div class="blocked-ip-info">
            <span class="blocked-ip-title"><i class="fa-solid fa-ban"></i> ${ip.ip}</span>
            <span class="blocked-ip-reason">${ip.reason}</span>
            <span class="blocked-ip-time">${new Date(ip.blocked_at).toLocaleTimeString()} da qo'shildi</span>
          </div>
          <button class="unblock-btn" onclick="unblockIp('${ip.ip}')">Blokdan yechish</button>
        `;
        grid.appendChild(card);
      });
    });
}

function unblockIp(ip) {
  fetch('/api/reset', { method: 'POST', headers: getAuthHeaders() })
    .then(() => {
      addLog('success', 'Ruter', `IP ${ip} blokdan muvaffaqiyatli chiqarildi.`);
      loadThreatsData();
    });
}

function loadLogsData() {
  fetch('/api/logs', { headers: getAuthHeaders() })
    .then(r => r.json())
    .then(logs => {
      // Keep logs stream updated
      const container = document.getElementById('terminal-logs');
      container.innerHTML = '';
      logs.forEach(l => {
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        
        let tagClass = 'info';
        let tagText = 'MA\'LUMOT';
        
        if (l.request_type === 'DDoS' || l.request_type === 'CCTV') {
          tagClass = 'alert';
          tagText = 'OGOHLANTIRISH';
        } else if (l.request_type === 'Firewall' || l.request_type === 'FILE') {
          tagClass = 'danger';
          tagText = 'XAVF';
        } else if (l.request_type === 'Reset' || l.request_type === 'Config') {
          tagClass = 'success';
          tagText = 'SOZLOV';
        }
        
        entry.innerHTML = `
          <span class="log-time">[${new Date(l.timestamp).toLocaleTimeString()}]</span>
          <span class="log-tag ${tagClass}">${tagText}</span>
          <span class="log-text"><strong>${l.ip}:</strong> ${l.metadata}</span>
        `;
        container.appendChild(entry);
      });
    });
}

function loadDevicesData() {
  fetch('/api/devices', { headers: getAuthHeaders() })
    .then(r => r.json())
    .then(devices => {
      const grid = document.getElementById('devices-list-grid');
      grid.innerHTML = '';
      
      devices.forEach(d => {
        const card = document.createElement('div');
        card.className = `device-card ${d.status}`;
        
        // Custom graphic icon
        let iconHtml = '<i class="fa-solid fa-server"></i>';
        if (d.device_id === 'router') iconHtml = '<i class="fa-solid fa-route"></i>';
        if (d.device_id === 'cctv') iconHtml = '<i class="fa-solid fa-video"></i>';
        if (d.device_id.includes('agent')) iconHtml = '<i class="fa-solid fa-laptop-code"></i>';
        if (d.device_id.includes('pc')) iconHtml = '<i class="fa-solid fa-desktop"></i>';
        if (d.device_id === 'database') iconHtml = '<i class="fa-solid fa-database"></i>';

        const statusLabel = d.status === 'normal' ? 'XAVFSIZ' : (d.status === 'attacked' ? 'HUJUM OSTIDA' : 'IZOLYATSIYA');
        const badgeClass = d.status === 'normal' ? 'badge-normal' : 'badge-danger';
        
        card.innerHTML = `
          <div class="device-card-header">
            <div class="device-icon">${iconHtml}</div>
            <div class="device-info">
              <h4>${d.name}</h4>
              <span class="device-id font-mono">${d.device_id}</span>
            </div>
            <span class="badge ${badgeClass}">${statusLabel}</span>
          </div>
          <div class="device-specs">
            <div class="spec-row">
              <span>Xavf darajasi:</span>
              <span class="font-mono" style="font-weight:700;">${d.risk_level}%</span>
            </div>
            <div class="spec-row">
              <span>Faollik:</span>
              <span>${new Date(d.last_seen).toLocaleTimeString()}</span>
            </div>
          </div>
        `;
        grid.appendChild(card);
      });
    });
}

function loadSettingsData() {
  fetch('/api/config', { headers: getAuthHeaders() })
    .then(r => r.json())
    .then(config => {
      autoDefenseActive = config.autoDefenseActive;
      anomalySensitivity = config.sensitivity;
      syncConfigUI();
    });
}

function updateRemoteConfig(params) {
  fetch('/api/config', {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(params)
  })
  .then(r => r.json())
  .then(data => {
    autoDefenseActive = data.config.autoDefenseActive;
    anomalySensitivity = data.config.sensitivity;
    syncConfigUI();
  });
}

// ---------------- SIMULATION CONTROLS ---------------- //
function triggerAttackSimulation(type) {
  if (activeAttackType) return;
  fetch('/api/simulate-attack', {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ type })
  });
}

function resetSystemState() {
  fetch('/api/reset', { method: 'POST', headers: getAuthHeaders() });
}

function submitFileSimulation() {
  const filename = document.getElementById('sim-filename').value;
  const type = document.getElementById('sim-file-event').value;
  
  closeModal('modal-file-sim');
  
  // Directly post fake agent activity packet to the server to simulate agent
  fetch('/api/agent/report', {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({
      device_id: 'local_host_agent',
      name: 'Endpoint Host PC',
      cpu: 45.2,
      memory: 32.1,
      file_event: { filename, type }
    })
  }).then(() => {
    addLog('info', 'Host Agent', `Fayl simulyatsiyasi serverga muvaffaqiyatli jo'natildi.`);
  });
}

// ---------------- LOGGING SYSTEM ---------------- //
function addLog(type, source, message) {
  const container = document.getElementById('terminal-logs');
  if (!container) return;
  
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  
  let tagClass = 'info';
  let tagText = 'MA\'LUMOT';
  
  if (type === 'alert') {
    tagClass = 'alert';
    tagText = 'OGOHLANTIRISH';
  } else if (type === 'danger') {
    tagClass = 'danger';
    tagText = 'XAVF';
  } else if (type === 'success') {
    tagClass = 'success';
    tagText = 'HIMOYA';
  }
  
  entry.innerHTML = `
    <span class="log-time">[${new Date().toTimeString().split(' ')[0]}]</span>
    <span class="log-tag ${tagClass}">${tagText}</span>
    <span class="log-text"><strong>${source}:</strong> ${message}</span>
  `;
  
  container.appendChild(entry);
  container.scrollTop = container.scrollHeight;
}

function initLogTerminal() {
  addLog('info', 'SilenceAI', 'Tizim monitoring moduli muvaffaqiyatli ishga tushirildi.');
  addLog('info', 'ML Tahlilchi', 'FastAPI va SQLite bazasi orqali model parametrlari yuklandi.');
}

// ---------------- CHARTJS IMPLEMENTATION ---------------- //
function initChart() {
  const canvas = document.getElementById('liveChart');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  
  const labels = Array.from({ length: 15 }, (_, i) => `${i}s avval`).reverse();
  const anomalyData = Array.from({ length: 15 }, () => 1.2 + Math.random() * 1.5);
  const trafficData = Array.from({ length: 15 }, () => 300 + Math.random() * 50);

  chartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Anomaliya (%)',
          data: anomalyData,
          borderColor: '#ff6e40',
          backgroundColor: 'rgba(255, 110, 64, 0.1)',
          yAxisID: 'yAnomaly',
          tension: 0.4,
          fill: true
        },
        {
          label: 'Trafik (Mbps)',
          data: trafficData,
          borderColor: '#00e5ff',
          backgroundColor: 'rgba(0, 229, 255, 0.05)',
          yAxisID: 'yTraffic',
          tension: 0.4,
          fill: true
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#9fa1bd' } },
        yAnomaly: { position: 'right', min: 0, max: 100, ticks: { color: '#ff6e40' } },
        yTraffic: { position: 'left', min: 0, max: 1200, ticks: { color: '#00e5ff' } }
      }
    }
  });
}

function pushChartData(anomaly, traffic) {
  if (!chartInstance) return;
  chartInstance.data.datasets[0].data.push(anomaly);
  chartInstance.data.datasets[0].data.shift();
  chartInstance.data.datasets[1].data.push(traffic);
  chartInstance.data.datasets[1].data.shift();
  chartInstance.update('none');
}

// ---------------- TOPOLOGY SVG DRAWER ---------------- //
function renderTopology() {
  const svg = document.getElementById('topology-svg');
  if (!svg) return;
  
  svg.innerHTML = '';
  
  // Draw glow filters
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  defs.innerHTML = `
    <filter id="shadow" x="-30%" y="-30%" width="160%" height="160%">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000" flood-opacity="0.6"/>
    </filter>
  `;
  svg.appendChild(defs);

  // Connection Lines
  connections.forEach(conn => {
    const s = nodes[conn.source];
    const t = nodes[conn.target];
    if (!s || !t) return;
    
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('id', conn.id);
    line.setAttribute('x1', s.x);
    line.setAttribute('y1', s.y);
    line.setAttribute('x2', t.x);
    line.setAttribute('y2', t.y);
    
    let cls = 'link-line';
    if (conn.status === 'active') cls += ' active';
    if (conn.status === 'under-threat') cls += ' under-threat';
    if (conn.status === 'severed') cls += ' severed';
    line.setAttribute('class', cls);
    svg.appendChild(line);
  });

  // Nodes Drawing
  Object.values(nodes).forEach(n => {
    const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    group.setAttribute('id', `node-group-${n.id}`);
    group.setAttribute('class', `node-group ${n.status}`);
    group.setAttribute('filter', 'url(#shadow)');

    const glow = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    glow.setAttribute('cx', n.x);
    glow.setAttribute('cy', n.y);
    glow.setAttribute('r', 28);
    glow.setAttribute('class', 'node-glow');
    group.appendChild(glow);

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', n.x);
    circle.setAttribute('cy', n.y);
    circle.setAttribute('r', 22);
    circle.setAttribute('class', 'node-bg');
    group.appendChild(circle);

    // Vector SVG Icons mapping
    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    icon.setAttribute('transform', `translate(${n.x - 10}, ${n.y - 10})`);
    
    if (n.type === 'attacker') {
      icon.innerHTML = `<path d="M 2 13 C 2 7, 18 7, 18 13 Z" fill="#ff1744" />
                        <rect x="0" y="14" width="20" height="2" fill="#ff1744" />
                        <circle cx="6" cy="11" r="2" fill="white" /><circle cx="14" cy="11" r="2" fill="white" />`;
    } else if (n.type === 'router') {
      icon.innerHTML = `<rect x="0" y="6" width="20" height="8" rx="2" fill="#00e5ff" />
                        <line x1="10" y1="6" x2="10" y2="0" stroke="#00e5ff" stroke-width="1.5" />
                        <circle cx="10" cy="0" r="2" fill="#00e5ff" />`;
    } else if (n.type === 'switch') {
      icon.innerHTML = `<rect x="0" y="4" width="20" height="12" rx="2" fill="#e040fb" />
                        <line x1="3" y1="8" x2="17" y2="8" stroke="#120f1b" stroke-width="1.5" />
                        <line x1="3" y1="12" x2="17" y2="12" stroke="#120f1b" stroke-width="1.5" />`;
    } else if (n.type === 'server') {
      icon.innerHTML = `<rect x="1" y="2" width="18" height="4" fill="#dfdae8" /><circle cx="4" cy="4" r="1" fill="#00e676" />
                        <rect x="1" y="8" width="18" height="4" fill="#dfdae8" /><circle cx="4" cy="10" r="1" fill="#00e676" />
                        <rect x="1" y="14" width="18" height="4" fill="#dfdae8" /><circle cx="4" cy="16" r="1" fill="#00e676" />`;
    } else if (n.type === 'db') {
      icon.innerHTML = `<path d="M 0 4 C 0 1, 20 1, 20 4 L 20 16 C 20 19, 0 19, 0 16 Z" fill="#9c27b0" />
                        <ellipse cx="10" cy="4" rx="10" ry="3.5" fill="#e040fb" />`;
    } else if (n.type === 'cctv') {
      icon.innerHTML = `<path d="M 1 4 L 14 4 L 14 11 L 1 11 Z" fill="#ff6e40" />
                        <polygon points="14,6 19,3 19,12 14,9" fill="#ff6e40" />
                        <rect x="5" y="11" width="4" height="6" fill="#dfdae8" />`;
    } else if (n.type === 'agent') {
      icon.innerHTML = `<rect x="1" y="2" width="18" height="11" rx="1.5" fill="#00e676" />
                        <rect x="3" y="4" width="14" height="7" fill="#120f1b" />
                        <polygon points="7,13 13,13 15,17 5,17" fill="#00e676" />`;
    } else {
      icon.innerHTML = `<rect x="1" y="2" width="18" height="11" rx="1.5" fill="#f3effa" />
                        <rect x="3" y="4" width="14" height="7" fill="#120f1b" />
                        <polygon points="7,13 13,13 15,18 5,18" fill="#f3effa" />`;
    }
    
    group.appendChild(icon);

    // Label
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', n.x);
    text.setAttribute('y', n.y + 36);
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('fill', '#9fa1bd');
    text.setAttribute('font-family', 'Outfit');
    text.setAttribute('font-size', '11px');
    text.textContent = n.label;
    group.appendChild(text);

    // Badges/Status icons
    if (n.status === 'disconnected') {
      const lock = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      lock.setAttribute('transform', `translate(${n.x + 10}, ${n.y - 22})`);
      lock.innerHTML = `<circle cx="6" cy="6" r="8" fill="#ff1744" stroke="#08070b" stroke-width="1.5" />
                        <path d="M 3 6 L 6 9 L 9 4" fill="none" stroke="white" stroke-width="2" />`;
      group.appendChild(lock);
    }
    
    svg.appendChild(group);
  });
}

function spawnPackets() {
  if (activeAttackType === null) return;
  
  connections.forEach(conn => {
    if (conn.status === 'severed') return;
    const s = nodes[conn.source];
    const t = nodes[conn.target];
    if (!s || !t) return;
    
    let chance = 0.3;
    let isThreat = false;
    
    if (activeAttackType === 'ddos') {
      if (conn.source === 'attacker' || conn.source === 'router' || conn.target === 'web_server') {
        chance = 0.95;
        isThreat = true;
      }
    } else if (activeAttackType === 'cctv') {
      if (conn.target === 'cctv' || conn.source === 'cctv') {
        chance = 0.85;
        isThreat = true;
      }
    }
    
    if (Math.random() < chance) {
      packets.push({
        linkId: conn.id,
        x1: s.x, y1: s.y,
        x2: t.x, y2: t.y,
        progress: 0,
        speed: isThreat ? 0.045 : 0.02,
        isThreat
      });
    }
  });
}

function animatePackets() {
  const svg = document.getElementById('topology-svg');
  if (!svg) return;
  
  svg.querySelectorAll('.packet-dot').forEach(p => p.remove());
  
  packets = packets.filter(p => {
    p.progress += p.speed;
    if (p.progress >= 1) return false;
    
    const x = p.x1 + (p.x2 - p.x1) * p.progress;
    const y = p.y1 + (p.y2 - p.y1) * p.progress;
    
    const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    dot.setAttribute('cx', x);
    dot.setAttribute('cy', y);
    dot.setAttribute('r', p.isThreat ? 4.5 : 2.5);
    dot.setAttribute('class', p.isThreat ? 'packet-dot threat' : 'packet-dot');
    
    svg.appendChild(dot);
    return true;
  });
  
  requestAnimationFrame(animatePackets);
}

// ---------------- UI UTILS ---------------- //
function updateKpis() {
  kpiAnomaly.textContent = `${currentAnomaly.toFixed(1)}%`;
  kpiTraffic.textContent = `${currentTraffic} Mbps`;

  if (currentAnomaly > 80) {
    kpiAnomaly.style.color = 'var(--accent-red)';
    kpiAnomalyTrend.innerHTML = '<i class="fa-solid fa-arrow-trend-up"></i> Hujum xavfi!';
    kpiAnomalyTrend.className = 'kpi-trend down';
  } else if (currentAnomaly > 30) {
    kpiAnomaly.style.color = 'var(--accent-orange)';
    kpiAnomalyTrend.innerHTML = '<i class="fa-solid fa-arrow-trend-up"></i> Shubhali faollik';
    kpiAnomalyTrend.className = 'kpi-trend warning-text';
  } else {
    kpiAnomaly.style.color = '#fff';
    kpiAnomalyTrend.innerHTML = '<i class="fa-solid fa-arrow-trend-down"></i> Normal holat';
    kpiAnomalyTrend.className = 'kpi-trend';
  }

  if (currentTraffic > 800) {
    kpiTraffic.style.color = 'var(--accent-red)';
    kpiTrafficTrend.innerHTML = '<i class="fa-solid fa-bolt"></i> Peak yuklanish';
    kpiTrafficTrend.className = 'kpi-trend down';
  } else {
    kpiTraffic.style.color = '#fff';
    kpiTrafficTrend.innerHTML = '<i class="fa-solid fa-arrow-trend-up"></i> Barqaror';
    kpiTrafficTrend.className = 'kpi-trend';
  }
}

function syncConfigUI() {
  toggleAutoDefense.checked = autoDefenseActive;
  sensitivitySlider.value = anomalySensitivity;
  sensitivityVal.textContent = `${anomalySensitivity}%`;
}

// ---------------- AI COPILOT CHAT CLIENT ---------------- //
function initAiCopilot() {
  const chatSidebar = document.getElementById('ai-chat-sidebar');
  const btnToggleChat = document.getElementById('btn-toggle-chat');
  const btnFloatChat = document.getElementById('btn-float-chat');
  const chatInput = document.getElementById('chat-input');
  const btnSendChat = document.getElementById('btn-send-chat');
  
  btnToggleChat.addEventListener('click', () => {
    chatSidebar.classList.add('collapsed');
    btnFloatChat.style.display = 'flex';
  });

  btnFloatChat.addEventListener('click', () => {
    chatSidebar.classList.remove('collapsed');
    btnFloatChat.style.display = 'none';
  });

  function sendChatMessage() {
    const text = chatInput.value.trim();
    if (!text) return;

    appendChatMessage('user', text);
    chatInput.value = '';

    fetch('/api/copilot/chat', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ message: text })
    })
    .then(r => r.json())
    .then(data => {
      appendChatMessage('bot', data.reply);
    })
    .catch(() => {
      appendChatMessage('bot', "Kechirasiz, server bilan aloqa uzildi. Savolingizga javob berolmayman.");
    });
  }

  btnSendChat.addEventListener('click', sendChatMessage);
  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendChatMessage();
  });
}

function appendChatMessage(sender, text) {
  const container = document.getElementById('chat-messages-container');
  const msg = document.createElement('div');
  msg.className = `chat-message ${sender}`;
  
  // Parse simple bold markdown
  let parsedText = text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br>')
    .replace(/• /g, '• ');
    
  msg.innerHTML = parsedText;
  container.appendChild(msg);
  container.scrollTop = container.scrollHeight;
}

window.sendSuggestion = function(text) {
  document.getElementById('chat-input').value = text;
  document.getElementById('btn-send-chat').click();
};

// ---------------- OVERLAYS (MODALS) ---------------- //
window.openModal = function(id) {
  document.getElementById(id).classList.add('active');
};

window.closeModal = function(id) {
  document.getElementById(id).classList.remove('active');
};
