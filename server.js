require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const path = require('path');
const db = require('./database');
const aiEngine = require('./ai_engine');
const auth = require('./auth');
const telegram = require('./telegram');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });
const PORT = process.env.PORT || 3000;

// =============================================
// TIZIM HOLATI
// =============================================
let autoDefenseActive = true;
let sensitivity = 65;
let currentAnomalyRate = 1.2;
let currentTrafficRate = 342;
let activeAttack = null;
const ipRequestMap = new Map();

const suspiciousPatterns = [
  /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
  /<script[\s\S]*?>[\s\S]*?<\/script>/i,
  /\.\.\//,
  /exec\s*\(|system\s*\(|passthru\s*\(/i,
  /union\s+select|drop\s+table|insert\s+into/i,
];

const RATE_LIMIT_WINDOW_MS = 10000;
const RATE_LIMIT_MAX = 30;
const AUTO_BLOCK_MAX = 60;

// =============================================
// ADMIN FOYDALANUVCHI (Birinchi ishga tushganda)
// =============================================
async function ensureAdminExists() {
  db.getUserByUsername(process.env.DEFAULT_ADMIN_USERNAME || 'admin', async (err, user) => {
    if (!user) {
      const hash = await auth.hashPassword(process.env.DEFAULT_ADMIN_PASSWORD || 'silence123');
      db.createUser('admin', hash, 'admin', 'Administrator', (err) => {
        if (!err) {
          console.log('✅ [Auth] Admin foydalanuvchi yaratildi: admin / silence123');
        }
      });
    }
  });
}

ensureAdminExists();

// =============================================
// MIDDLEWARE
// =============================================
app.use(express.json());

// Public static endpoints
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});
app.get('/style.css', (req, res) => {
  res.sendFile(path.join(__dirname, 'style.css'));
});

// =============================================
// REAL HUJUM ANIQLASH MIDDLEWARE (Tashqi IPlar)
// =============================================
app.use((req, res, next) => {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '127.0.0.1';
  const isLocal = ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(clientIp);

  if (req.path === '/api/agent/report' || req.path.startsWith('/api/auth/')) return next();
  if (!req.path.startsWith('/api/') && !req.path.endsWith('.html')) return next();

  if (!isLocal) {
    const now = Date.now();
    const entry = ipRequestMap.get(clientIp) || { count: 0, firstSeen: now };
    if (now - entry.firstSeen > RATE_LIMIT_WINDOW_MS) { entry.count = 0; entry.firstSeen = now; }
    entry.count++;
    entry.lastSeen = now;
    ipRequestMap.set(clientIp, entry);

    const fullUrl = req.originalUrl;
    const body = JSON.stringify(req.body || '');
    const isSuspicious = suspiciousPatterns.some(p => p.test(fullUrl) || p.test(body));

    if (isSuspicious) {
      const analysis = aiEngine.analyzeEvent({ ip: clientIp, request_type: 'INJECTION', metadata: `Payload: ${fullUrl.substring(0, 80)}` });
      db.logEvent(clientIp, 'Injection', `⚠️ Injection hujumi aniqlandi! URL: ${fullUrl.substring(0, 100)}`);
      db.createAlert(analysis.riskScore, 'SQL Injection / XSS', 'active', clientIp, (err, alertId) => {
        if (autoDefenseActive) {
          db.blockIp(clientIp, `Injection (Risk: ${analysis.riskScore}%)`, () => {});
          db.logEvent('System', 'WAF', `Auto-Defense: ${clientIp} bloklandi (Injection hujumi).`);
        }
        broadcast({ type: 'ATTACK_DETECTED', attack: 'injection', attackerIp: clientIp,
          alert: { id: alertId, riskScore: analysis.riskScore, type: 'SQL Injection / XSS', ip: clientIp, timestamp: new Date().toISOString() } });
        telegram.sendThreatAlert({ type: 'SQL Injection / XSS', ip: clientIp, riskScore: analysis.riskScore, description: `Shubhali payload aniqlandi: ${fullUrl.substring(0, 80)}` });
      });
      return res.status(403).json({ error: 'Forbidden: Suspicious payload detected' });
    }

    if (entry.count >= AUTO_BLOCK_MAX) {
      if (autoDefenseActive) {
        db.blockIp(clientIp, `DDoS/Rate limit (${entry.count} req/10s)`, () => {});
        db.logEvent('System', 'Firewall', `Auto-Defense: ${clientIp} bloklandi (Rate: ${entry.count} req/10s)`);
        broadcast({ type: 'ATTACK_DETECTED', attack: 'ratelimit', attackerIp: clientIp,
          alert: { riskScore: 95, type: 'DDoS / Rate Limit', ip: clientIp, timestamp: new Date().toISOString() } });
        telegram.sendThreatAlert({ type: 'DDoS / Rate Limit', ip: clientIp, riskScore: 95, description: `${entry.count} so'rov/10 soniya — avtomatik bloklandi.` });
      }
      return res.status(429).json({ error: 'Too Many Requests' });
    }
  }
  next();
});

// Static fayllar (himoya keyin)
app.use(express.static(__dirname));

// =============================================
// AUTH ROUTELAR (Himoyasiz)
// =============================================

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username va parol kiritish shart.' });

  db.getUserByUsername(username, async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Foydalanuvchi topilmadi.' });

    const valid = await auth.verifyPassword(password, user.password_hash);
    if (!valid) {
      db.logEvent('Auth', 'Login', `❌ Noto'g'ri login urinishi: ${username}`);
      return res.status(401).json({ error: 'Parol noto\'g\'ri.' });
    }

    db.updateLastLogin(user.id, () => {});
    const token = auth.generateToken(user);
    db.logEvent('Auth', 'Login', `✅ ${user.role.toUpperCase()} foydalanuvchi kirdi: ${username}`);
    broadcast({ type: 'USER_LOGIN', username, role: user.role });

    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role, full_name: user.full_name }
    });
  });
});

// CHIQISH
app.post('/api/auth/logout', auth.authMiddleware, (req, res) => {
  db.logEvent('Auth', 'Logout', `${req.user.username} tizimdan chiqdi.`);
  res.json({ success: true });
});

// MENING MA'LUMOTLARIM
app.get('/api/auth/me', auth.authMiddleware, (req, res) => {
  db.getUserById(req.user.id, (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'Foydalanuvchi topilmadi.' });
    res.json(user);
  });
});

// =============================================
// FOYDALANUVCHI BOSHQARUVI (Faqat admin)
// =============================================
app.get('/api/users', auth.authMiddleware, auth.requireRole('admin'), (req, res) => {
  db.getAllUsers((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/users', auth.authMiddleware, auth.requireRole('admin'), async (req, res) => {
  const { username, password, role, full_name } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username va password kiritish shart.' });
  const hash = await auth.hashPassword(password);
  db.createUser(username, hash, role || 'analyst', full_name, (err, id) => {
    if (err) return res.status(400).json({ error: 'Bu username band.' });
    db.logEvent('Admin', 'UserCreate', `Yangi foydalanuvchi yaratildi: ${username} (${role})`);
    res.json({ success: true, id });
  });
});

app.delete('/api/users/:id', auth.authMiddleware, auth.requireRole('admin'), (req, res) => {
  if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'O\'z profilingizni o\'chira olmaysiz.' });
  db.deleteUser(req.params.id, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// =============================================
// API KALIT BOSHQARUVI
// =============================================
app.get('/api/api-keys', auth.authMiddleware, auth.requireRole('admin'), (req, res) => {
  db.getAllApiKeys((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/api-keys', auth.authMiddleware, auth.requireRole('admin'), (req, res) => {
  const { name } = req.body;
  const key = 'sai_' + crypto.randomBytes(24).toString('hex');
  db.createApiKey(key, name || 'API Kalit', req.user.id, (err, id) => {
    if (err) return res.status(500).json({ error: err.message });
    db.logEvent('Admin', 'APIKey', `Yangi API kalit yaratildi: ${name}`);
    res.json({ success: true, id, key_value: key, name });
  });
});

app.delete('/api/api-keys/:id', auth.authMiddleware, auth.requireRole('admin'), (req, res) => {
  db.deleteApiKey(req.params.id, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// =============================================
// TELEGRAM SOZLAMALARI
// =============================================
app.get('/api/telegram/status', auth.authMiddleware, (req, res) => {
  res.json(telegram.getStatus());
});

app.post('/api/telegram/config', auth.authMiddleware, auth.requireRole('admin'), (req, res) => {
  const { bot_token, chat_id } = req.body;
  if (!bot_token || !chat_id) return res.status(400).json({ error: 'Bot token va chat_id kiritish shart.' });

  const success = telegram.initBot(bot_token, chat_id);
  if (success) {
    db.saveTelegramConfig(bot_token, chat_id, () => {});
    db.logEvent('Admin', 'Telegram', 'Telegram bot sozlamalari yangilandi.');
    res.json({ success: true, message: 'Bot ulandi!' });
  } else {
    res.status(400).json({ error: 'Bot token noto\'g\'ri. @BotFather dan to\'g\'ri token oling.' });
  }
});

app.post('/api/telegram/test', auth.authMiddleware, auth.requireRole('admin'), async (req, res) => {
  const sent = await telegram.sendTestMessage();
  if (sent) {
    res.json({ success: true, message: 'Test xabari Telegramga yuborildi!' });
  } else {
    res.status(400).json({ error: 'Telegram sozlanmagan. Avval bot tokenini kiriting.' });
  }
});

// =============================================
// HIMOYALANGAN API ENDPOINTLAR
// =============================================
app.get('/api/logs', auth.authMiddleware, (req, res) => {
  db.getLogs(100, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/alerts', auth.authMiddleware, (req, res) => {
  db.getAlerts(50, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/devices', auth.authMiddleware, (req, res) => {
  db.getDevices((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/blocked-ips', auth.authMiddleware, (req, res) => {
  db.getBlockedIps((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/config', auth.authMiddleware, (req, res) => {
  res.json({ autoDefenseActive, sensitivity, activeAttack });
});

app.post('/api/config', auth.authMiddleware, (req, res) => {
  if (req.body.autoDefenseActive !== undefined) autoDefenseActive = !!req.body.autoDefenseActive;
  if (req.body.sensitivity !== undefined) {
    sensitivity = Number(req.body.sensitivity);
    aiEngine.setSensitivity(sensitivity);
  }
  db.logEvent('127.0.0.1', 'Config', `Sozlamalar yangilandi: Auto-Defense=${autoDefenseActive}, Sezgirlik=${sensitivity}%`);
  broadcast({ type: 'CONFIG_UPDATE', config: { autoDefenseActive, sensitivity } });
  res.json({ success: true });
});

// =============================================
// TASHQI INTEGRATSIYA (API Key orqali)
// =============================================
app.post('/api/external/alert', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'API kalit talab qilinadi. X-API-Key header kiriting.' });

  db.validateApiKey(apiKey, (err, keyData) => {
    if (err || !keyData) return res.status(403).json({ error: 'Yaroqsiz API kalit.' });

    const { type, ip, risk_score, description } = req.body;
    if (!type || !ip) return res.status(400).json({ error: 'type va ip maydonlari shart.' });

    const riskScore = risk_score || 50;
    db.logEvent(ip, 'External', `📡 Tashqi tizim ogohlantirishi: ${type} — ${description || ''}`);
    db.createAlert(riskScore, type, 'active', ip, (err, alertId) => {
      broadcast({ type: 'ATTACK_DETECTED', attack: 'external', attackerIp: ip,
        alert: { id: alertId, riskScore, type, ip, timestamp: new Date().toISOString(), source: keyData.name } });
      telegram.sendThreatAlert({ type, ip, riskScore, description: description || 'Tashqi tizimdan ogohlantirildi.' });
      res.json({ success: true, alertId });
    });
  });
});

// =============================================
// HUJUM SIMULYATSIYALARI (6 tur)
// =============================================
function runAttack(config) {
  const { attackType, ip, logMsg, deviceUpdates, alertType, trafficRate, anomalyRate, mitigationLog, mitigationDelay, deviceResets } = config;

  activeAttack = attackType;
  if (trafficRate) currentTrafficRate = trafficRate;
  if (anomalyRate) currentAnomalyRate = anomalyRate;

  db.logEvent(ip, attackType.toUpperCase(), logMsg);
  deviceUpdates.forEach(d => db.updateDeviceStatus(d.id, d.status, d.risk));

  const analysis = aiEngine.analyzeEvent({ ip, request_type: attackType.toUpperCase(), metadata: logMsg });
  db.createAlert(analysis.riskScore, alertType, 'active', ip, (err, alertId) => {
    broadcast({ type: 'ATTACK_START', attack: attackType, attackerIp: ip,
      alert: { id: alertId, riskScore: analysis.riskScore, type: alertType, ip, timestamp: new Date().toISOString() } });
    telegram.sendThreatAlert({ type: alertType, ip, riskScore: analysis.riskScore, description: logMsg });

    if (autoDefenseActive) {
      setTimeout(() => {
        db.blockIp(ip, `${alertType} (Risk: ${analysis.riskScore}%)`, () => {});
        db.logEvent('System', 'AutoDefense', mitigationLog);
        deviceResets.forEach(d => db.updateDeviceStatus(d.id, 'normal', d.risk || 5.0));
        db.updateAlertStatus(alertId, 'solved');
        activeAttack = null;
        currentTrafficRate = 330;
        currentAnomalyRate = 1.2;
        broadcast({ type: 'ATTACK_MITIGATED', attack: attackType, ip });
        telegram.sendMitigationNotice({ type: alertType, ip, action: mitigationLog });
      }, mitigationDelay || 5000);
    }
  });
}

app.post('/api/simulate-attack', auth.authMiddleware, (req, res) => {
  const { type } = req.body;

  const attacks = {
    ddos: {
      attackType: 'ddos', ip: '185.220.101.5', alertType: 'DDoS Hujumi',
      trafficRate: 980, anomalyRate: 96.5,
      logMsg: '🚨 Massiv DDoS hujumi! Web server parallel so\'rovlar ostida. Bandwidth to\'yinyapti.',
      deviceUpdates: [{ id: 'web_server', status: 'attacked', risk: 96.5 }, { id: 'router', status: 'suspicious', risk: 65 }],
      mitigationLog: 'Auto-Defense: DDoS IP bloklandi. BGP Blackhole yoqildi. Trafik normalga qaytdi.',
      deviceResets: [{ id: 'web_server' }, { id: 'router' }], mitigationDelay: 5000
    },
    brute_force: {
      attackType: 'brute_force', ip: '92.118.160.12', alertType: 'Brute Force Hujumi',
      anomalyRate: 78.3,
      logMsg: '🔑 SSH/Admin panelda brute-force! Soniyada 200+ noto\'g\'ri login urinishi.',
      deviceUpdates: [{ id: 'cctv', status: 'attacked', risk: 78.3 }],
      mitigationLog: 'Auto-Defense: IP bloklandi. Login sessiyasi o\'chirildi. CAPTCHA yoqildi.',
      deviceResets: [{ id: 'cctv' }], mitigationDelay: 4500
    },
    sql_injection: {
      attackType: 'sql_injection', ip: '103.21.244.99', alertType: 'SQL Injection',
      anomalyRate: 88.0,
      logMsg: '💉 SQL Injection! Payload: \' OR 1=1-- Ma\'lumotlar bazasiga kirish urinishi.',
      deviceUpdates: [{ id: 'database', status: 'attacked', risk: 88 }],
      mitigationLog: 'Auto-Defense: WAF qoidasi qo\'shildi. DB kirish logi saqlandi. IP bloklandi.',
      deviceResets: [{ id: 'database' }], mitigationDelay: 4000
    },
    ransomware: {
      attackType: 'ransomware', ip: '45.142.212.100', alertType: 'Ransomware Hujumi',
      trafficRate: 150, anomalyRate: 99.1,
      logMsg: '💀 RANSOMWARE! Fayl shifrlash boshlanmoqda. Kritik fayllar .encrypted ga o\'zgartirilmoqda!',
      deviceUpdates: [{ id: 'file_server', status: 'attacked', risk: 99.1 }, { id: 'database', status: 'suspicious', risk: 70 }],
      mitigationLog: 'Auto-Defense: Tarmoq segmenti izolyatsiya qilindi. Jarayon to\'xtatildi. Backup tiklanmoqda.',
      deviceResets: [{ id: 'file_server' }, { id: 'database' }], mitigationDelay: 6000
    },
    port_scan: {
      attackType: 'port_scan', ip: '198.51.100.42', alertType: 'Port Skanerlash',
      anomalyRate: 55.0,
      logMsg: '🔭 Nmap port skanerlash! 1-65535 portlar ketma-ket tekshirilmoqda. Razvedka hujumi.',
      deviceUpdates: [{ id: 'router', status: 'suspicious', risk: 55 }],
      mitigationLog: 'Auto-Defense: IDS qoidasi ishga tushdi. IP bloklandi. Honeypot yoqildi.',
      deviceResets: [{ id: 'router' }], mitigationDelay: 3500
    },
    mitm: {
      attackType: 'mitm', ip: '172.16.0.99', alertType: 'MITM (ARP Spoofing)',
      anomalyRate: 71.5,
      logMsg: '🕵️ Man-in-the-Middle! ARP Spoofing aniqlandi. Tarmoq trafigi tutib olinmoqda.',
      deviceUpdates: [{ id: 'router', status: 'attacked', risk: 71.5 }, { id: 'switch', status: 'suspicious', risk: 45 }],
      mitigationLog: 'Auto-Defense: Dynamic ARP Inspection yoqildi. Port izolyatsiyaga olindi.',
      deviceResets: [{ id: 'router' }, { id: 'switch' }], mitigationDelay: 5000
    }
  };

  if (!attacks[type]) return res.status(400).json({ error: 'Noma\'lum hujum turi.' });
  runAttack(attacks[type]);
  res.json({ success: true, activeAttack: type });
});

// =============================================
// RESET
// =============================================
app.post('/api/reset', auth.authMiddleware, (req, res) => {
  activeAttack = null;
  currentTrafficRate = 340;
  currentAnomalyRate = 1.2;
  ipRequestMap.clear();
  db.clearDatabase(() => {
    db.logEvent('System', 'Reset', 'Tizim boshlang\'ich holatga qaytarildi.');
    broadcast({ type: 'RESET' });
    res.json({ success: true });
  });
});

// =============================================
// ENDPOINT AGENT (API Key orqali)
// =============================================
app.post('/api/agent/report', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const { device_id, name, cpu, memory, file_event } = req.body;
  const clientIp = req.ip || '127.0.0.1';

  db.registerDevice(device_id, name, 'normal', 0.0);
  let analysis = { riskScore: 0, isAnomalous: false };

  if (file_event) {
    const isDangerous = file_event.severity === 'HIGH';
    analysis = aiEngine.analyzeEvent({
      ip: clientIp,
      request_type: isDangerous ? 'DANGEROUS_FILE' : 'FILE',
      metadata: `Fayl: ${file_event.filename} (${file_event.type})`
    });

    if (isDangerous || analysis.isAnomalous) {
      const riskScore = isDangerous ? 95 : analysis.riskScore;
      const alertType = isDangerous ? 'Xavfli Fayl Aniqlandi' : 'Fayl Anomaliyasi';
      db.logEvent(clientIp, 'FILE', `⚠️ Agent xavf aniqladi: ${file_event.filename}`);
      db.createAlert(riskScore, alertType, 'active', clientIp, (err, alertId) => {
        db.updateDeviceStatus(device_id, 'suspicious', riskScore);
        broadcast({ type: 'AGENT_ALERT', device_id,
          alert: { id: alertId, riskScore, type: alertType, ip: clientIp, timestamp: new Date().toISOString() } });
        if (isDangerous) {
          telegram.sendThreatAlert({ type: alertType, ip: clientIp, riskScore, description: `Agent xavfli fayl aniqladi: ${file_event.filename}` });
        }
      });
    }
  } else if (cpu > 90) {
    analysis = aiEngine.analyzeEvent({ ip: clientIp, request_type: 'CPU_SPIKE', metadata: `CPU: ${cpu}%` });
    db.logEvent(clientIp, 'System', `⚠️ Yuqori CPU: ${cpu}%, RAM: ${memory}%`);
    db.updateDeviceStatus(device_id, 'suspicious', 40.0);
  } else {
    db.updateDeviceStatus(device_id, 'normal', 5.0);
  }

  broadcast({ type: 'AGENT_HEARTBEAT', data: { device_id, name, cpu, memory, file_event, risk_level: analysis.riskScore || 5.0 } });
  res.json({ success: true, autoDefenseActive });
});

// =============================================
// AI COPILOT
// =============================================
app.post('/api/copilot/chat', auth.authMiddleware, (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Xabar bo\'sh.' });
  const q = message.toLowerCase();

  if (q.includes('blok') || q.includes('ip')) {
    db.getBlockedIps((err, rows) => {
      if (!rows?.length) return res.json({ reply: "Hozirda hech qaysi IP bloklanmagan. Tizim xavfsiz ✅" });
      res.json({ reply: `Bloklangan IP'lar:\n\n${rows.map(r => `• **${r.ip}**: ${r.reason}`).join('\n')}` });
    });
  } else if (q.includes('alert') || q.includes('xavf') || q.includes('tahdid')) {
    db.getAlerts(5, (err, rows) => {
      if (!rows?.length) return res.json({ reply: "Faol tahdidlar yo'q." });
      res.json({ reply: `So'nggi alertlar:\n\n${rows.map(r => `• **${r.type}** (${r.ip}) — Risk: ${r.risk_score}% [${r.status}]`).join('\n')}` });
    });
  } else if (q.includes('telegram')) {
    const status = telegram.getStatus();
    res.json({ reply: status.isConfigured ? "✅ Telegram bot ulangan va ogohlantirishlar yuborilmoqda!" : "❌ Telegram sozlanmagan. Admin paneldan bot token kiriting." });
  } else if (q.includes('foydalanuvchi') || q.includes('user')) {
    db.getAllUsers((err, rows) => {
      res.json({ reply: `Tizim foydalanuvchilari:\n\n${rows.map(r => `• **${r.username}** (${r.role}) — So'nggi kirish: ${r.last_login ? new Date(r.last_login).toLocaleString() : 'hech qachon'}`).join('\n')}` });
    });
  } else if (q.includes('hisobot') || q.includes('xulosa')) {
    db.getAlerts(50, (err, alerts) => {
      db.getBlockedIps((e, blocked) => {
        db.getDevices((e2, devices) => {
          const active = alerts?.filter(a => a.status === 'active').length || 0;
          const normal = devices?.filter(d => d.status === 'normal').length || 0;
          const tg = telegram.getStatus();
          res.json({ reply: `### Silence AI — Kiberxavfsizlik Xulosasi\n\n• **Holat:** ${active > 0 ? '⚠️ TAHDID BOR' : '✅ XAVFSIZ'}\n• **Faol tahdidlar:** ${active} ta\n• **Bloklangan IP:** ${blocked?.length || 0} ta\n• **Xavfsiz qurilmalar:** ${normal}/${devices?.length || 0}\n• **Telegram:** ${tg.isConfigured ? '✅ Ulangan' : '❌ Sozlanmagan'}\n\n**Tavsiya:** ${active > 0 ? 'Shubhali portlarni uzing va loglarni tekshiring.' : 'Tizim barqaror.'}` });
        });
      });
    });
  } else if (q.includes('qurilma') || q.includes('device')) {
    db.getDevices((err, rows) => {
      res.json({ reply: `Tarmoq qurilmalari:\n\n${rows?.map(r => `• **${r.name}**: ${r.status.toUpperCase()} (Xavf: ${r.risk_level}%)`).join('\n')}` });
    });
  } else {
    res.json({ reply: "Savollaringiz:\n- *Bloklangan IP'lar?*\n- *So'nggi alertlar?*\n- *Tizim hisoboti*\n- *Qurilmalar holati*\n- *Telegram holati?*\n- *Foydalanuvchilar?*" });
  }
});

// =============================================
// WEBSOCKET
// =============================================
server.on('upgrade', (request, socket, head) => {
  const pathname = new URL(request.url, `http://${request.headers.host}`).pathname;
  if (pathname === '/ws') {
    wss.handleUpgrade(request, socket, head, ws => wss.emit('connection', ws, request));
  } else socket.destroy();
});

function broadcast(data) {
  const payload = JSON.stringify(data);
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(payload); });
}

wss.on('connection', (ws) => {
  ws.send(JSON.stringify({ type: 'INIT', config: { autoDefenseActive, sensitivity }, metrics: { currentAnomalyRate, currentTrafficRate } }));
  ws.on('message', (msg) => {
    try {
      const d = JSON.parse(msg);
      if (d.type === 'PING') ws.send(JSON.stringify({ type: 'PONG' }));
    } catch (e) {}
  });
});

// =============================================
// METRICS LOOP
// =============================================
setInterval(() => {
  if (!activeAttack) {
    currentAnomalyRate = 1.0 + Math.random() * 1.5;
    currentTrafficRate = 300 + Math.random() * 50;
  } else {
    currentAnomalyRate = Math.max(1, currentAnomalyRate + (Math.random() - 0.5) * 2);
    currentTrafficRate = Math.max(100, currentTrafficRate + (Math.random() - 0.5) * 10);
  }
  broadcast({ type: 'METRICS_UPDATE', metrics: {
    currentAnomalyRate: parseFloat(currentAnomalyRate.toFixed(1)),
    currentTrafficRate: Math.round(currentTrafficRate)
  }});
}, 1000);

server.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`🚀 Silence AI Enterprise Server — port ${PORT}`);
  console.log(`🌐 Dashboard:  http://localhost:${PORT}/login.html`);
  console.log(`🔐 Login:      admin / silence123`);
  console.log(`🛡️  Real Threat Detection: YONIQ`);
  console.log(`📱 Telegram:   ${telegram.getStatus().isConfigured ? 'ULANGAN ✅' : 'Sozlanmagan (.env ni to\'ldiring)'}`);
  console.log(`⚔️  Attacks:    DDoS, BruteForce, SQLi, Ransomware, PortScan, MITM`);
  console.log(`======================================================\n`);
});
