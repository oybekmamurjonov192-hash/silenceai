const sqlite3 = require('sqlite3').verbose();
const path = require('path');
require('dotenv').config();

const dbPath = path.join(__dirname, 'silence_ai.db');
const db = new sqlite3.Database(dbPath);

// =============================================
// JADVALLAR YARATISH
// =============================================
db.serialize(() => {
  // 1. Logs
  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT, timestamp TEXT, request_type TEXT, metadata TEXT
  )`);

  // 2. Alerts
  db.run(`CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    risk_score REAL, type TEXT, status TEXT, ip TEXT, timestamp TEXT
  )`);

  // 3. Devices
  db.run(`CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    name TEXT, status TEXT, risk_level REAL, last_seen TEXT
  )`);

  // 4. Blocked IPs
  db.run(`CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY, reason TEXT, blocked_at TEXT
  )`);

  // 5. FOYDALANUVCHILAR (YANGI)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'analyst',
    full_name TEXT,
    created_at TEXT,
    last_login TEXT
  )`);

  // 6. API KALITLAR (YANGI)
  db.run(`CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_value TEXT UNIQUE NOT NULL,
    name TEXT,
    created_by INTEGER,
    created_at TEXT,
    last_used TEXT,
    is_active INTEGER DEFAULT 1
  )`);

  // 7. TELEGRAM SOZLAMALAR (YANGI)
  db.run(`CREATE TABLE IF NOT EXISTS telegram_config (
    id INTEGER PRIMARY KEY,
    bot_token TEXT,
    chat_id TEXT,
    is_active INTEGER DEFAULT 0,
    updated_at TEXT
  )`);

  // =============================================
  // BOSHLANG'ICH MA'LUMOTLAR (Seed)
  // =============================================

  // Default qurilmalar
  db.get("SELECT COUNT(*) as count FROM devices", (err, row) => {
    if (row && row.count === 0) {
      const defaultDevices = [
        { id: 'router',     name: 'Gateway Ruter',       status: 'normal', risk: 5  },
        { id: 'switch',     name: 'Core Switch',         status: 'normal', risk: 8  },
        { id: 'web_server', name: 'Web Server',          status: 'normal', risk: 10 },
        { id: 'database',   name: 'Database SQL Server', status: 'normal', risk: 4  },
        { id: 'file_server',name: 'File Server',         status: 'normal', risk: 6  },
        { id: 'cctv',       name: 'NVR / CCTV Camera',  status: 'normal', risk: 12 },
        { id: 'pc1',        name: 'Moliya Bo\'limi PC',  status: 'normal', risk: 15 },
        { id: 'pc2',        name: 'Menejer PC',          status: 'normal', risk: 7  }
      ];
      const stmt = db.prepare("INSERT OR REPLACE INTO devices (device_id, name, status, risk_level, last_seen) VALUES (?, ?, ?, ?, ?)");
      defaultDevices.forEach(d => stmt.run(d.id, d.name, d.status, d.risk, new Date().toISOString()));
      stmt.finalize();
    }
  });

  // Default alertlar (tarix uchun)
  db.get("SELECT COUNT(*) as count FROM alerts", (err, row) => {
    if (row && row.count === 0) {
      const pastAlerts = [
        { risk: 45.2, type: 'Port Scan',     status: 'solved', ip: '192.168.1.55',  time: new Date(Date.now() - 4*3600000).toISOString() },
        { risk: 89.7, type: 'DDoS Attack',   status: 'solved', ip: '185.220.101.5', time: new Date(Date.now() - 2*3600000).toISOString() },
        { risk: 62.1, type: 'Brute Force',   status: 'solved', ip: '177.44.120.3',  time: new Date(Date.now() - 1*3600000).toISOString() }
      ];
      const stmt = db.prepare("INSERT INTO alerts (risk_score, type, status, ip, timestamp) VALUES (?, ?, ?, ?, ?)");
      pastAlerts.forEach(a => stmt.run(a.risk, a.type, a.status, a.ip, a.time));
      stmt.finalize();
    }
  });

  // Default bloklangan IP
  db.get("SELECT COUNT(*) as count FROM blocked_ips", (err, row) => {
    if (row && row.count === 0) {
      db.run("INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at) VALUES (?, ?, ?)",
        '185.220.101.5', 'DDoS Hujumi (Risk: 89.7%)', new Date(Date.now() - 2*3600000).toISOString());
    }
  });

  // Default loglar
  db.get("SELECT COUNT(*) as count FROM logs", (err, row) => {
    if (row && row.count === 0) {
      const logs = [
        { ip: '127.0.0.1',    type: 'System',   meta: 'Silence AI engine initialized. Barcha modullar yuklandi.' },
        { ip: '192.168.1.1',  type: 'Gateway',  meta: 'WAN interfeysi ulandi. Monitoring boshlandi.' },
        { ip: '185.220.101.5',type: 'DDoS',     meta: 'DDoS hujumi aniqlandi. Avtomatik himoya ishga tushdi.' },
        { ip: '185.220.101.5',type: 'Firewall', meta: 'IP bloklandi: 185.220.101.5. Port 80 trafigi to\'xtatildi.' }
      ];
      const stmt = db.prepare("INSERT INTO logs (ip, timestamp, request_type, metadata) VALUES (?, ?, ?, ?)");
      logs.forEach(l => stmt.run(l.ip, new Date().toISOString(), l.type, l.meta));
      stmt.finalize();
    }
  });

  // Default admin foydalanuvchi (async yaratish server.js da bo'ladi)
  db.get("SELECT COUNT(*) as count FROM logs", () => {
    console.log('✅ [DB] Barcha jadvallar tayyor (users, api_keys, telegram_config qo\'shildi)');
  });
});

// =============================================
// FOYDALANUVCHI FUNKSIYALARI
// =============================================
function createUser(username, passwordHash, role, fullName, callback) {
  const now = new Date().toISOString();
  db.run(
    "INSERT INTO users (username, password_hash, role, full_name, created_at) VALUES (?, ?, ?, ?, ?)",
    [username, passwordHash, role, fullName || username, now],
    function(err) { if (callback) callback(err, this ? this.lastID : null); }
  );
}

function getUserByUsername(username, callback) {
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    callback(err, row);
  });
}

function getUserById(id, callback) {
  db.get("SELECT id, username, role, full_name, created_at, last_login FROM users WHERE id = ?", [id], (err, row) => {
    callback(err, row);
  });
}

function getAllUsers(callback) {
  db.all("SELECT id, username, role, full_name, created_at, last_login FROM users ORDER BY id", [], (err, rows) => {
    callback(err, rows);
  });
}

function updateLastLogin(userId, callback) {
  db.run("UPDATE users SET last_login = ? WHERE id = ?", [new Date().toISOString(), userId], err => {
    if (callback) callback(err);
  });
}

function deleteUser(userId, callback) {
  db.run("DELETE FROM users WHERE id = ?", [userId], err => {
    if (callback) callback(err);
  });
}

// =============================================
// API KALIT FUNKSIYALARI
// =============================================
function createApiKey(keyValue, name, createdBy, callback) {
  const now = new Date().toISOString();
  db.run(
    "INSERT INTO api_keys (key_value, name, created_by, created_at) VALUES (?, ?, ?, ?)",
    [keyValue, name, createdBy, now],
    function(err) { if (callback) callback(err, this ? this.lastID : null); }
  );
}

function getAllApiKeys(callback) {
  db.all("SELECT id, name, key_value, created_at, last_used, is_active FROM api_keys ORDER BY id DESC", [], (err, rows) => {
    callback(err, rows);
  });
}

function validateApiKey(keyValue, callback) {
  db.get("SELECT * FROM api_keys WHERE key_value = ? AND is_active = 1", [keyValue], (err, row) => {
    if (row) {
      db.run("UPDATE api_keys SET last_used = ? WHERE key_value = ?", [new Date().toISOString(), keyValue]);
    }
    callback(err, row);
  });
}

function deleteApiKey(id, callback) {
  db.run("DELETE FROM api_keys WHERE id = ?", [id], err => {
    if (callback) callback(err);
  });
}

// =============================================
// TELEGRAM KONFIGURATSIYA
// =============================================
function saveTelegramConfig(botToken, chatId, callback) {
  const now = new Date().toISOString();
  db.run(
    "INSERT OR REPLACE INTO telegram_config (id, bot_token, chat_id, is_active, updated_at) VALUES (1, ?, ?, 1, ?)",
    [botToken, chatId, now],
    err => { if (callback) callback(err); }
  );
}

function getTelegramConfig(callback) {
  db.get("SELECT * FROM telegram_config WHERE id = 1", [], (err, row) => {
    callback(err, row);
  });
}

// =============================================
// ASOSIY FUNKSIYALAR (Avvalgilar)
// =============================================
function logEvent(ip, requestType, metadata, callback) {
  const timestamp = new Date().toISOString();
  db.run(
    "INSERT INTO logs (ip, timestamp, request_type, metadata) VALUES (?, ?, ?, ?)",
    [ip, timestamp, requestType, typeof metadata === 'object' ? JSON.stringify(metadata) : metadata],
    function(err) { if (callback) callback(err, this ? this.lastID : null); }
  );
}

function createAlert(riskScore, type, status, ip, callback) {
  const timestamp = new Date().toISOString();
  db.run(
    "INSERT INTO alerts (risk_score, type, status, ip, timestamp) VALUES (?, ?, ?, ?, ?)",
    [riskScore, type, status, ip, timestamp],
    function(err) { if (callback) callback(err, this ? this.lastID : null); }
  );
}

function updateAlertStatus(id, status, callback) {
  db.run("UPDATE alerts SET status = ? WHERE id = ?", [status, id], err => {
    if (callback) callback(err);
  });
}

function registerDevice(deviceId, name, status, riskLevel, callback) {
  const lastSeen = new Date().toISOString();
  db.run(
    "INSERT OR REPLACE INTO devices (device_id, name, status, risk_level, last_seen) VALUES (?, ?, ?, ?, ?)",
    [deviceId, name, status, riskLevel, lastSeen],
    err => { if (callback) callback(err); }
  );
}

function updateDeviceStatus(deviceId, status, riskLevel, callback) {
  db.run(
    "UPDATE devices SET status = ?, risk_level = ?, last_seen = ? WHERE device_id = ?",
    [status, riskLevel, new Date().toISOString(), deviceId],
    err => { if (callback) callback(err); }
  );
}

function blockIp(ip, reason, callback) {
  db.run(
    "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at) VALUES (?, ?, ?)",
    [ip, reason, new Date().toISOString()],
    err => { if (callback) callback(err); }
  );
}

function unblockIp(ip, callback) {
  db.run("DELETE FROM blocked_ips WHERE ip = ?", [ip], err => {
    if (callback) callback(err);
  });
}

function isIpBlocked(ip, callback) {
  db.get("SELECT ip FROM blocked_ips WHERE ip = ?", [ip], (err, row) => {
    callback(err, !!row);
  });
}

function getLogs(limit = 100, callback) {
  db.all("SELECT * FROM logs ORDER BY id DESC LIMIT ?", [limit], (err, rows) => {
    callback(err, rows);
  });
}

function getAlerts(limit = 50, callback) {
  db.all("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", [limit], (err, rows) => {
    callback(err, rows);
  });
}

function getDevices(callback) {
  db.all("SELECT * FROM devices ORDER BY name ASC", [], (err, rows) => {
    callback(err, rows);
  });
}

function getBlockedIps(callback) {
  db.all("SELECT * FROM blocked_ips ORDER BY blocked_at DESC", [], (err, rows) => {
    callback(err, rows);
  });
}

function clearDatabase(callback) {
  db.serialize(() => {
    db.run("DELETE FROM logs");
    db.run("DELETE FROM alerts");
    db.run("DELETE FROM blocked_ips");
    db.run("UPDATE devices SET status = 'normal', risk_level = 0", [], err => {
      if (callback) callback(err);
    });
  });
}

module.exports = {
  // Auth
  createUser, getUserByUsername, getUserById, getAllUsers, updateLastLogin, deleteUser,
  // API Keys
  createApiKey, getAllApiKeys, validateApiKey, deleteApiKey,
  // Telegram
  saveTelegramConfig, getTelegramConfig,
  // Core
  logEvent, createAlert, updateAlertStatus,
  registerDevice, updateDeviceStatus,
  blockIp, unblockIp, isIpBlocked,
  getLogs, getAlerts, getDevices, getBlockedIps,
  clearDatabase,
  db
};
