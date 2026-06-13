/**
 * Silence AI - Lightweight Host Endpoint Agent v2.0
 * Monitors host system and reports ONLY real suspicious activity.
 * Filters out false positives from its own database/log files.
 */

const fs = require('fs');
const path = require('path');
const http = require('http');

const SERVER_URL = 'http://localhost:3000/api/agent/report';
const AGENT_ID = 'local_host_agent';
const AGENT_NAME = 'Endpoint Host PC';

// === FAYLLAR FILTRI: Bular o'zgarganda HECH QACHON tahdid sifatida belgilanmaydi ===
const IGNORED_EXTENSIONS = [
  '.db', '.db-journal', '.db-wal', '.db-shm',  // SQLite database fayllari
  '.log', '.tmp', '.temp',                        // Log va vaqtinchalik fayllar
  '.lock', '.pid',                                // Tizim fayllari
];

const IGNORED_DIRS = [
  'node_modules', '.git', '.gemini', '__pycache__', '.cache', 'dist', 'build'
];

const IGNORED_FILENAMES = [
  'silence.db', 'package-lock.json', '.DS_Store', 'Thumbs.db'
];

// === HAQIQIY TAHDID: Bu kengaytmali fayllar paydo bo'lsa — xavf! ===
const DANGEROUS_EXTENSIONS = [
  '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js.bak',
  '.sh', '.msi', '.dll', '.ransomware', '.encrypted',
  '.crypted', '.locky', '.wannacry'
];

console.log(`\n======================================================`);
console.log(`🛡️  Silence AI - Endpoint Agent v2.0`);
console.log(`🖥️  Tugun nomi: ${AGENT_NAME}`);
console.log(`🔌 Backend: ${SERVER_URL}`);
console.log(`======================================================\n`);
console.log(`📁 Kuzatilayotgan papka: ${__dirname}`);
console.log(`🚫 Istisno: .db, .log, node_modules va tizim fayllari`);
console.log(`⚠️  Xavfli: .exe, .bat, .ps1, .encrypted fayllar\n`);

// === Fayl xavfliligini tekshirish ===
function isIgnored(filename) {
  if (!filename) return true;

  // Yashirin fayllar (.gitignore kabi)
  if (filename.startsWith('.')) return true;

  // Istisno nomlar
  if (IGNORED_FILENAMES.some(f => filename === f)) return true;

  // Istisno papkalar
  if (IGNORED_DIRS.some(d => filename.includes(d))) return true;

  // Istisno kengaytmalar
  const ext = path.extname(filename).toLowerCase();
  if (IGNORED_EXTENSIONS.includes(ext)) return true;

  return false;
}

function isDangerous(filename) {
  const ext = path.extname(filename).toLowerCase();
  return DANGEROUS_EXTENSIONS.includes(ext);
}

// === Tizim metrikalari (simulyatsiya) ===
function getCpuUsage() {
  const base = Math.sin(Date.now() / 60000) * 10 + 15;
  const spikeChance = Math.random() < 0.03 ? 55 : 0; // kamroq spike
  return parseFloat((base + spikeChance + Math.random() * 5).toFixed(1));
}

function getMemoryUsage() {
  const total = 16384;
  const baseUsed = 6120 + Math.sin(Date.now() / 120000) * 500;
  return parseFloat(((baseUsed / total) * 100).toFixed(1));
}

// === Fayl o'zgarishlarini kuzatish ===
let fileEventQueue = [];

fs.watch(__dirname, { recursive: true }, (eventType, filename) => {
  if (!filename) return;
  if (isIgnored(filename)) return; // Soxta tahdidlarni o'tkazib yubor

  const dangerous = isDangerous(filename);
  const severity = dangerous ? 'HIGH' : 'LOW';

  if (dangerous) {
    console.log(`🚨 [XAVFLI FAYL!] ${filename} (${eventType}) — Xavf darajasi: YUQORI`);
  } else {
    console.log(`🔍 [Fayl] ${filename} (${eventType}) — Kuzatilmoqda`);
  }

  // Faqat .js, .json, .html, .css va xavfli fayllarni yuboramiz
  const ext = path.extname(filename).toLowerCase();
  const monitoredExts = ['.js', '.json', '.html', '.css', '.env', '.config'];
  if (dangerous || monitoredExts.includes(ext)) {
    fileEventQueue.push({
      filename,
      type: eventType,
      severity,
      time: new Date().toISOString()
    });
  }
});

// === Serverga hisobot yuborish ===
function reportToBackend() {
  const fileEvent = fileEventQueue.shift() || null;
  const cpu = getCpuUsage();
  const memory = getMemoryUsage();

  const payload = JSON.stringify({
    device_id: AGENT_ID,
    name: AGENT_NAME,
    cpu,
    memory,
    file_event: fileEvent
  });

  const parsedUrl = new URL(SERVER_URL);
  const options = {
    hostname: parsedUrl.hostname,
    port: parsedUrl.port,
    path: parsedUrl.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  };

  const req = http.request(options, (res) => {
    let data = '';
    res.on('data', chunk => { data += chunk; });
    res.on('end', () => {
      if (fileEvent && fileEvent.severity === 'HIGH') {
        console.log(`✅ [YUBORILDI] Xavfli fayl hodisasi serverga yuborildi: ${fileEvent.filename}`);
      }
    });
  });

  req.on('error', (err) => {
    console.error(`❌ [Xato] Backend ulanmadi: ${err.message}`);
  });

  req.write(payload);
  req.end();
}

// Har 2 soniyada hisobot
setInterval(reportToBackend, 2000);
console.log(`📡 Agent ishga tushdi. Har 2 soniyada serverga hisobot jo'natilmoqda...`);
console.log(`✅ Tizim fayllari avtomatik filtrlangan — soxta tahdidlar yo'q!\n`);
