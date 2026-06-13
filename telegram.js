/**
 * Silence AI — Telegram Bot Servisi
 * Real-time xavfsizlik ogohlantirishlarini Telegram orqali yuboradi.
 */

require('dotenv').config();

let bot = null;
let chatId = null;
let isConfigured = false;

// =============================================
// BOT ISHGA TUSHIRISH
// =============================================
function initBot(token, chat_id) {
  try {
    const TelegramBot = require('node-telegram-bot-api');
    bot = new TelegramBot(token, { polling: false });
    chatId = chat_id;
    isConfigured = true;
    console.log(`✅ [Telegram] Bot muvaffaqiyatli ulandi. Chat ID: ${chat_id}`);
    return true;
  } catch (err) {
    console.error(`❌ [Telegram] Bot ulanishda xato: ${err.message}`);
    isConfigured = false;
    return false;
  }
}

// =============================================
// XABAR YUBORISH
// =============================================
async function sendMessage(text) {
  if (!isConfigured || !bot || !chatId) return false;
  try {
    await bot.sendMessage(chatId, text, { parse_mode: 'Markdown' });
    return true;
  } catch (err) {
    console.error(`❌ [Telegram] Xabar yuborishda xato: ${err.message}`);
    return false;
  }
}

// =============================================
// XAVF OGOHLANTIRISHLARI (formatli)
// =============================================
async function sendThreatAlert({ type, ip, riskScore, description }) {
  const emoji = getRiskEmoji(riskScore);
  const time = new Date().toLocaleString('uz-UZ');

  const message = `
${emoji} *SILENCE AI — TAHDID ANIQLANDI!*

🎯 *Hujum turi:* ${type}
🌐 *Hujumchi IP:* \`${ip}\`
⚠️ *Xavf darajasi:* ${riskScore}%
📋 *Tavsif:* ${description}
🕐 *Vaqt:* ${time}

${riskScore >= 80 ? '🔴 *KRITIK! Darhol chora ko\'ring!*' : riskScore >= 50 ? '🟡 *O\'rta xavf. Kuzatilmoqda.*' : '🟢 *Past xavf. Monitoring davom etmoqda.*'}
  `.trim();

  return await sendMessage(message);
}

// =============================================
// HUJUM BARTARAF ETILGANDA XABAR
// =============================================
async function sendMitigationNotice({ type, ip, action }) {
  const message = `
✅ *SILENCE AI — HUJUM BARTARAF ETILDI!*

🛡️ *Hujum turi:* ${type}
🚫 *Bloklangan IP:* \`${ip}\`
⚙️ *Qo'llangan chora:* ${action}
🕐 *Vaqt:* ${new Date().toLocaleString('uz-UZ')}

_Tizim yana normal holatda ishlayapti._
  `.trim();

  return await sendMessage(message);
}

// =============================================
// TIZIM HOLATI XABARI
// =============================================
async function sendSystemStatus({ status, details }) {
  const emoji = status === 'ok' ? '✅' : status === 'warning' ? '⚠️' : '🔴';
  const message = `
${emoji} *SILENCE AI — TIZIM XABARI*

📊 *Holat:* ${status.toUpperCase()}
📝 *Tafsilot:* ${details}
🕐 *Vaqt:* ${new Date().toLocaleString('uz-UZ')}
  `.trim();

  return await sendMessage(message);
}

// =============================================
// TEST XABARI
// =============================================
async function sendTestMessage() {
  const message = `
🔔 *SILENCE AI — TEST XABARI*

Agar siz bu xabarni ko'rsangiz, Telegram bot muvaffaqiyatli ulangan!

✅ Bot: Faol
✅ Chat ID: Tasdiqlangan
✅ Ogohlantirishlar: Yoqilgan

_Silence AI Kiberxavfsizlik Platformasi_
  `.trim();

  return await sendMessage(message);
}

// =============================================
// YORDAMCHI FUNKSIYALAR
// =============================================
function getRiskEmoji(score) {
  if (score >= 90) return '🚨';
  if (score >= 70) return '🔴';
  if (score >= 50) return '🟡';
  return '🟢';
}

function getStatus() {
  return { isConfigured, hasChatId: !!chatId };
}

// Standart konfiguratsiyadan ishga tushirish
if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID &&
    process.env.TELEGRAM_BOT_TOKEN !== 'your_bot_token_here') {
  initBot(process.env.TELEGRAM_BOT_TOKEN, process.env.TELEGRAM_CHAT_ID);
}

module.exports = {
  initBot,
  sendMessage,
  sendThreatAlert,
  sendMitigationNotice,
  sendSystemStatus,
  sendTestMessage,
  getStatus
};
