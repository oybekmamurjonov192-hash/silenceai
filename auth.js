/**
 * Silence AI — Auth Module (JWT + bcrypt)
 * Login, token verification, role-based access control
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || 'silence_ai_secret_2024';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// =============================================
// PAROL BOSHQARUVI
// =============================================
async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// =============================================
// JWT TOKEN
// =============================================
function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
}

// =============================================
// MIDDLEWARE — Himoyalangan routelar uchun
// =============================================
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

  if (!token) {
    return res.status(401).json({ error: 'Kirish taqiqlangan. Token topilmadi.' });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(403).json({ error: 'Token yaroqsiz yoki muddati tugagan.' });
  }

  req.user = decoded;
  next();
}

// =============================================
// ROL TEKSHIRISH MIDDLEWARE
// =============================================
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Autentifikatsiya talab qilinadi.' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: `Bu amal uchun ${roles.join(' yoki ')} roli kerak.` });
    }
    next();
  };
}

// =============================================
// AGENT AUTENTIFIKATSIYA (API Key orqali)
// =============================================
function agentAuthMiddleware(validApiKeys) {
  return (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !validApiKeys.includes(apiKey)) {
      return res.status(401).json({ error: 'Yaroqsiz API kalit.' });
    }
    req.isAgent = true;
    next();
  };
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateToken,
  verifyToken,
  authMiddleware,
  requireRole,
  agentAuthMiddleware
};
