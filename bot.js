const TelegramBot = require("node-telegram-bot-api");
const express = require("express");
const fs = require("fs").promises;
const path = require("path");
const { spawn } = require("child_process");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const xss = require("xss");
const validator = require("validator");
const axios = require('axios');
require('dotenv').config();
const admin = require("firebase-admin");

const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI || "https://accounts.google.com/o/oauth2/auth",
  token_uri: process.env.FIREBASE_TOKEN_URI || "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: `https://www.googleapis.com/oauth2/v1/certs`,
  client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(process.env.FIREBASE_CLIENT_EMAIL)}`
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL || "https://rabattedealde-23a0d-default-rtdb.firebaseio.com"
});

const db = admin.database();
const dealsRef = db.ref('deals');

const requiredEnvVars = ['BOT_TOKEN', 'ADMIN_IDS', 'WEBHOOK_SECRET'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_IDS = process.env.ADMIN_IDS.split(',').map(id => parseInt(id.trim()));
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const WEBSITE_URL = process.env.WEBSITE_URL || "localhost:3000";
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

let bot;
try {
  bot = new TelegramBot(BOT_TOKEN, { 
    polling: true,
    request: {
      agentOptions: {
        keepAlive: true,
        family: 4
      }
    }
  });
} catch (error) {
  console.error('❌ Failed to initialize Telegram bot:', error);
  process.exit(1);
}

class SecurityManager {
  constructor() {
    this.rateLimits = new Map();
    this.blockedIPs = new Set();
    this.suspiciousActivity = new Map();
    this.botDetection = new Map();
    this.fingerprints = new Map();
    this.cleanupInterval = setInterval(() => this.cleanup(), 300000);
  }

  checkRateLimit(identifier, limit = 50, window = 60000) { 
    const now = Date.now();
    const key = `rate_${identifier}`;
    
    if (!this.rateLimits.has(key)) {
      this.rateLimits.set(key, [now]);
      return true;
    }
    
    const requests = this.rateLimits.get(key);
    const recentRequests = requests.filter(time => now - time < window);
    
    if (recentRequests.length >= limit) {
      return false;
    }
    
    recentRequests.push(now);
    this.rateLimits.set(key, recentRequests);
    return true;
  }

  blockIdentifier(identifier, duration = 300000) {
    this.blockedIPs.add(identifier);
    setTimeout(() => this.blockedIPs.delete(identifier), duration);
    console.warn(`🚫 Blocked identifier: ${identifier} for ${duration}ms`);
  }

  isBlocked(identifier) {
    return this.blockedIPs.has(identifier);
  }

  logSuspiciousActivity(identifier, activity) {
    const key = `${identifier}-${activity}`;
    const count = this.suspiciousActivity.get(key) || 0;
    this.suspiciousActivity.set(key, count + 1);
    
    if (count > 3) {
      this.blockIdentifier(identifier, 600000); 
      console.error(`🚨 Suspicious activity detected: ${identifier} - ${activity}`);
    }
  }

  detectBot(req) {
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.ip;
    
    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /requests/i,
      /postman/i, /insomnia/i, /httpie/i
    ];
    
    if (botPatterns.some(pattern => pattern.test(userAgent))) {
      this.logSuspiciousActivity(ip, 'bot_user_agent');
      return true;
    }
    
    const requiredHeaders = ['accept', 'accept-language', 'accept-encoding'];
    const missingHeaders = requiredHeaders.filter(header => !req.headers[header]);
    
    if (missingHeaders.length > 1) {
      this.logSuspiciousActivity(ip, 'missing_headers');
      return true;
    }
    
    const botKey = `bot_${ip}`;
    const requests = this.botDetection.get(botKey) || [];
    const now = Date.now();
    const recentRequests = requests.filter(time => now - time < 10000); 
    
    if (recentRequests.length > 10) {
      this.logSuspiciousActivity(ip, 'high_frequency_requests');
      return true;
    }
    
    recentRequests.push(now);
    this.botDetection.set(botKey, recentRequests);
    
    return false;
  }

  generateFingerprint(req) {
    const components = [
      req.headers['user-agent'] || '',
      req.headers['accept'] || '',
      req.headers['accept-language'] || '',
      req.headers['accept-encoding'] || '',
      req.ip
    ];
    
    return crypto.createHash('sha256')
      .update(components.join('|'))
      .digest('hex')
      .substring(0, 16);
  }

  validateFingerprint(req) {
    const fingerprint = this.generateFingerprint(req);
    const ip = req.ip;
    const stored = this.fingerprints.get(ip);
    
    if (!stored) {
      this.fingerprints.set(ip, {
        fingerprint,
        firstSeen: Date.now(),
        requestCount: 1
      });
      return true;
    }
    
    stored.requestCount++;
    
    if (stored.fingerprint !== fingerprint) {
      this.logSuspiciousActivity(ip, 'fingerprint_change');
      stored.fingerprint = fingerprint;
    }
    
    return true;
  }

  generateSecureToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  validateCSRF(token, session) {
    return session && session.csrfToken === token;
  }

  cleanup() {
    const now = Date.now();
    const fiveMinutesAgo = now - 300000;
    
    for (const [identifier, requests] of this.rateLimits.entries()) {
      const validRequests = requests.filter(time => time > fiveMinutesAgo);
      if (validRequests.length === 0) {
        this.rateLimits.delete(identifier);
      } else {
        this.rateLimits.set(identifier, validRequests);
      }
    }
    
    for (const [key, requests] of this.botDetection.entries()) {
      const validRequests = requests.filter(time => time > fiveMinutesAgo);
      if (validRequests.length === 0) {
        this.botDetection.delete(key);
      } else {
        this.botDetection.set(key, validRequests);
      }
    }
    
    for (const [key, count] of this.suspiciousActivity.entries()) {
      if (Math.random() > 0.9) {
        this.suspiciousActivity.delete(key);
      }
    }
    
    for (const [ip, data] of this.fingerprints.entries()) {
      if (now - data.firstSeen > 86400000) {
        this.fingerprints.delete(ip);
      }
    }
  }
}

class InputValidator {
  static sanitizeText(input, maxLength = 1000) {
    if (typeof input !== 'string') return '';
    const escaped = validator.escape(input);
    const sanitized = xss(escaped, {
      whiteList: {},
      stripIgnoreTag: true,
      stripIgnoreTagBody: ['script']
    });
    return sanitized.substring(0, maxLength).trim();
  }

  static validatePrice(price) {
    const num = parseFloat(price);
    return !isNaN(num) && num > 0 && num < 99999.99;
  }

  static validateURL(url) {
    try {
      const urlObj = new URL(url);
      const allowedDomains = [
        'amazon.de', 'www.amazon.de',
        'amazon.com', 'www.amazon.com',
        'amazon.co.uk', 'www.amazon.co.uk',
        'amazon.fr', 'www.amazon.fr',
        'amazon.it', 'www.amazon.it',
        'amazon.es', 'www.amazon.es'
      ];
      return urlObj.protocol === 'https:' && allowedDomains.includes(urlObj.hostname.toLowerCase());
    } catch {
      return false;
    }
  }

static validateImageURL(url) {
  try {
    if (url.startsWith('/secure-image/')) return true;
    const urlObj = new URL(url);
    return urlObj.protocol === 'https:' &&
      (url.includes('telegram.org') ||
       url.includes('amazonaws.com') ||
       url.includes('cloudfront.net') ||
       /\.(jpg|jpeg|png|gif|webp)$/i.test(urlObj.pathname));
  } catch {
    return false;
  }
}

  static validateDealData(data) {
    const errors = [];
  
    if (!data.name || data.name.length < 5 || data.name.length > 100) {
      errors.push('Name must be 5-100 characters');
    }
  
    if (!data.description || data.description.length < 10 || data.description.length > 500) {
      errors.push('Description must be 10-500 characters');
    }
  
    if (!this.validatePrice(data.originalPrice)) {
      errors.push('Invalid original price');
    }
  
    if (!this.validatePrice(data.dealPrice)) {
      errors.push('Invalid deal price');
    }
  
    if (data.dealPrice >= data.originalPrice) {
      errors.push('Deal price must be lower than original price');
    }
  
const validCategories = [
        'elektronik', 'bücher', 'games', 'spielzeug', 'küche', 'Haushalt',
        'lebensmittel', 'drogerie', 'fashion', 'sport', 'auto', 
        'haustier', 'büro', 'multimedia', 'computer', 'gesundheit', 
        'werkzeuge', 'garten', 'musik', 'software'
    ];

if (!data.category || !validCategories.includes(data.category.toLowerCase())) {
    errors.push('Invalid category');
}
  
    if (!this.validateURL(data.amazonUrl)) {
      errors.push('Invalid Amazon URL');
    }
  
    if (!this.validateImageURL(data.imageUrl)) {
      errors.push('Invalid image URL');
    }

    if (data.coupon && data.coupon.length > 50) {
      errors.push('Coupon code must be less than 50 characters');
    }
  
    return errors;
  }
}


const security = new SecurityManager();

let deals = [];
let userSessions = new Map();
let serverProcess = null;

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "http:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use((req, res, next) => {
  if (security.detectBot(req)) {
    return res.status(403).send(generateErrorPage(
      "Access Denied", 
      "Automated requests are not allowed"
    ));
  }
  
  if (!security.validateFingerprint(req)) {
    return res.status(403).send(generateErrorPage(
      "Security Check Failed", 
      "Request validation failed"
    ));
  }

  
  next();
});

const redirectLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 50, 
  message: generateErrorPage("Rate Limit Exceeded", "Please wait before making more requests"),
  skip: (req) => security.isBlocked(req.ip),
  onLimitReached: (req) => {
    security.logSuspiciousActivity(req.ip, 'redirect_rate_limit');
  }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Too many API requests' },
  handler: (req, res) => {
    security.logSuspiciousActivity(req.ip, 'api_rate_limit');
    res.status(429).json({ error: 'Too many requests' });
  }
});
function generateErrorPage(title, description) {
  return `
    <!DOCTYPE html>
    <html lang="de">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title} - Rabatte&Deal&DE</title>
      <meta name="robots" content="noindex, nofollow">
      <style>
        body { 
          font-family: system-ui, -apple-system, sans-serif; 
          text-align: center; 
          padding: 50px; 
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          margin: 0;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .container {
          background: white;
          color: #333;
          padding: 3rem;
          border-radius: 16px;
          box-shadow: 0 20px 40px rgba(0,0,0,0.1);
          max-width: 500px;
        }
        .error { color: #e74c3c; margin-bottom: 1rem; }
        .btn { 
          display: inline-block; 
          margin-top: 1.5rem; 
          padding: 0.75rem 1.5rem; 
          background: #667eea; 
          color: white; 
          text-decoration: none; 
          border-radius: 8px; 
          font-weight: 500;
          transition: all 0.2s ease;
        }
        .btn:hover { background: #4f46e5; transform: translateY(-1px); }
        .security-info {
          margin-top: 2rem;
          font-size: 0.9rem;
          color: #666;
          padding: 1rem;
          background: #f8f9fa;
          border-radius: 8px;
        }
      </style>
      <script>
        document.addEventListener('keydown', function(e) {
          if (e.keyCode === 123 || 
              (e.ctrlKey && e.shiftKey && e.keyCode === 73) ||
              (e.ctrlKey && e.keyCode === 85) ||
              (e.ctrlKey && e.keyCode === 83)) {
            e.preventDefault();
            return false;
          }
        });
        
        document.addEventListener('contextmenu', function(e) {
          e.preventDefault();
          return false;
        });
      </script>
    </head>
    <body>
      <div class="container">
        <h1 class="error">${title}</h1>
        <p>${description}</p>
        <div class="security-info">
          🔒 Aus Sicherheitsgründen werden alle Zugriffe protokolliert und überwacht.
        </div>
        <a href="/" class="btn">← Zurück zur Startseite</a>
      </div>
    </body>
    </html>
  `;
}

app.set('trust proxy', 1);

app.use('/redirect', (req, res, next) => {
  res.setHeader('CF-Cache-Status', 'DYNAMIC');
  res.setHeader('CF-Ray', generateCloudflareRay());
  res.setHeader('Server', 'cloudflare');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

function generateCloudflareRay() {
  const chars = '0123456789abcdef';
  let ray = '';
  for (let i = 0; i < 16; i++) {
    ray += chars[Math.floor(Math.random() * chars.length)];
  }
  return ray + '-FRA';
}

async function loadDeals() {
  try {
    const snapshot = await dealsRef.once('value');
    const loadedDeals = snapshot.val() || {};
    
    deals = Object.values(loadedDeals).filter(deal => {
      try {
        return deal && deal.id && 
               deal.title && 
               deal.description &&
               deal.price > 0 &&
               deal.oldPrice > 0 &&
               deal.amazonUrl &&
               deal.imageUrl &&
               deal.category;
      } catch {
        return false;
      }
    }).map(deal => ({
      ...deal,
      title: InputValidator.sanitizeText(deal.title, 100),
      description: InputValidator.sanitizeText(deal.description, 500),
      category: InputValidator.sanitizeText(deal.category, 50).toLowerCase()
    }));
    
    console.log(`✅ Loaded ${deals.length} valid deals from Firebase`);
  } catch (error) {
    console.error("❌ Error loading deals from Firebase:", error);
    deals = [];
  }
}
async function saveDeals() {
  try {
    const validDeals = deals.filter(deal => {
      const errors = InputValidator.validateDealData({
        name: deal.title,
        description: deal.description,
        originalPrice: deal.oldPrice,
        dealPrice: deal.price,
        category: deal.category,
        amazonUrl: deal.amazonUrl,
        imageUrl: `/secure-image/${deal.id}`
      });
      return errors.length === 0;
    });
    
    if (validDeals.length !== deals.length) {
      console.warn(`⚠️ Removed ${deals.length - validDeals.length} invalid deals during save`);
      deals = validDeals;
    }
    const dealsObj = {};
    deals.forEach(deal => {
      dealsObj[deal.id] = deal;
    });
    
    await dealsRef.set(dealsObj);
    console.log(`💾 Saved ${deals.length} deals to Firebase`);
  } catch (error) {
    console.error("❌ Error saving deals to Firebase:", error);
    throw error;
  }
}

function generateDealId() {
  return Date.now().toString() + crypto.randomBytes(4).toString('hex');
}

function generateSlug(title) {
  const sanitized = InputValidator.sanitizeText(title)
    .toLowerCase()
    .trim()
    .replace(/[^a-z\s-]/gi, '')
    .replace(/[\s_-]+/g, ' ');

  const words = sanitized.split(' ').filter(word => word.length > 0);
  const firstTwoWords = words.slice(0, 2).join('-');
  
  return firstTwoWords.substring(0, 30);
}


function isAdmin(userId) {
  return ADMIN_IDS.includes(userId);
}

function createSecureSession(userId, action) {
  return {
    action,
    step: "name",
    data: {},
    completing: false,
    csrfToken: security.generateSecureToken(),
    createdAt: Date.now(),
    userId
  };
}

const adminKeyboard = {
  keyboard: [
    [{ text: "🛑 Stop Website" }, { text: "➕ Add Deal" }],
    [{ text: "🗑️ Delete Deal" }, { text: "✏️ Change Deal" }],
    [{ text: "📊 View Stats" }, { text: "📋 List All Deals" }],
    [{ text: "🔄 Restart Website" }, { text: "❌ Cancel" }],
  ],
  resize_keyboard: true,
  one_time_keyboard: false,
};

bot.onText(/\/start/, (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  if (!security.checkRateLimit(`bot_${userId}`, 10, 60000)) {
bot.sendMessage(chatId, "⏳ يرجى الانتظار قبل إرسال المزيد من الأوامر.")
    return;
  }

  if (!isAdmin(userId)) {
    security.logSuspiciousActivity(userId, 'unauthorized_access_attempt');
    bot.sendMessage(
    chatId,
    "❌ الوصول مرفوض. أنت غير مصرح لك باستخدام هذا البوت."
)

    return;
  }

  bot.sendMessage(
    chatId,
    "🔐 مرحبًا بك في لوحة تحكم Rabatte&Deal&DE!\n\n" +
    "اختر إجراءً من القائمة أدناه:",
    { reply_markup: adminKeyboard }
  );
});

const processedPhotos = new Set();
const MAX_PHOTOS = 50;

if (processedPhotos.size > MAX_PHOTOS) {
    const photosArray = Array.from(processedPhotos);
    processedPhotos.clear();
    photosArray.slice(-25).forEach(id => processedPhotos.add(id));
}


bot.on("photo", async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const session = userSessions.get(userId);

  if (!isAdmin(userId)) return;

  if (!security.checkRateLimit(`photo_${userId}`, 3, 60000)) {
    bot.sendMessage(chatId, "⏳ يرجى الانتظار قبل رفع المزيد من الصور.");
    return;
  }

  const photoId = msg.photo[msg.photo.length - 1].file_id;
  if (processedPhotos.has(photoId)) {
    return;
  }
  processedPhotos.add(photoId);

   if (session && session.action === "add_deal" && session.step === "photo") {
    try {
      const photo = msg.photo[msg.photo.length - 1];
      const fileId = photo.file_id;
      session.data.imageInfo = {
        file_id: fileId,
        file_unique_id: photo.file_unique_id,
        width: photo.width,
        height: photo.height,
        file_size: photo.file_size
      };
      session.data.imageUrl = `/secure-image/${fileId}`;
      
      await completeDealAdd(chatId, userId, session.data);
    } catch (error) {
      console.error("Error processing photo:", error);
      bot.sendMessage(chatId, "❌ حدث خطأ في معالجة الصورة. يرجى المحاولة مرة أخرى.");
    }
  }
});

bot.on("message", async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const text = msg.text;

  if (msg.photo || !text) {
    return;
  }

  if (msg.date && Date.now() / 1000 - msg.date > 30) {
    return;
  }

  if (!isAdmin(userId)) {
    security.logSuspiciousActivity(userId, 'unauthorized_message');
bot.sendMessage(chatId, "❌ الوصول مرفوض.")
    return;
  }

  if (!security.checkRateLimit(`msg_${userId}`, 20, 60000)) {
bot.sendMessage(chatId, "⏳ يرجى التمهل في إرسال الرسائل.")
    return;
  }

  const session = userSessions.get(userId);

  if (session) {
    if (session.completing || session.userId !== userId) {
      return;
    }
    
    await handleSessionMessage(chatId, userId, text, session);
    return;
  }

  switch (text) {
    case "🛑 Stop Website":
      await handleStopWebsite(chatId);
      break;
    case "➕ Add Deal":
      await startAddDeal(chatId, userId);
      break;
    case "🗑️ Delete Deal":
      await startDeleteDeal(chatId, userId);
      break;
    case "✏️ Change Deal":
      await startChangeDeal(chatId, userId);
      break;
    case "📊 View Stats":
      await showStats(chatId);
      break;
    case "📋 List All Deals":
      await listAllDeals(chatId);
      break;
    case "🔄 Restart Website":
      await handleRestartWebsite(chatId);
      break;
    case "❌ Cancel":
      userSessions.delete(userId);
      bot.sendMessage(chatId, "✅ تم إلغاء العملية.", {
        reply_markup: adminKeyboard,
      });
      break;
    default:
      if (!text.startsWith("/")) {
        bot.sendMessage(
          chatId,
          "❓ أمر غير معروف. يرجى استخدام أزرار القائمة.",
          { reply_markup: adminKeyboard }
        );
      }

  }
});

async function handleSessionMessage(chatId, userId, text, session) {
  switch (session.action) {
    case "add_deal":
      await handleAddDealSession(chatId, userId, text, session);
      break;
    case "delete_deal":
      await handleDeleteDealSession(chatId, userId, text, session);
      break;
    case "change_deal":
      await handleChangeDealSession(chatId, userId, text, session);
      break;
  }
}

async function startAddDeal(chatId, userId) {
  const session = createSecureSession(userId, "add_deal");
  userSessions.set(userId, session);

  bot.sendMessage(
    chatId,
"📝 إضافة عرض جديد...\n\nيرجى إدخال اسم العرض (5-100 حرف):"
  );
}

async function handleAddDealSession(chatId, userId, text, session) {
  const { step, data } = session;

  switch (step) {
    case "name":{
      const sanitizedName = InputValidator.sanitizeText(text, 100);
      if (sanitizedName.length < 5 || sanitizedName.length > 100) {
bot.sendMessage(chatId, "❌ يجب أن يكون اسم العرض بين 5 و 100 حرف:")
        return;}

      data.name = sanitizedName;
      session.step = "description";
      userSessions.set(userId, session);
bot.sendMessage(chatId, "✅ تم حفظ الاسم!\n\nالآن أدخل الوصف (10-500 حرف):")
      break;}

    case "description":{
      const sanitizedDesc = InputValidator.sanitizeText(text, 500);
      if (sanitizedDesc.length < 10 || sanitizedDesc.length > 500) {
bot.sendMessage(chatId, "❌ يجب أن يكون الوصف بين 10 و 500 حرف:")
        return;
      }
      data.description = sanitizedDesc;
      session.step = "original_price";
      userSessions.set(userId, session);
bot.sendMessage(chatId, "✅ تم حفظ الوصف!\n\nأدخل السعر الأصلي (مثلاً 99.99):")
      break;}

    case "original_price":{
      if (!InputValidator.validatePrice(text)) {
bot.sendMessage(chatId, "❌ يرجى إدخال سعر صالح (0.01 - 99999.99):")
        return;
      }
      data.originalPrice = parseFloat(text);
      session.step = "deal_price";
      userSessions.set(userId, session);
bot.sendMessage(chatId, "✅ تم حفظ السعر الأصلي!\n\nأدخل سعر العرض:")
      break;}

    case "deal_price":{
      if (!InputValidator.validatePrice(text)) {
bot.sendMessage(chatId, "❌ يرجى إدخال سعر صالح (0.01 - 99999.99):")
        return;
      }
      const dealPrice = parseFloat(text);
      if (dealPrice >= data.originalPrice) {
bot.sendMessage(chatId, "❌ يجب أن يكون سعر العرض أقل من السعر الأصلي:")
        return;
      }
      data.dealPrice = dealPrice;
      session.step = "coupon";
      userSessions.set(userId, session);
bot.sendMessage(chatId, "✅ تم حفظ سعر العرض!\n\nهل لديك رمز قسيمة لهذا العرض؟ أدخل رمز القسيمة أو اكتب 'no' إذا لا توجد قسيمة:");
      break;}

    case "coupon":{
      const couponText = InputValidator.sanitizeText(text, 50).trim();
      if (couponText.toLowerCase() === 'no' || couponText.toLowerCase() === 'nein') {
        data.coupon = null;
      } else {
        data.coupon = couponText;
      }
      session.step = "category";
      userSessions.set(userId, session);
      const validCategories = [
      'elektronik', 'bücher', 'games', 'spielzeug', 'küche', 
      'lebensmittel', 'drogerie', 'fashion', 'sport', 'auto', 
      'haustier', 'büro', 'multimedia', 'computer', 'gesundheit', 
      'werkzeuge', 'garten', 'musik', 'software','Haushalt'
  ]

      bot.sendMessage(
        chatId,
        `✅ تم ${data.coupon ? 'حفظ' : 'تخطي'} القسيمة!\n\n` +
        `أدخل التصنيف (واحد من هذه التصنيفات: ${validCategories.join(', ')}):`
      );

      break;}

    case "category":{
    const category = InputValidator.sanitizeText(text, 50).toLowerCase();
    const validCategories = [
        'elektronik', 'bücher', 'games', 'spielzeug', 'küche','Haushalt',
        'lebensmittel', 'drogerie', 'fashion', 'sport', 'auto', 
        'haustier', 'büro', 'multimedia', 'computer', 'gesundheit', 
        'werkzeuge', 'garten', 'musik', 'software'
    ];
    
    if (!validCategories.includes(category)) {
    bot.sendMessage(chatId, 
        "❌ يرجى إدخال تصنيف صالح:\n" +
        "elektronik, bücher, games, spielzeug, küche, lebensmittel, Haushalt, " +
        "drogerie, fashion, sport, auto, haustier, büro, multimedia, " +
        "computer, gesundheit, werkzeuge, garten, musik, software"
    );
    return;
}

    data.category = category;
    session.step = "amazon_url";
    userSessions.set(userId, session);
bot.sendMessage(chatId, "✅ تم حفظ التصنيف!\n\nأدخل رابط أمازون (يجب أن يكون HTTPS):");
    break;}

    case "amazon_url":{
      if (!InputValidator.validateURL(text)) {
bot.sendMessage(chatId, "❌ يرجى إدخال رابط أمازون HTTPS صالح من النطاقات المدعومة:");
        return;
      }
      data.amazonUrl = text;
      session.step = "photo";
      userSessions.set(userId, session);
bot.sendMessage(chatId, "✅ تم حفظ رابط أمازون!\n\nأرسل صورة أو أدخل رابط صورة HTTPS:");
      break;}

    case "photo": {
  if (session.completing) {
    return;
  }
  
  session.completing = true;
  userSessions.set(userId, session);

  if (text && InputValidator.validateImageURL(text)) {
    data.imageUrl = text;
    await completeDealAdd(chatId, userId, data);
  } else {
    session.completing = false;
    userSessions.set(userId, session);
    bot.sendMessage(chatId, "❌ يرجى إرسال صورة أو إدخال رابط صورة HTTPS صالح:");
  }
  break;
}
  }
}
async function completeDealAdd(chatId, userId, data) {
  try {
    console.log(`🔄 Starting deal completion for user ${userId}:`, {
      name: data.name,
      amazonUrl: data.amazonUrl,
      hasImageInfo: !!data.imageInfo
    });

    // Validate all deal data
    const validationErrors = InputValidator.validateDealData(data);
    if (validationErrors.length > 0) {
      console.error('❌ Validation failed:', validationErrors);
      throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
    }

    // Generate unique deal ID and slug
    const dealId = generateDealId();
    const slug = generateSlug(data.name);
    
    // Calculate discount percentage
    const discount = Math.round(
      ((data.originalPrice - data.dealPrice) / data.originalPrice) * 100
    );

    // Determine badge based on discount
    const badge = discount >= 70 ? "HOT" : discount >= 50 ? "FIRE" : discount >= 30 ? "DEAL" : "SAVE";

    // Set expiration time (24 hours from now)
    const expirationTime = Date.now() + (24 * 60 * 60 * 1000);

    // Generate random but realistic ratings and reviews
    const rating = (Math.random() * 1.5 + 3.5).toFixed(1); // 3.5 to 5.0
    const reviews = Math.floor(Math.random() * 2000) + 100; // 100 to 2100 reviews

    // Create the complete deal object
    const newDeal = {
      // Basic identifiers
      id: dealId,
      slug: slug,
      
      // Deal information
      title: data.name.trim(),
      description: data.description.trim(),
      
      // Pricing
      price: parseFloat(data.dealPrice),
      oldPrice: parseFloat(data.originalPrice),
      discount: discount,
      
      // Classification
      category: data.category.toLowerCase(),
      
      // URLs and media
      amazonUrl: data.amazonUrl,
      imageUrl: `/secure-image/${dealId}`,
      imageInfo: data.imageInfo || null,
      
      // Additional features
      coupon: data.coupon && data.coupon.trim() ? data.coupon.trim() : null,
      
      // Social proof
      rating: parseFloat(rating),
      reviews: reviews,
      
      // Status and timing
      timer: expirationTime,
      badge: badge,
      isActive: true,
      isFeatured: discount >= 60,
      
      // Metadata
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      createdBy: userId,
      
      // SEO and tracking
      views: 0,
      clicks: 0,
      
      // Additional fields for frontend
      currency: "EUR",
      availability: "In Stock",
      shipping: discount >= 50 ? "Free Shipping" : null
    };

    console.log(`✅ Created deal object:`, {
      id: newDeal.id,
      slug: newDeal.slug,
      title: newDeal.title,
      discount: newDeal.discount,
      badge: newDeal.badge,
      hasImageInfo: !!newDeal.imageInfo,
      expiresAt: new Date(newDeal.timer).toISOString()
    });

    // Save deal to Firebase
    await dealsRef.child(dealId).set(newDeal);
    console.log(`💾 Deal saved to Firebase successfully.`);
    
    // Clean up user session
    userSessions.delete(userId);

    // Generate deal URLs
    const dealUrl = `${WEBSITE_URL}/deal/${slug}`;
    const redirectUrl = `${WEBSITE_URL}/redirect/${dealId}`;
    const apiUrl = `${WEBSITE_URL}/api/deal/${slug}`;

    // Calculate savings
    const savings = (data.originalPrice - data.dealPrice).toFixed(2);
    const savingsPercent = discount;

    // Create success message
    const successMessage = `✅ Deal added successfully!\n\n` +
      `🆔 Deal ID: ${dealId}\n` +
      `📝 Name: ${data.name}\n` +
      `💰 Price: €${data.dealPrice} (was €${data.originalPrice})\n` +
      `💵 Savings: €${savings} (${savingsPercent}%)\n` +
      `🏷️ Badge: ${badge}\n` +
      `📂 Category: ${data.category}\n` +
      `🎫 Coupon: ${data.coupon || 'None'}\n` +
      `⭐ Rating: ${rating}/5.0 (${reviews} reviews)\n` +
      `⏰ Expires in: 24 hours\n` +
      `🚚 Shipping: ${newDeal.shipping || 'Standard'}\n\n` +
      `🔗 Deal Links:\n` +
      `📱 Homepage: ${dealUrl}\n` +
      `🔄 Redirect: ${redirectUrl}\n` +
      `🔧 API: ${apiUrl}\n\n` +
      `🛠️ To manage this deal:\n` +
      `• To edit: Use "✏️ Change Deal" with ID "${dealId}"\n` +
      `• To delete: Use "🗑️ Delete Deal" with ID "${dealId}"`;

    // Send success message
    await bot.sendMessage(chatId, successMessage, { 
      reply_markup: adminKeyboard,
      parse_mode: 'HTML'
    });

    // Log successful creation
    console.log(`🎉 Deal "${data.name}" (${dealId}) created successfully by admin ${userId}`);
    console.log(`🔗 Deal accessible at: ${dealUrl}`);
    console.log(`🛍️ Amazon redirect: ${data.amazonUrl}`);

    // Optional: Send a preview of the deal (if you want to show how it looks)
    try {
      const previewMessage = `📋 Deal Preview:\n\n` +
        `🛍️ ${newDeal.title}\n` +
        `💰 ${newDeal.price}€ ⚡ Instead of ${newDeal.oldPrice}€\n` +
        `🔥 Save ${savingsPercent}% • ${badge}\n` +
        `⭐ ${newDeal.rating}/5 (${newDeal.reviews} reviews)\n` +
        `📦 ${newDeal.category} • ${newDeal.availability}\n` +
        `${newDeal.coupon ? `🎫 Coupon Code: ${newDeal.coupon}\n` : ''}` +
        `${newDeal.shipping ? `🚚 ${newDeal.shipping}\n` : ''}` +
        `⏰ Expires in 24 hours`;

      await bot.sendMessage(chatId, previewMessage);
    } catch (previewError) {
      console.warn('⚠️ Could not send preview message:', previewError.message);
    }

  } catch (error) {
    console.error("❌ Error completing deal add:", error);
    
    // Clean up session on error
    userSessions.delete(userId);
    
    // Send detailed error message
    let errorMessage = "❌ Error saving deal:\n\n";
    
    if (error.message.includes('Validation failed')) {
      errorMessage += `🔍 Data validation error:\n${error.message.replace('Validation failed: ', '')}`;
    } else if (error.message.includes('permission')) {
      errorMessage += "🔒 Firebase permission denied. Check your rules.";
    } else if (error.message.includes('network') || error.message.includes('timeout')) {
      errorMessage += "🌐 Network error. Please try again.";
    } else {
      errorMessage += `⚠️ ${error.message}`;
    }
    
    errorMessage += "\n\nPlease try again or contact support.";
    
    await bot.sendMessage(chatId, errorMessage, { reply_markup: adminKeyboard });
  }
}

async function startDeleteDeal(chatId, userId) {
  try {
    const snapshot = await dealsRef.once('value');
    const allDeals = snapshot.val() || {};
    const dealsArray = Object.values(allDeals);
    
    if (dealsArray.length === 0) {
      bot.sendMessage(chatId, "❌ No deals available to delete.", {
        reply_markup: adminKeyboard,
      });
      return;
    }

    const session = createSecureSession(userId, "delete_deal");
    session.step = "select_id";
    userSessions.set(userId, session);

    let dealsList = "🗑️ Select a deal to delete:\n\n";
    const activeDeals = dealsArray.filter(deal => deal.timer > Date.now()).slice(0, 10);
    
    activeDeals.forEach((deal) => {
      dealsList += `🆔 ${deal.id}\n📝 ${deal.title.substring(0, 50)}...\n💰 €${deal.price}\n\n`;
    });

    if (dealsArray.length > 10) {
      dealsList += `... and ${dealsArray.length - 10} more deals\n\n`;
    }

    dealsList += "Enter the Deal ID to delete:";
    bot.sendMessage(chatId, dealsList);
  } catch (error) {
    console.error("❌ Error starting deal deletion:", error);
    bot.sendMessage(chatId, "❌ Error loading deals.", { reply_markup: adminKeyboard });
  }
}

async function handleDeleteDealSession(chatId, userId, text, session) {
  const dealId = InputValidator.sanitizeText(text, 50).trim();
  
  if (!/^[0-9a-f]{8,}$/i.test(dealId)) {
    bot.sendMessage(chatId, "❌ Invalid deal ID format. Please enter a valid deal ID:");
    return;
  }
  
  try {
    const snapshot = await dealsRef.child(dealId).once('value');
    const deal = snapshot.val();

    if (!deal) {
      bot.sendMessage(chatId, "❌ Deal not found. Please enter a valid deal ID:");
      return;
    }

    await dealsRef.child(dealId).remove();
    userSessions.delete(userId);

    bot.sendMessage(
      chatId,
      `✅ Deal deleted successfully!\n\n` +
      `🆔 Deleted Deal ID: ${dealId}\n` +
      `📝 Name: ${deal.title}`,
      { reply_markup: adminKeyboard }
    );

    console.log(`🗑️ Deal deleted by admin ${userId}: ${dealId}`);
  } catch (error) {
    console.error("❌ Error deleting deal:", error);
    bot.sendMessage(chatId, "❌ Error deleting deal.", { reply_markup: adminKeyboard });
  }
}

async function handleDeleteDealSession(chatId, userId, text, session) {
  const dealId = InputValidator.sanitizeText(text, 50).trim();
  
  if (!/^[0-9a-f]{8,}$/i.test(dealId)) {
bot.sendMessage(chatId, "❌ صيغة معرف العرض غير صحيحة. يرجى إدخال معرف عرض صالح:");
    return;
  }
  
  const dealIndex = deals.findIndex((deal) => deal.id === dealId);

  if (dealIndex === -1) {
bot.sendMessage(chatId, "❌ لم يتم العثور على العرض. يرجى إدخال معرف عرض صالح:");
    return;
  }

  const deletedDeal = deals.splice(dealIndex, 1)[0];
  await saveDeals();
  userSessions.delete(userId);

 bot.sendMessage(
  chatId,
  `✅ تم حذف العرض بنجاح!\n\n` +
  `🆔 معرف العرض المحذوف: ${dealId}\n` +
  `📝 الاسم: ${deletedDeal.title}`,
  { reply_markup: adminKeyboard }
);

console.log(`🗑️ تم حذف العرض بواسطة المدير ${userId}: ${dealId}`);
}

async function startChangeDeal(chatId, userId) {
  if (deals.length === 0) {
    bot.sendMessage(chatId, "❌ لا توجد عروض متاحة للتعديل.", {
      reply_markup: adminKeyboard,
    });
    return;
  }

  const session = createSecureSession(userId, "change_deal");
  session.step = "select_id";
  userSessions.set(userId, session);

  let dealsList = "✏️ اختر عرضًا للتعديل:\n\n";
  const activeDeals = deals.filter(deal => deal.timer > Date.now()).slice(0, 10);

  activeDeals.forEach((deal) => {
    dealsList += `🆔 ${deal.id}\n📝 ${deal.title.substring(0, 50)}...\n💰 €${deal.price}\n\n`;
  });

  if (deals.length > 10) {
    dealsList += `... و ${deals.length - 10} عروض أخرى\n\n`;
  }

  dealsList += "أدخل معرف العرض للتعديل:";
  bot.sendMessage(chatId, dealsList);
}

async function handleChangeDealSession(chatId, userId, text, session) {
 if (session.step === "select_id") {
   const dealId = InputValidator.sanitizeText(text, 50).trim();
   
   if (!/^[0-9a-f]{8,}$/i.test(dealId)) {
     bot.sendMessage(chatId, "❌ Invalid deal ID format. Please enter a valid deal ID:");
     return;
   }

   try {
     const snapshot = await dealsRef.child(dealId).once('value');
     const deal = snapshot.val();

     if (!deal) {
       bot.sendMessage(chatId, "❌ Deal not found. Please enter a valid deal ID:");
       return;
     }

     session.dealId = dealId;
     session.step = "select_field";
     userSessions.set(userId, session);

     const fieldKeyboard = {
       keyboard: [
         [{ text: "Name" }, { text: "Description" }],
         [{ text: "Price" }, { text: "Original Price" }],
         [{ text: "Category" }, { text: "Amazon URL" }],
         [{ text: "❌ Cancel" }],
       ],
       resize_keyboard: true,
       one_time_keyboard: true,
     };

     bot.sendMessage(
       chatId,
       `✏️ Editing deal: ${deal.title}\n\nWhich field would you like to change?`,
       { reply_markup: fieldKeyboard }
     );
   } catch (error) {
     console.error("❌ Error fetching deal:", error);
     bot.sendMessage(chatId, "❌ Error loading deal information.", { reply_markup: adminKeyboard });
   }
 } else if (session.step === "select_field") {
   const field = InputValidator.sanitizeText(text, 20).toLowerCase();
   session.field = field;
   session.step = "enter_value";
   userSessions.set(userId, session);

   let prompt = `✏️ Enter the new ${field}:`;
   if (field === "name") {
     prompt += "\n(5-100 characters)";
   } else if (field === "description") {
     prompt += "\n(10-500 characters)";
   } else if (field.includes("price")) {
     prompt += "\n(0.01 - 99999.99)";
   } else if (field === "amazon url") {
     prompt += "\n(Must be HTTPS Amazon URL)";
   }

   bot.sendMessage(chatId, prompt);
 } else if (session.step === "enter_value") {
   try {
     const dealId = session.dealId;
     const snapshot = await dealsRef.child(dealId).once('value');
     const deal = snapshot.val();
     
     if (!deal) {
       bot.sendMessage(chatId, "❌ Deal no longer exists.", { reply_markup: adminKeyboard });
       userSessions.delete(userId);
       return;
     }

     const field = session.field;
     let updateValue = text;
     let isValid = true;
     let errorMessage = "";
     const updates = {};

     switch (field) {
       case "name":{
         updateValue = InputValidator.sanitizeText(text, 100);
         if (updateValue.length < 5 || updateValue.length > 100) {
           isValid = false;
           errorMessage = "Name must be 5-100 characters long";
         } else {
           updates.title = updateValue;
           updates.slug = generateSlug(updateValue);
         }
         break;}
         
       case "description":{
         updateValue = InputValidator.sanitizeText(text, 500);
         if (updateValue.length < 10 || updateValue.length > 500) {
           isValid = false;
           errorMessage = "Description must be 10-500 characters long";
         } else {
           updates.description = updateValue;
         }
         break;}
         
       case "price":{
         if (!InputValidator.validatePrice(text)) {
           isValid = false;
           errorMessage = "Please enter a valid price (0.01 - 99999.99)";
         } else {
           const newPrice = parseFloat(text);
           if (newPrice >= deal.oldPrice) {
             isValid = false;
             errorMessage = "Deal price must be lower than original price";
           } else {
             updates.price = newPrice;
           }
         }
         break;}
         
       case "original price":{
         if (!InputValidator.validatePrice(text)) {
           isValid = false;
           errorMessage = "Please enter a valid price (0.01 - 99999.99)";
         } else {
           const newOriginalPrice = parseFloat(text);
           if (newOriginalPrice <= deal.price) {
             isValid = false;
             errorMessage = "Original price must be higher than deal price";
           } else {
             updates.oldPrice = newOriginalPrice;
           }
         }
         break;}
         
       case "category":{
         const category = InputValidator.sanitizeText(text, 50).toLowerCase();
         const validCategories = [
             'elektronik', 'bücher', 'games', 'spielzeug', 'küche', 'Haushalt',
             'lebensmittel', 'drogerie', 'fashion', 'sport', 'auto', 
             'haustier', 'büro', 'multimedia', 'computer', 'gesundheit', 
             'werkzeuge', 'garten', 'musik', 'software'
         ];
         
         if (!validCategories.includes(category)) {
             isValid = false;
             errorMessage = "Please enter a valid category: " + validCategories.join(', ');
         } else {
             updates.category = category;
         }
         break;}
         
       case "amazon url":{
         if (!InputValidator.validateURL(text)) {
           isValid = false;
           errorMessage = "Please enter a valid HTTPS Amazon URL";
         } else {
           updates.amazonUrl = text;
         }
         break;}
         
       default:
         isValid = false;
         errorMessage = "Invalid field selected";
     }

     if (!isValid) {
       bot.sendMessage(chatId, `❌ ${errorMessage}:`);
       return;
     }

     if (field === "price" || field === "original price") {
       const newPrice = updates.price || deal.price;
       const newOriginalPrice = updates.oldPrice || deal.oldPrice;
       updates.discount = Math.round(((newOriginalPrice - newPrice) / newOriginalPrice) * 100);
       updates.badge = updates.discount > 50 ? "HOT" : "DEAL";
     }

     updates.updatedAt = new Date().toISOString();
     
     await dealsRef.child(dealId).update(updates);
     userSessions.delete(userId);

     const updatedDeal = { ...deal, ...updates };
     const dealUrl = `${WEBSITE_URL}/deal/${updatedDeal.slug}`;

     bot.sendMessage(
       chatId,
       `✅ Deal updated successfully!\n\n` +
       `🆔 Deal ID: ${dealId}\n` +
       `📝 Name: ${updatedDeal.title}\n` +
       `💰 Price: €${updatedDeal.price} (was €${updatedDeal.oldPrice})\n` +
       `🏷️ Discount: ${updatedDeal.discount}%\n` +
       `📂 Category: ${updatedDeal.category}\n\n` +
       `🔗 Deal URL: ${dealUrl}`,
       { reply_markup: adminKeyboard }
     );

   } catch (error) {
     console.error("❌ Error updating deal:", error);
     bot.sendMessage(chatId, `❌ Error updating deal: ${error.message}`);
     userSessions.delete(userId);
   }
 }
}

async function showStats(chatId) {
  try {
    const now = Date.now();
    const snapshot = await dealsRef.once('value');
    const allDeals = snapshot.val() || {};
    const dealsArray = Object.values(allDeals);
    
    const activeDeals = dealsArray.filter(deal => deal.timer > now);
    const expiredDeals = dealsArray.filter(deal => deal.timer <= now);
    
    const categories = {};
    activeDeals.forEach(deal => {
      categories[deal.category] = (categories[deal.category] || 0) + 1;
    });

    const totalSavings = activeDeals.reduce((sum, deal) => {
      return sum + (deal.oldPrice - deal.price);
    }, 0);

    const avgDiscount = activeDeals.length > 0 
      ? activeDeals.reduce((sum, deal) => sum + deal.discount, 0) / activeDeals.length 
      : 0;

    let statsMessage = `📊 Website Statistics\n\n`;
    statsMessage += `📈 Active Deals: ${activeDeals.length}\n`;
    statsMessage += `📉 Expired Deals: ${expiredDeals.length}\n`;
    statsMessage += `💰 Total Savings: €${totalSavings.toFixed(2)}\n`;
    statsMessage += `📊 Average Discount: ${avgDiscount.toFixed(1)}%\n\n`;
    
    statsMessage += `📂 Categories:\n`;
    Object.entries(categories).forEach(([category, count]) => {
      statsMessage += `  • ${category}: ${count} deals\n`;
    });

    const blockedIPs = security.blockedIPs.size;
    const suspiciousActivities = security.suspiciousActivity.size;
    
    statsMessage += `\n🔒 Security:\n`;
    statsMessage += `  • Blocked IPs: ${blockedIPs}\n`;
    statsMessage += `  • Suspicious Activities: ${suspiciousActivities}\n`;

    bot.sendMessage(chatId, statsMessage, { reply_markup: adminKeyboard });
  } catch (error) {
    console.error("❌ Error showing stats:", error);
    bot.sendMessage(chatId, "❌ Error retrieving statistics.", { reply_markup: adminKeyboard });
  }
}

async function listAllDeals(chatId) {
  try {
    const snapshot = await dealsRef.once('value');
    const allDeals = snapshot.val() || {};
    const dealsArray = Object.values(allDeals);
    
    if (dealsArray.length === 0) {
      bot.sendMessage(chatId, "❌ No deals available.", { reply_markup: adminKeyboard });
      return;
    }

    const now = Date.now();
    const activeDeals = dealsArray.filter(deal => deal.timer > now);
    const expiredDeals = dealsArray.filter(deal => deal.timer <= now);

    let message = `📋 All Deals (${dealsArray.length} total)\n\n`;
    
    if (activeDeals.length > 0) {
      message += `✅ Active Deals (${activeDeals.length}):\n`;
      activeDeals.slice(0, 5).forEach(deal => {
        const timeLeft = Math.ceil((deal.timer - now) / (1000 * 60 * 60));
        message += `🆔 ${deal.id}\n`;
        message += `📝 ${deal.title.substring(0, 40)}...\n`;
        message += `💰 €${deal.price} (${deal.discount}% off)\n`;
        message += `⏰ ${timeLeft}h left\n\n`;
      });
      
      if (activeDeals.length > 5) {
        message += `... and ${activeDeals.length - 5} more active deals\n\n`;
      }
    }

    if (expiredDeals.length > 0) {
      message += `❌ Expired Deals (${expiredDeals.length}):\n`;
      expiredDeals.slice(0, 3).forEach(deal => {
        message += `🆔 ${deal.id} - ${deal.title.substring(0, 30)}...\n`;
      });
      
      if (expiredDeals.length > 3) {
        message += `... and ${expiredDeals.length - 3} more expired deals\n`;
      }
    }

    bot.sendMessage(chatId, message, { reply_markup: adminKeyboard });
  } catch (error) {
    console.error("❌ Error listing deals:", error);
    bot.sendMessage(chatId, "❌ Error retrieving deals list.", { reply_markup: adminKeyboard });
  }
}


async function handleStopWebsite(chatId) {
  try {
    if (serverProcess) {
      serverProcess.kill('SIGTERM');
      serverProcess = null;
      bot.sendMessage(chatId, "🛑 Website stopped successfully!", { reply_markup: adminKeyboard });
      console.log("🛑 Website stopped by admin");
    } else {
      bot.sendMessage(chatId, "⚠️ Website is not currently running.", { reply_markup: adminKeyboard });
    }
  } catch (error) {
    console.error("❌ Error stopping website:", error);
    bot.sendMessage(chatId, "❌ Error stopping website.", { reply_markup: adminKeyboard });
  }
}

async function handleRestartWebsite(chatId) {
  try {
    if (serverProcess) {
      serverProcess.kill('SIGTERM');
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    await startWebsite();
    bot.sendMessage(chatId, "🔄 Website restarted successfully!", { reply_markup: adminKeyboard });
    console.log("🔄 Website restarted by admin");
  } catch (error) {
    console.error("❌ Error restarting website:", error);
    bot.sendMessage(chatId, "❌ Error restarting website.", { reply_markup: adminKeyboard });
  }
}
app.get('/api/deals', apiLimiter, async (req, res) => {
  try {
    const now = Date.now();
    const snapshot = await dealsRef.once('value');
    const allDeals = snapshot.val() || {};
    
    const activeDeals = Object.values(allDeals)
      .filter(deal => deal.timer > now)
      .map(deal => ({
        id: deal.id,
        slug: deal.slug,
        title: deal.title,
        description: deal.description,
        price: deal.price,
        oldPrice: deal.oldPrice,
        discount: deal.discount,
        category: deal.category,
        imageUrl: `/secure-image/${deal.id}`,
        coupon: deal.coupon || null,
        rating: deal.rating || 4.5,
        reviews: deal.reviews || Math.floor(Math.random() * 1000) + 100,
        timer: deal.timer,
        badge: deal.badge || (deal.discount > 50 ? "HOT" : "DEAL"),
        createdAt: deal.createdAt
      }));
    
    res.setHeader('Cache-Control', 'public, max-age=300'); 
    res.json(activeDeals);
  } catch (error) {
    console.error("❌ Error serving deals API:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/redirect/:dealId', redirectLimiter, async (req, res) => {
  try {
    const dealId = InputValidator.sanitizeText(req.params.dealId, 50);
    
    if (!dealId || !/^[0-9a-f]{8,}$/i.test(dealId)) {
      return res.status(400).send(generateErrorPage(
        "Invalid Deal ID",
        "The deal ID format is invalid"
      ));
    }

    const snapshot = await dealsRef.child(dealId).once('value');
    const deal = snapshot.val();
    
    if (!deal) {
      return res.status(404).send(generateErrorPage(
        "Deal Not Found",
        "The requested deal could not be found"
      ));
    }

    if (deal.timer <= Date.now()) {
      return res.status(410).send(generateErrorPage(
        "Deal Expired",
        "This deal has expired and is no longer available"
      ));
    }

    if (!InputValidator.validateURL(deal.amazonUrl)) {
      return res.status(400).send(generateErrorPage(
        "Invalid Deal URL",
        "The deal URL is invalid or unsafe"
      ));
    }

    console.log(`🔗 Redirect to deal ${dealId} from IP ${req.ip}`);
    
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    res.setHeader('Referrer-Policy', 'no-referrer');
    
    res.redirect(302, deal.amazonUrl);
  } catch (error) {
    console.error("❌ Error handling redirect:", error);
    res.status(500).send(generateErrorPage(
      "Server Error",
      "An error occurred while processing your request"
    ));
  }
});
app.get('/deal/:slug', async (req, res) => {
  try {
    const slug = InputValidator.sanitizeText(req.params.slug, 100);
    
    if (!slug || slug.length < 3) {
      return res.status(400).send(generateErrorPage(
        "Invalid Deal URL", 
        "The deal URL format is invalid"
      ));
    }

    const snapshot = await dealsRef.once('value');
    const allDeals = snapshot.val() || {};
    
    let deal = Object.values(allDeals).find(d => d.slug === slug);
    
    // If not found, try partial slug match
    if (!deal) {
      deal = Object.values(allDeals).find(d => 
        slug.startsWith(d.slug) || d.slug.startsWith(slug)
      );
    }
    
    // Last resort: check if slug contains a deal ID
    if (!deal) {
      const slugParts = slug.split('-');
      for (const part of slugParts) {
        if (/^[0-9a-f]{8,}$/i.test(part)) {
          deal = allDeals[part];
          if (deal) break;
        }
      }
    }
    
    if (!deal) {
      console.warn(`🔍 Deal not found for slug: ${slug}`);
      return res.status(404).send(generateErrorPage(
        "Deal Not Found", 
        "The requested deal could not be found"
      ));
    }

    if (deal.timer <= Date.now()) {
      return res.status(410).send(generateErrorPage(
        "Deal Expired", 
        "This deal has expired and is no longer available"
      ));
    }

    if (!InputValidator.validateURL(deal.amazonUrl)) {
      return res.status(400).send(generateErrorPage(
        "Invalid Deal URL", 
        "The deal URL is invalid or unsafe"
      ));
    }

    console.log(`🔗 Redirecting to Amazon for deal "${deal.title}" (ID: ${deal.id}, Slug: ${deal.slug}) from IP ${req.ip}`);
    console.log(`🔗 Amazon URL: ${deal.amazonUrl}`);
    
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('CF-Cache-Status', 'DYNAMIC');
    res.setHeader('CF-Ray', generateCloudflareRay());
    res.setHeader('Server', 'cloudflare');
    
    res.redirect(302, deal.amazonUrl);
    
  } catch (error) {
    console.error("❌ Error handling deal redirect:", error);
    res.status(500).send(generateErrorPage(
      "Server Error", 
      "An error occurred while processing your request"
    ));
  }
});

app.get('/api/deal/:slug', apiLimiter, async (req, res) => {
  try {
    const slug = InputValidator.sanitizeText(req.params.slug, 100);
    
    if (!slug || slug.length < 3) {
      return res.status(400).json({ error: 'Invalid deal slug format' });
    }

    const snapshot = await dealsRef.once('value');
    const allDeals = snapshot.val() || {};
    
    const deal = Object.values(allDeals).find(d => d.slug === slug);
    
    if (!deal) {
      return res.status(404).json({ error: 'Deal not found' });
    }

    if (deal.timer <= Date.now()) {
      return res.status(410).json({ error: 'Deal expired' });
    }

    const publicDeal = {
      id: deal.id,
      slug: deal.slug,
      title: deal.title,
      description: deal.description,
      price: deal.price,
      oldPrice: deal.oldPrice,
      discount: deal.discount,
      category: deal.category,
      imageUrl: `/secure-image/${deal.id}`,
      coupon: deal.coupon,
      rating: deal.rating,
      reviews: deal.reviews,
      badge: deal.badge,
      timer: deal.timer,
      createdAt: deal.createdAt
    };

    res.json(publicDeal);
  } catch (error) {
    console.error("❌ Error serving individual deal API:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.use((req, res, next) => {
  const blockedFiles = [
    '/deals.json',
    '/bot.js',
    '/package.json',
    '/package-lock.json',
    '/.env',
    '/node_modules',
    '/config.json',
    '/logs',
    '/uploads'
  ];
  
  const blockedExtensions = ['.json', '.js', '.env', '.log', '.config'];
  const requestPath = req.path.toLowerCase();
  
  if (blockedFiles.some(file => requestPath === file || requestPath.startsWith(file))) {
    console.warn(`🚫 Blocked access to sensitive file: ${req.path} from IP: ${req.ip}`);
    security.logSuspiciousActivity(req.ip, 'sensitive_file_access');
    return res.status(403).send(generateErrorPage(
      "Access Denied",
      "This resource is not publicly available"
    ));
  }
  
  const allowedPaths = ['/api/', '/redirect/', '/deal/'];
  const isAllowedPath = allowedPaths.some(path => requestPath.startsWith(path));
  
  if (!isAllowedPath && blockedExtensions.some(ext => requestPath.endsWith(ext))) {
    console.warn(`🚫 Blocked access to file with sensitive extension: ${req.path} from IP: ${req.ip}`);
    security.logSuspiciousActivity(req.ip, 'sensitive_extension_access');
    return res.status(403).send(generateErrorPage(
      "Access Denied", 
      "This file type is not publicly accessible"
    ));
  }
  
  next();
});

app.get('/secure-image/:id', async (req, res) => {
  try {
    const requestedId = req.params.id;
    
    const snapshot = await dealsRef.child(requestedId).once('value');
    let deal = snapshot.val();
    
    if (!deal) {
      const allDealsSnapshot = await dealsRef.once('value');
      const allDeals = allDealsSnapshot.val() || {};
      
      deal = Object.values(allDeals).find(d => 
        d.imageInfo && d.imageInfo.file_id === requestedId
      );
    }
    
    if (!deal) {
      console.warn(`🖼️ Image not found for ID: ${requestedId}`);
      return res.redirect('https://via.placeholder.com/300?text=Image+Not+Available');
    }

    if (deal.imageInfo && deal.imageInfo.file_id) {
      const fileId = deal.imageInfo.file_id;
      
      try {
        const fileInfo = await bot.getFile(fileId);
        const filePath = fileInfo.file_path;
        const telegramUrl = `https://api.telegram.org/file/bot${BOT_TOKEN}/${filePath}`;
        
        const response = await axios({
          method: 'get',
          url: telegramUrl,
          responseType: 'stream',
          timeout: 10000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; ImageBot/1.0)'
          }
        });

        res.set({
          'Content-Type': response.headers['content-type'] || 'image/jpeg',
          'Cache-Control': 'public, max-age=86400',
          'Access-Control-Allow-Origin': '*'
        });

        response.data.pipe(res);
        return;
      } catch (telegramError) {
        console.error('Telegram image error:', telegramError);
      }
    }

    if (deal.imageUrl && deal.imageUrl.startsWith('http')) {
      return res.redirect(deal.imageUrl);
    }

    return res.redirect('https://via.placeholder.com/300?text=Image+Not+Available');
    
    } catch (error) {
    console.error('Image proxy error:', error);
    res.redirect('https://via.placeholder.com/300?text=Image+Not+Available');
  }
});

app.use(express.static('public', {
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) {
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'no-referrer');
    }
  },
  dotfiles: 'deny',
  index: ['index.html']
}));
app.use((err, req, res, next) => {
  console.error("❌ Unhandled error:", err);
  security.logSuspiciousActivity(req.ip, 'server_error');
  res.status(500).send(generateErrorPage(
    "Server Error", 
    "An unexpected error occurred"
  ));
});

app.use((req, res) => {
  security.logSuspiciousActivity(req.ip, '404_request');
  res.status(404).send(generateErrorPage(
    "Page Not Found", 
    "The requested page could not be found"
  ));
});

async function startWebsite() {
  try {
    await loadDeals();
    
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Website running on port ${PORT}`);
      console.log(`🔗 Access at: http://localhost:${PORT}`);
      console.log(`🔒 Security features enabled`);
    });

    process.on('SIGTERM', () => {
      console.log('🛑 Received SIGTERM, shutting down gracefully');
      server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
      });
    });

    return server;
  } catch (error) {
    console.error("❌ Error starting website:", error);
    throw error;
  }
}

bot.on('error', (error) => {
  console.error('❌ Telegram bot error:', error);
});

bot.on('polling_error', (error) => {
  console.error('❌ Telegram polling error:', error);
});

if (require.main === module) {
  startWebsite().catch(error => {
    console.error("❌ Failed to start application:", error);
    process.exit(1);
  });
}


module.exports = { app, startWebsite, security };
