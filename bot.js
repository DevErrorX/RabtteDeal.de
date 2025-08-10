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

// Load environment variables
require('dotenv').config();

// Validate required environment variables
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
    this.cleanupInterval = setInterval(() => this.cleanup(), 300000); // 5 minutes
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
      this.blockIdentifier(identifier, 600000); // 10 minutes
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
    const recentRequests = requests.filter(time => now - time < 10000); // 10 seconds
    
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

    // Validate coupon (optional field)
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
  max: 50, // 50 redirects per minute
  message: generateErrorPage("Rate Limit Exceeded", "Please wait before making more requests"),
  skip: (req) => security.isBlocked(req.ip),
  onLimitReached: (req) => {
    security.logSuspiciousActivity(req.ip, 'redirect_rate_limit');
  }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60, // 60 API requests per minute
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
    const data = await fs.readFile("deals.json", "utf8");
    const loadedDeals = JSON.parse(data);
    
    deals = loadedDeals.filter(deal => {
      try {
        return deal.id && 
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
    
    console.log(`✅ Loaded ${deals.length} valid deals`);
  } catch (error) {
    console.log("⚠️ No existing deals file found or invalid format, starting with empty array");
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
        imageUrl: deal.imageUrl
      });
      return errors.length === 0;
    });
    
    if (validDeals.length !== deals.length) {
      console.warn(`⚠️ Removed ${deals.length - validDeals.length} invalid deals during save`);
      deals = validDeals;
    }
    
    const dealsData = JSON.stringify(deals, null, 2);
    await fs.writeFile("deals.json", dealsData, { mode: 0o600 });
    console.log(`💾 Saved ${deals.length} deals securely`);
  } catch (error) {
    console.error("❌ Error saving deals:", error);
    throw error;
  }
}

function generateDealId() {
  return Date.now().toString() + crypto.randomBytes(4).toString('hex');
}

function generateSlug(title) {
  return InputValidator.sanitizeText(title)
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .substring(0, 50);
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
bot.sendMessage(chatId, "⏳ يرجى الانتظار قبل رفع المزيد من الصور.")
    return;
  }

  const photoId = msg.photo[msg.photo.length - 1].file_id;
  if (processedPhotos.has(photoId)) {
    return;
  }
  processedPhotos.add(photoId);

  if (processedPhotos.size > 50) {
    const photosArray = Array.from(processedPhotos);
    processedPhotos.clear();
    photosArray.slice(-25).forEach(id => processedPhotos.add(id));
  }

  if (session && session.action === "add_deal" && session.step === "photo") {
    if (session.completing || session.userId !== userId) {
      return;
    }
    
    session.completing = true;
    userSessions.set(userId, session);

    try {
      const file = await bot.getFile(photoId);
      const imageUrl = `https://api.telegram.org/file/bot${BOT_TOKEN}/${file.file_path}`;

      if (!InputValidator.validateImageURL(imageUrl)) {
        throw new Error('Invalid image URL');
      }

      session.data.imageUrl = imageUrl;
      await completeDealAdd(chatId, userId, session.data);
    } catch (error) {
      console.error("❌ Error processing photo:", error);
      session.completing = false;
      userSessions.set(userId, session);
bot.sendMessage(chatId, "❌ خطأ في معالجة الصورة. يرجى المحاولة مرة أخرى أو إدخال رابط صورة.")
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
      bot.sendMessage(chatId, "✅ Deal price saved!\n\nDo you have a coupon code for this deal? Enter the coupon code or type 'no' if there's no coupon:");
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
validCategories = [
    'elektronik', 'bücher', 'games', 'spielzeug', 'küche', 
    'lebensmittel', 'drogerie', 'fashion', 'sport', 'auto', 
    'haustier', 'büro', 'multimedia', 'computer', 'gesundheit', 
    'werkzeuge', 'garten', 'musik', 'software'
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

    case "photo":{
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
      break;}
  }
}

async function completeDealAdd(chatId, userId, data) {
  try {
    const validationErrors = InputValidator.validateDealData(data);
    if (validationErrors.length > 0) {
      throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
    }

    const dealId = generateDealId();
    const slug = generateSlug(data.name);
    const discount = Math.round(
      ((data.originalPrice - data.dealPrice) / data.originalPrice) * 100
    );

    const newDeal = {
      id: dealId,
      slug: slug,
      title: data.name,
      description: data.description,
      price: data.dealPrice,
      oldPrice: data.originalPrice,
      discount: discount,
      category: data.category,
      amazonUrl: data.amazonUrl,
      imageUrl: data.imageUrl,
      coupon: data.coupon || null, // Add coupon field
      rating: 4.5,
      reviews: Math.floor(Math.random() * 1000) + 100,
      timer: Date.now() + 24 * 60 * 60 * 1000,
      badge: discount > 50 ? "HOT" : "DEAL",
      createdAt: new Date().toISOString(),
      createdBy: userId,
    };

    deals.push(newDeal);
    await saveDeals();

    userSessions.delete(userId);

    const dealUrl = `${WEBSITE_URL}/deal/${slug}-${dealId}`;

bot.sendMessage(
  chatId,
  `✅ تم إضافة العرض بنجاح!\n\n` +
  `🆔 معرف العرض: ${dealId}\n` +
  `📝 الاسم: ${data.name}\n` +
  `💰 السعر: €${data.dealPrice} (كان €${data.originalPrice})\n` +
  `🏷️ الخصم: ${discount}%\n` +
  `📂 التصنيف: ${data.category}\n` +
  `🎫 القسيمة: ${data.coupon || 'لا يوجد'}\n\n` +
  `🔗 رابط العرض: ${dealUrl}\n\n` +
  `استخدم المعرف "${dealId}" لتعديل أو حذف هذا العرض.`,
  { reply_markup: adminKeyboard }
);

  } catch (error) {
    console.error("❌ Error completing deal add:", error);
bot.sendMessage(chatId, `❌ حدث خطأ أثناء حفظ العرض: ${error.message}. يرجى المحاولة مرة أخرى.`);
    userSessions.delete(userId);
  }
}

async function startDeleteDeal(chatId, userId) {
  if (deals.length === 0) {
bot.sendMessage(chatId, "❌ لا توجد عروض متاحة للحذف.", {
      reply_markup: adminKeyboard,
    });
    return;
  }

  const session = createSecureSession(userId, "delete_deal");
  session.step = "select_id";
  userSessions.set(userId, session);

  let dealsList = "🗑️ Select a deal to delete:\n\n";
  const activeDeals = deals.filter(deal => deal.timer > Date.now()).slice(0, 10);
  
  activeDeals.forEach((deal) => {
    dealsList += `🆔 ${deal.id}\n📝 ${deal.title.substring(0, 50)}...\n💰 €${deal.price}\n\n`;
  });

  if (deals.length > 10) {
    dealsList += `... and ${deals.length - 10} more deals\n\n`;
  }

  dealsList += "Enter the Deal ID to delete:";
  bot.sendMessage(chatId, dealsList);
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
     bot.sendMessage(chatId, "❌ صيغة معرف العرض غير صحيحة. يرجى إدخال معرف عرض صالح:");
     return;
   }
const deal = deals.find((d) => d.id === dealId);

if (!deal) {
  bot.sendMessage(chatId, "❌ لم يتم العثور على العرض. يرجى إدخال معرف عرض صالح:");
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
`✏️ تعديل العرض: ${deal.title}\n\nأي حقل تريد تغييره؟`,
     { reply_markup: fieldKeyboard }
   );
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
   const deal = deals.find((d) => d.id === session.dealId);
   const field = session.field;
   let updateValue = text;
   let isValid = true;
   let errorMessage = "";

   switch (field) {
     case "name":{
       updateValue = InputValidator.sanitizeText(text, 100);
       if (updateValue.length < 5 || updateValue.length > 100) {
         isValid = false;
         errorMessage = "Name must be 5-100 characters long";
       } else {
         deal.title = updateValue;
         deal.slug = generateSlug(updateValue);
       }
       break;}
       
     case "description":{
       updateValue = InputValidator.sanitizeText(text, 500);
       if (updateValue.length < 10 || updateValue.length > 500) {
         isValid = false;
         errorMessage = "Description must be 10-500 characters long";
       } else {
         deal.description = updateValue;
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
           deal.price = newPrice;
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
           deal.oldPrice = newOriginalPrice;
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
        deal.category = category;
    }
    break;}
       
     case "amazon url":{
       if (!InputValidator.validateURL(text)) {
         isValid = false;
         errorMessage = "Please enter a valid HTTPS Amazon URL";
       } else {
         deal.amazonUrl = text;
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
     deal.discount = Math.round(
       ((deal.oldPrice - deal.price) / deal.oldPrice) * 100
     );
     deal.badge = deal.discount > 50 ? "HOT" : "DEAL";
   }

   try {
     await saveDeals();
     userSessions.delete(userId);

     const dealUrl = `${WEBSITE_URL}/deal/${deal.slug}-${deal.id}`;

     bot.sendMessage(
       chatId,
       `✅ تم تحديث العرض بنجاح!\n\n` +
`🆔 معرف العرض: ${deal.id}\n` +
`📝 الاسم: ${deal.title}\n` +
`💰 السعر: €${deal.price} (كان €${deal.oldPrice})\n` +
`🏷️ الخصم: ${deal.discount}%\n` +
`📂 التصنيف: ${deal.category}\n\n` +
`🔗 رابط العرض: ${dealUrl}`,

       { reply_markup: adminKeyboard }
     );

   } catch (error) {
     console.error("❌ Error updating deal:", error);
bot.sendMessage(chatId, `❌ حدث خطأ أثناء تحديث العرض: ${error.message}`);
     userSessions.delete(userId);
   }
 }
}

async function showStats(chatId) {
  try {
    const now = Date.now();
    const activeDeals = deals.filter(deal => deal.timer > now);
    const expiredDeals = deals.filter(deal => deal.timer <= now);
    
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
    if (deals.length === 0) {
bot.sendMessage(chatId, "❌ لا توجد عروض متاحة.", { reply_markup: adminKeyboard });
      return;
    }

    const now = Date.now();
    const activeDeals = deals.filter(deal => deal.timer > now);
    const expiredDeals = deals.filter(deal => deal.timer <= now);

    let message = `📋 All Deals (${deals.length} total)\n\n`;
    
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
    if (!security.validateFingerprint(req)) {
      return res.status(403).json({ error: 'Security validation failed' });
    }

    const now = Date.now();
    const activeDeals = deals.filter(deal => deal.timer > now);
    
    const publicDeals = activeDeals.map(deal => ({
      id: deal.id,
      slug: deal.slug,
      title: deal.title,
      description: deal.description,
      price: deal.price,
      oldPrice: deal.oldPrice,
      discount: deal.discount,
      category: deal.category,
      imageUrl: deal.imageUrl,
      coupon: deal.coupon, 
      rating: deal.rating,
      reviews: deal.reviews,
      badge: deal.badge,
      createdAt: deal.createdAt
    }));

    res.json(publicDeals);
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

    const deal = deals.find(d => d.id === dealId);
    
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

// Individual deal page route
app.get('/deal/:slugWithId', async (req, res) => {
  try {
    const slugWithId = InputValidator.sanitizeText(req.params.slugWithId, 100);
    const dealId = slugWithId.split('-').pop();
    
    if (!dealId || !/^[0-9a-f]{8,}$/i.test(dealId)) {
      return res.status(400).send(generateErrorPage(
        "Invalid Deal ID", 
        "The deal ID format is invalid"
      ));
    }

    const deal = deals.find(d => d.id === dealId);
    
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

    // Serve the deal.html file
    const dealHtmlPath = path.join(__dirname, 'deal.html');
    res.sendFile(dealHtmlPath);
    
    console.log(`📄 Serving deal page for ${dealId} from IP ${req.ip}`);
  } catch (error) {
    console.error("❌ Error serving deal page:", error);
    res.status(500).send(generateErrorPage(
      "Server Error", 
      "An error occurred while loading the deal page"
    ));
  }
});

// API route to get individual deal data
app.get('/api/deals/:dealId', apiLimiter, async (req, res) => {
  try {
    const dealId = InputValidator.sanitizeText(req.params.dealId, 50);
    
    if (!dealId || !/^[0-9a-f]{8,}$/i.test(dealId)) {
      return res.status(400).json({ error: 'Invalid deal ID format' });
    }

    const deal = deals.find(d => d.id === dealId);
    
    if (!deal) {
      return res.status(404).json({ error: 'Deal not found' });
    }

    if (deal.timer <= Date.now()) {
      return res.status(410).json({ error: 'Deal expired' });
    }

    // Return public deal data including coupon
    const publicDeal = {
      id: deal.id,
      slug: deal.slug,
      title: deal.title,
      description: deal.description,
      price: deal.price,
      oldPrice: deal.oldPrice,
      discount: deal.discount,
      category: deal.category,
      imageUrl: deal.imageUrl,
      coupon: deal.coupon, // Include coupon
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
app.use(express.static('.', {
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) {
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'no-referrer');
    }
  }
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
