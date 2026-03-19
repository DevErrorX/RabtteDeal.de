const TelegramBot = require("node-telegram-bot-api");
const express = require("express");
const fs = require("fs").promises;
const path = require("path");
const { spawn } = require("child_process");
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss');
const validator = require('validator');
const axios = require('axios');
const AdvancedSecurityManager = require('./security-middleware');
const VerificationSystem = require('./verification');
require('dotenv').config();
const admin = require("firebase-admin");
let firebaseConfig;

if (process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT) {
  firebaseConfig = {
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n')
    }),
    databaseURL: process.env.FIREBASE_DATABASE_URL || "https://rabattedealde-23a0d-default-rtdb.firebaseio.com"
  };
} else {
  try {
    const serviceAccount = require("./serviceAccountKey.json");
    firebaseConfig = {
      credential: admin.credential.cert({
        projectId: serviceAccount.project_id,
        clientEmail: serviceAccount.client_email,
        privateKey: serviceAccount.private_key.replace(/\\n/g, '\n')
      }),
      databaseURL: "https://rabattedealde-23a0d-default-rtdb.firebaseio.com"
    };
  } catch (error) {
    console.error('❌ Could not load service account file for local development:', error);
    process.exit(1);
  }
}

try {
  admin.initializeApp(firebaseConfig);
  console.log('✅ Firebase initialized successfully');
} catch (error) {
  console.error('❌ Firebase initialization failed:', error);
  process.exit(1);
}

const db = admin.database();
const dealsRef = db.ref("deals");

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
  // Kill any existing polling connection before starting
  const tempBot = new TelegramBot(BOT_TOKEN, { polling: false });
  tempBot.deleteWebHook().catch(() => {});

  bot = new TelegramBot(BOT_TOKEN, {
    polling: {
      params: { timeout: 30 },
      autoStart: true
    },
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

  generateProtectedUrl(dealId, ip) {
  const timestamp = Date.now();
  const token = crypto.createHmac('sha256', WEBHOOK_SECRET)
    .update(`${dealId}-${ip}-${timestamp}`)
    .digest('hex')
    .substring(0, 16);
  
  return `/redirect/${dealId}?t=${timestamp}&token=${token}`;
}

  validateProtectedUrl(dealId, token, timestamp, ip) {
  const expectedToken = crypto.createHmac('sha256', WEBHOOK_SECRET)
    .update(`${dealId}-${ip}-${timestamp}`)
    .digest('hex')
    .substring(0, 16);
  
  const isExpired = Date.now() - parseInt(timestamp) > 30000; 
  return !isExpired && token === expectedToken;
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
        'amazon.es', 'www.amazon.es',
        'amzn.to'
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
       url.includes('media-amazon.com') ||
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
    'fashion', 'uhren', 'baumarkt', 'haushalt', 'kosmetik', 
    'küche', 'schmuck', 'musik', 'möbel', 'auto', 
    'bücher', 'sport', 'büro', 'baby', 'computer', 
    'elektronik', 'haustier', 'kamera', 'spielwaren', 
    'garten', 'lebensmittel', 'videospiele', 'gutscheine'
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


const security = new AdvancedSecurityManager();
const verify = new VerificationSystem(WEBHOOK_SECRET);

let deals = [];
let userSessions = new Map();
let serverProcess = null;

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://static.cloudflareinsights.com"],
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
  handler: (req, res) => {
    security.logSuspiciousActivity(req.ip, 'redirect_rate_limit');
    res.status(429).send(generateErrorPage("Rate Limit Exceeded", "Please wait before making more requests"));
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

// Advanced security middleware for secure redirects
app.use('/secure-redirect', (req, res, next) => {
  res.setHeader('CF-Cache-Status', 'DYNAMIC');
  res.setHeader('CF-Ray', generateCloudflareRay());
  res.setHeader('Server', 'cloudflare');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});

// Advanced security API routes
app.use('/api/security', apiLimiter);

// ====== INVISIBLE VERIFICATION ENDPOINTS ======
app.post('/api/verify/simple', (req, res) => {
  const { fingerprint } = req.body || {};
  if (!fingerprint || typeof fingerprint !== 'string' || fingerprint.length < 10) {
    return res.status(400).json({ error: 'Invalid fingerprint' });
  }
  const result = verify.issueToken(fingerprint, req.ip);
  res.json({ success: true, ...result });
});

app.get('/api/verify/status', (req, res) => {
  const token = req.headers['x-verify-token'];
  const fp = req.headers['x-browser-fingerprint'];
  if (!token || !fp) {
    return res.json({ valid: false });
  }
  res.json({ valid: verify.validateToken(token, fp, req.ip) });
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
    console.log('🔄 Loading deals from Firebase...');
    const snapshot = await dealsRef.once("value");
    const firebaseData = snapshot.val();
    
    if (!firebaseData) {
      console.log('📭 No deals found in Firebase');
      deals = [];
      return;
    }

    let loadedDeals = [];
    if (Array.isArray(firebaseData)) {
      loadedDeals = firebaseData.filter(deal => deal != null);
    } else if (typeof firebaseData === 'object') {
      loadedDeals = Object.values(firebaseData).filter(deal => deal != null);
    }

    console.log(`📊 Raw data loaded: ${loadedDeals.length} deals`);

    deals = loadedDeals.filter(deal => {
      try {
        const isValid = deal && 
               typeof deal === 'object' &&
               deal.id && 
               deal.title && 
               deal.description &&
               typeof deal.price === 'number' && deal.price > 0 &&
               typeof deal.oldPrice === 'number' && deal.oldPrice > 0 &&
               deal.amazonUrl &&
               deal.category;
        
        if (!isValid) {
          console.warn('⚠️ Invalid deal found:', deal?.id || 'unknown');
          return false;
        }
        
        return true;
      } catch (error) {
        console.warn('⚠️ Error validating deal:', error);
        return false;
      }
    }).map(deal => ({
      ...deal,
      price: parseFloat(deal.price),
      oldPrice: parseFloat(deal.oldPrice),
      discount: deal.discount || Math.round(((deal.oldPrice - deal.price) / deal.oldPrice) * 100),
      timer: deal.timer || (Date.now() + 24 * 60 * 60 * 1000),
      rating: deal.rating || 4.5,
      reviews: deal.reviews || Math.floor(Math.random() * 1000) + 100,
      badge: deal.badge || (deal.discount >= 70 ? "HOT" : deal.discount >= 50 ? "FIRE" : deal.discount >= 30 ? "DEAL" : "SAVE"),
      imageUrl: deal.imageUrl || `/secure-image/${deal.id}`,
      title: InputValidator.sanitizeText(deal.title, 100),
      description: InputValidator.sanitizeText(deal.description, 500),
      category: InputValidator.sanitizeText(deal.category, 50).toLowerCase(),
      slug: deal.slug || generateSlug(deal.title)
    }));
    
    console.log(`✅ Successfully loaded ${deals.length} valid deals from Firebase`);
    const now = Date.now();
    const activeDeals = deals.filter(deal => deal.timer > now);
    const expiredDeals = deals.filter(deal => deal.timer <= now);
    // تجديد جميع العروض المنتهية - إضافة لمرة واحدة
async function renewAllDeals() {
  try {
    const now = Date.now();
    const twoThousandDays = 2000 * 24 * 60 * 60 * 1000;
    let renewedCount = 0;

    for (const deal of deals) {
      if (deal.timer <= now) {
        deal.timer = now + twoThousandDays;
        renewedCount++;
      }
    }

    if (renewedCount > 0) {
      await saveDeals();
      console.log(`🔄 تم تجديد ${renewedCount} عرض منتهي لمدة 2000 يوم`);
      // أعادة تحميل العروض بعد التجديد
      await loadDeals();
    }
  } catch (error) {
    console.error('❌ خطأ في تجديد العروض:', error);
  }
}

// تجديد العروض فقط إذا كانت كلها منتهية
if (deals.length > 0 && expiredDeals.length === deals.length) {
  console.log('🔄 تجديد جميع العروض المنتهية...');
  await renewAllDeals();
}
    
    console.log(`📈 Active deals: ${activeDeals.length}, Expired deals: ${expiredDeals.length}`);
    
  } catch (error) {
    console.error("❌ Error loading deals from Firebase:", error);
    if (!deals || deals.length === 0) {
      deals = [];
    }
    throw error; 
  }
}

async function saveDeals() {
  try {
    console.log(`💾 Saving ${deals.length} deals to Firebase...`);
    
    // Validate all deals before saving
    const validDeals = deals.filter(deal => {
      try {
        const errors = InputValidator.validateDealData({
          name: deal.title,
          description: deal.description,
          originalPrice: deal.oldPrice,
          dealPrice: deal.price,
          category: deal.category,
          amazonUrl: deal.amazonUrl,
          imageUrl: deal.imageUrl || `/secure-image/${deal.id}`
        });
        
        if (errors.length > 0) {
          console.warn(`⚠️ Invalid deal ${deal.id}:`, errors);
          return false;
        }
        
        return true;
      } catch (error) {
        console.warn(`⚠️ Error validating deal ${deal.id}:`, error);
        return false;
      }
    });
    
    if (validDeals.length !== deals.length) {
      console.warn(`⚠️ Filtered out ${deals.length - validDeals.length} invalid deals during save`);
      deals = validDeals; // Update the global deals array
    }
    
    // Create the data structure for Firebase
    const dealsObject = {};
    deals.forEach((deal, index) => {
      // Use the deal ID as the key for better Firebase structure
      dealsObject[deal.id] = {
        ...deal,
        // Ensure we have all required fields
        updatedAt: new Date().toISOString(),
        // Add index for ordering if needed
        order: index
      };
    });
    
    // Save to Firebase
    await dealsRef.set(dealsObject);
    console.log(`✅ Successfully saved ${deals.length} deals to Firebase`);
    
  } catch (error) {
    console.error("❌ Error saving deals to Firebase:", error);
    throw error;
  }
}

// Fixed API endpoint to ensure consistency

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
  session.step = "amazon_url"; // Start with URL
  userSessions.set(userId, session);

  bot.sendMessage(
    chatId,
    "📝 إضافة عرض جديد...\n\nيرجى إدخال رابط أمازون (يجب أن يكون HTTPS):"
  );
}

async function handleAddDealSession(chatId, userId, text, session) {
  const { step, data } = session;

  switch (step) {
    case "amazon_url": {
      if (!InputValidator.validateURL(text)) {
        bot.sendMessage(chatId, "❌ يرجى إدخال رابط أمازون HTTPS صالح من النطاقات المدعومة:");
        return;
      }
      data.amazonUrl = text;
      
      bot.sendMessage(chatId, "🔍 جاري جلب بيانات المنتج من أمازون...");
      
      const pythonProcess = spawn('python3', [path.join(__dirname, 'amazon_scraper.py'), text]);
      let output = '';
      let errorOutput = '';
      
      pythonProcess.stdout.on('data', (data) => {
        output += data.toString();
      });

      pythonProcess.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });
      
      pythonProcess.on('close', async (code) => {
        if (code !== 0) {
          console.error(`Scraper exited with code ${code}. Error: ${errorOutput}`);
        }
        try {
          // Extract JSON from output - handle cases where there might be multiple lines
          let result = null;
          let parseError = null;
          
          // Try to find and parse JSON objects in the output
          const jsonMatches = output.match(/{[^{}]*"(?:title|error)"[^{}]*}/g);
          
          if (jsonMatches && jsonMatches.length > 0) {
            // Parse the last (most likely the actual result) JSON object
            try {
              result = JSON.parse(jsonMatches[jsonMatches.length - 1]);
            } catch (innerError) {
              parseError = innerError;
            }
          }
          
          // Fallback: try parsing the whole output
          if (!result && !parseError) {
            try {
              result = JSON.parse(output.trim());
            } catch (innerError) {
              parseError = innerError;
            }
          }
          
          if (!result) {
            result = { error: parseError ? parseError.message : 'No valid data from scraper' };
          }
          
          console.log('Scraper result:', result);
          
          if (result.error) {
            bot.sendMessage(chatId, `❌ فشل جلب البيانات: ${result.error}\nيرجى إدخال اسم العرض يدوياً:`);
            session.step = "name";
            userSessions.set(userId, session);
          } else if (!result.title) {
            bot.sendMessage(chatId, `❌ لم يتم الحصول على بيانات صحيحة من المنتج.\nيرجى إدخال اسم العرض يدوياً:`);
            session.step = "name";
            userSessions.set(userId, session);
          } else {
            // Truncate title to 100 characters if needed
            data.name = result.title ? result.title.substring(0, 100) : 'nicht verfügbar';
            // Use a default description if not available or too short
            data.description = (result.description && result.description.length >= 10) 
              ? result.description 
              : 'Hochwertiges Produkt mit ausgezeichneter Qualität und Performance';
            data.imageUrl = result.image_url;
            
            // Extract prices
            const parsePrice = (p) => {
    if (!p || typeof p !== 'string') return null;
    
    // 1. تنظيف أولي للكلمات العربية أو الرموز الغريبة
    if (p.includes("غير متوفر") || p.includes("لا يوجد خصم")) return null;

    // 2. إزالة كل شيء ليس (رقماً أو فاصلة أو نقطة)
    // هذا سيحول "29,99€" إلى "29,99"
    let cleaned = p.replace(/[^\d.,]/g, '');

    // 3. استخراج الرقم (يدعم: 9 | 9.5 | 9,99)
    const match = cleaned.match(/(\d+([.,]\d+)?)/);

    if (match) {
        // تحويل الفاصلة إلى نقطة ليفهمها البرمج كـ Float
        let numStr = match[1].replace(',', '.');
        
        // التعامل مع حالة آلاف (مثلاً 1.250,50) 
        // إذا وجد أكثر من نقطة، نعتبر الأخيرة هي العلامة العشرية
        const parts = numStr.split('.');
        if (parts.length > 2) {
            const decimal = parts.pop();
            numStr = parts.join('') + '.' + decimal;
        }
        
        return parseFloat(numStr);
    }
    
    return null;
};
            
            data.dealPrice = parsePrice(result.current_price);
            data.originalPrice = parsePrice(result.old_price);
            
            // If no original price or prices are the same, ask user to enter prices manually
            if (!data.dealPrice || !data.originalPrice || data.dealPrice >= data.originalPrice) {
              // Ensure description is set before asking for prices
              if (!data.description || data.description.length < 10) {
                data.description = 'Hochwertiges Produkt mit ausgezeichneter Qualität und Performance';
              }
              session.step = "original_price";
              userSessions.set(userId, session); // Save session with description set
              bot.sendMessage(chatId, `⚠️ لم نتمكن من جلب سعر الخصم.‏ يرجى إدخال السعر الأصلي أولاً:`);
              return;
            }
            
            bot.sendMessage(chatId,
              `✅ تم جلب البيانات بنجاح!\n\n` +
              `📦 المنتج: ${data.name}\n` +
              `💰 السعر الحالي: ${result.current_price}\n` +
              `❌ السعر قبل الخصم: ${result.old_price}\n\n` +
              `هل لديك رمز قسيمة لهذا العرض؟ أدخل رمز القسيمة أو اكتب 'no' إذا لا توجد قسيمة:`
            );
            session.step = "coupon";
            userSessions.set(userId, session);
          }
        } catch (e) {
          console.error("Error parsing scraper output:", e, "Raw output:", output);
          bot.sendMessage(chatId, "❌ حدث خطأ أثناء معالجة البيانات. يرجى إدخال اسم العرض يدوياً:");
          session.step = "name";
          userSessions.set(userId, session);
        }
      });
      break;
    }

    case "name": {
      const sanitizedName = InputValidator.sanitizeText(text, 100);
      if (sanitizedName.length < 5 || sanitizedName.length > 100) {
        bot.sendMessage(chatId, "❌ يجب أن يكون اسم العرض بين 5 و 100 حرف:");
        return;
      }
      data.name = sanitizedName;
      session.step = "description";
      userSessions.set(userId, session);
      bot.sendMessage(chatId, "✅ تم حفظ الاسم!\n\nالآن أدخل الوصف (10-500 حرف):");
      break;
    }

    case "description": {
      const sanitizedDesc = InputValidator.sanitizeText(text, 500);
      if (sanitizedDesc.length < 10 || sanitizedDesc.length > 500) {
        bot.sendMessage(chatId, "❌ يجب أن يكون الوصف بين 10 و 500 حرف:");
        return;
      }
      data.description = sanitizedDesc;
      session.step = "original_price";
      userSessions.set(userId, session);
      bot.sendMessage(chatId, "✅ تم حفظ الوصف!\n\nأدخل السعر الأصلي (مثلاً 99.99):");
      break;
    }

    case "original_price": {
      if (!InputValidator.validatePrice(text)) {
        bot.sendMessage(chatId, "❌ يرجى إدخال سعر صالح (0.01 - 99999.99):");
        return;
      }
      data.originalPrice = parseFloat(text);
      session.step = "deal_price";
      userSessions.set(userId, session);
      bot.sendMessage(chatId, "✅ تم حفظ السعر الأصلي!\n\nأدخل سعر العرض:");
      break;
    }

    case "deal_price": {
      if (!InputValidator.validatePrice(text)) {
        bot.sendMessage(chatId, "❌ يرجى إدخال سعر صالح (0.01 - 99999.99):");
        return;
      }
      const dealPrice = parseFloat(text);
      if (dealPrice >= data.originalPrice) {
        bot.sendMessage(chatId, "❌ يجب أن يكون سعر العرض أقل من السعر الأصلي:");
        return;
      }
      data.dealPrice = dealPrice;
      session.step = "coupon";
      userSessions.set(userId, session);
      bot.sendMessage(chatId, "✅ تم حفظ سعر العرض!\n\nهل لديك رمز قسيمة لهذا العرض؟ أدخل رمز القسيمة أو اكتب 'no' إذا لا توجد قسيمة:");
      break;
    }

    case "coupon": {
      const couponText = InputValidator.sanitizeText(text, 50).trim();
      if (couponText.toLowerCase() === 'no' || couponText.toLowerCase() === 'nein') {
        data.coupon = null;
      } else {
        data.coupon = couponText;
      }
      session.step = "category";
      userSessions.set(userId, session);
      const validCategories = [
        'fashion', 'uhren', 'baumarkt', 'haushalt', 'kosmetik',
        'küche', 'schmuck', 'musik', 'möbel', 'auto',
        'bücher', 'sport', 'büro', 'baby', 'computer',
        'elektronik', 'haustier', 'kamera', 'spielwaren',
        'garten', 'lebensmittel', 'videospiele', 'gutscheine'
      ];
      bot.sendMessage(
        chatId,
        `✅ تم ${data.coupon ? 'حفظ' : 'تخطي'} القسيمة!\n\n` +
        `أدخل التصنيف (واحد من هذه التصنيفات: ${validCategories.join(', ')}):`
      );
      break;
    }

    case "category": {
      const category = InputValidator.sanitizeText(text, 50).toLowerCase();
      const validCategories = [
        'fashion', 'uhren', 'baumarkt', 'haushalt', 'kosmetik',
        'küche', 'schmuck', 'musik', 'möbel', 'auto',
        'bücher', 'sport', 'büro', 'baby', 'computer',
        'elektronik', 'haustier', 'kamera', 'spielwaren',
        'garten', 'lebensmittel', 'videospiele', 'gutscheine'
      ];

      if (!validCategories.includes(category)) {
        bot.sendMessage(chatId,
          "❌ يرجى إدخال تصنيف صالح من القائمة التالية:\n\n" +
          "Amazon Fashion, Uhren, Baumarkt, Haushalt\n" +
          "Kosmetik & Körperpflege, Küche & Esszimmer\n" +
          "Schmuck, Musik, Möbel, Auto & Motorrad\n" +
          "Bücher, Sport und Fitness, Bürobedarf\n" +
          "Babyartikel, Computer & Zubehör, Elektronik\n" +
          "Haustierprodukte, Kameras, Spielwaren\n" +
          "Garten, Lebensmittel, Videospiele\n" +
          "Geschenkgutscheine"
        );
        return;
      }

      data.category = category;
      
      // If we have all data from scraper, complete the deal
      if (data.name && data.description && data.dealPrice && data.originalPrice && data.imageUrl) {
        if (session.completing) return;
        session.completing = true;
        userSessions.set(userId, session);
        await completeDealAdd(chatId, userId, data);
      } else {
        // Fallback if scraper missed something
        if (!data.name) {
          session.step = "name";
          bot.sendMessage(chatId, "✅ تم حفظ التصنيف!\n\nيرجى إدخال اسم العرض:");
        } else if (!data.description) {
          session.step = "description";
          bot.sendMessage(chatId, "✅ تم حفظ التصنيف!\n\nيرجى إدخال الوصف:");
        } else if (!data.originalPrice) {
          session.step = "original_price";
          bot.sendMessage(chatId, "✅ تم حفظ التصنيف!\n\nيرجى إدخال السعر الأصلي:");
        } else if (!data.dealPrice) {
          session.step = "deal_price";
          bot.sendMessage(chatId, "✅ تم حفظ التصنيف!\n\nيرجى إدخال سعر العرض:");
        } else {
          session.step = "photo";
          bot.sendMessage(chatId, "✅ تم حفظ التصنيف!\n\nأرسل صورة أو أدخل رابط صورة HTTPS:");
        }
        userSessions.set(userId, session);
      }
      break;
    }

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
    const currentSession = userSessions.get(userId);
    if (!currentSession || currentSession.action !== "add_deal") {
      throw new Error("Session validation failed");
    }
    
    // Ensure description is properly formatted and within length limits
    if (!data.description || typeof data.description !== 'string') {
      data.description = 'Hochwertiges Produkt mit ausgezeichneter Qualität und Performance';
    } else {
      // Trim and ensure it's between 10-500 characters
      data.description = data.description.trim();
      if (data.description.length < 10) {
        data.description = 'Hochwertiges Produkt mit ausgezeichneter Qualität und Performance';
      } else if (data.description.length > 500) {
        data.description = data.description.substring(0, 500);
      }
    }
    
    const validationErrors = InputValidator.validateDealData(data);
    if (validationErrors.length > 0) {
      console.error('❌ Validation failed:', validationErrors);
      throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
    }
    const dealId = generateDealId();
    const slug = generateSlug(data.name);
    
    const discount = Math.round(
      ((data.originalPrice - data.dealPrice) / data.originalPrice) * 100
    );

    const badge = discount >= 70 ? "HOT" : discount >= 50 ? "FIRE" : discount >= 30 ? "DEAL" : "SAVE";

    const expirationTime = Date.now() + (2000 * 24 * 60 * 60 * 1000); // 2000 يوم

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
      // Preserve Amazon image URL if available, otherwise use secure-image path
      imageUrl: data.imageUrl && data.imageUrl.startsWith('http') ? data.imageUrl : `/secure-image/${dealId}`,
      imageInfo: data.imageInfo || null,
      // Store the original Amazon image URL for reference
      originalImageUrl: data.imageUrl,
      
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

    // Add deal to array
    deals.push(newDeal);
    
    // Save deals to file
    await saveDeals();
    console.log(`💾 Deal saved successfully. Total deals: ${deals.length}`);

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
    const successMessage = `✅ تم إضافة العرض بنجاح!\n\n` +
      `🆔 معرف العرض: ${dealId}\n` +
      `📝 الاسم: ${data.name}\n` +
      `💰 السعر: €${data.dealPrice} (كان €${data.originalPrice})\n` +
      `💵 التوفير: €${savings} (${savingsPercent}%)\n` +
      `🏷️ الشارة: ${badge}\n` +
      `📂 التصنيف: ${data.category}\n` +
      `🎫 القسيمة: ${data.coupon || 'لا يوجد'}\n` +
      `⭐ التقييم: ${rating}/5.0 (${reviews} مراجعة)\n` +
      `⏰ ينتهي في: 24 ساعة\n` +
      `🚚 الشحن: ${newDeal.shipping || 'عادي'}\n\n` +
      `🔗 روابط العرض:\n` +
      `📱 الصفحة الرئيسية: ${dealUrl}\n` +
      `🔄 رابط التوجيه: ${redirectUrl}\n` +
      `🔧 API: ${apiUrl}\n\n` +
      `🛠️ للتحكم في العرض:\n` +
      `• للتعديل: استخدم "✏️ Change Deal" مع المعرف "${dealId}"\n` +
      `• للحذف: استخدم "🗑️ Delete Deal" مع المعرف "${dealId}"`;

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
      const previewMessage = `📋 معاينة العرض:\n\n` +
        `🛍️ ${newDeal.title}\n` +
        `💰 ${newDeal.price}€ ⚡ بدلاً من ${newDeal.oldPrice}€\n` +
        `🔥 توفير ${savingsPercent}% • ${badge}\n` +
        `⭐ ${newDeal.rating}/5 (${newDeal.reviews} مراجعة)\n` +
        `📦 ${newDeal.category} • ${newDeal.availability}\n` +
        `${newDeal.coupon ? `🎫 كود الخصم: ${newDeal.coupon}\n` : ''}` +
        `${newDeal.shipping ? `🚚 ${newDeal.shipping}\n` : ''}` +
        `⏰ ينتهي خلال 24 ساعة`;
  
      userSessions.delete(userId);
      await bot.sendMessage(chatId, previewMessage);
    } catch (previewError) {
      console.warn('⚠️ Could not send preview message:', previewError.message);
    }

  } catch (error) {
    console.error("❌ Error completing deal add:", error);
    
    // Clean up session on error
    userSessions.delete(userId);
    
    // Send detailed error message
    let errorMessage = "❌ حدث خطأ أثناء حفظ العرض:\n\n";
    
    if (error.message.includes('Validation failed')) {
      errorMessage += `🔍 خطأ في التحقق من البيانات:\n${error.message.replace('Validation failed: ', '')}`;
    } else if (error.message.includes('ENOENT') || error.message.includes('permission')) {
      errorMessage += "💾 خطأ في حفظ الملف. تحقق من الصلاحيات.";
    } else if (error.message.includes('network') || error.message.includes('timeout')) {
      errorMessage += "🌐 خطأ في الاتصال. يرجى المحاولة مرة أخرى.";
    } else {
      errorMessage += `⚠️ ${error.message}`;
    }
    
    errorMessage += "\n\nيرجى المحاولة مرة أخرى أو الاتصال بالدعم الفني.";
    
    await bot.sendMessage(chatId, errorMessage, { reply_markup: adminKeyboard });
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
    'fashion', 'uhren', 'baumarkt', 'haushalt', 'kosmetik', 
    'küche', 'schmuck', 'musik', 'möbel', 'auto', 
    'bücher', 'sport', 'büro', 'baby', 'computer', 
    'elektronik', 'haustier', 'kamera', 'spielwaren', 
    'garten', 'lebensmittel', 'videospiele', 'gutscheine'
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

     const dealUrl = `${WEBSITE_URL}/deal/${deal.slug}`;

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
let syncInterval;

function startPeriodicSync() {
  if (syncInterval) {
    clearInterval(syncInterval);
  }
  
  // Sync every 5 minutes
  syncInterval = setInterval(async () => {
    try {
      console.log('🔄 Performing periodic sync with Firebase...');
      await loadDeals();
    } catch (error) {
      console.error('❌ Periodic sync failed:', error);
    }
  }, 5 * 60 * 1000);
  
  console.log('⏰ Periodic sync started (5 minute intervals)');
}

// Add Firebase connection monitoring
dealsRef.on('value', (snapshot) => {
  console.log('🔄 Firebase data changed, updating local cache...');
  // Don't directly update deals array here to avoid conflicts
  // Instead, trigger a reload after a short delay
  setTimeout(() => {
    loadDeals().catch(console.error);
  }, 1000);
});
app.get('/api/deals', apiLimiter, verify.rateLimit(100, 60000), async (req, res) => {
  try {
    // Require verification token
    const token = req.headers['x-verify-token'] || req.query._vt;
    const fingerprint = req.headers['x-browser-fingerprint'] || '';
    if (!token || !fingerprint || !verify.validateToken(token, fingerprint, req.ip)) {
      return res.status(401).json({ error: 'verification_required' });
    }

    const now = Date.now();
    
    // Always fetch fresh data from Firebase for API calls
    const snapshot = await dealsRef.once("value");
    const firebaseData = snapshot.val() || {};
    
    // Convert to array and filter active deals
    const allDeals = Object.values(firebaseData).filter(deal => 
      deal && 
      deal.id && 
      deal.title && 
      typeof deal.price === 'number' && 
      typeof deal.oldPrice === 'number'
    );
    
    const activeDeals = allDeals
      .filter(deal => (deal.timer || 0) > now)
      .map(deal => ({
        id: deal.id,
        slug: deal.slug || generateSlug(deal.title),
        title: deal.title,
        description: deal.description,
        price: parseFloat(deal.price),
        oldPrice: parseFloat(deal.oldPrice),
        discount: deal.discount || Math.round(((deal.oldPrice - deal.price) / deal.oldPrice) * 100),
        category: deal.category,
        imageUrl: `/secure-image/${deal.id}`,
        coupon: deal.coupon || null,
        rating: deal.rating || 4.5,
        reviews: deal.reviews || Math.floor(Math.random() * 1000) + 100,
        timer: deal.timer,
        badge: deal.badge || (deal.discount >= 70 ? "HOT" : deal.discount >= 50 ? "FIRE" : deal.discount >= 30 ? "DEAL" : "SAVE"),
        createdAt: deal.createdAt,
        availability: deal.availability || "In Stock",
        shipping: deal.shipping || (deal.discount >= 50 ? "Free Shipping" : null)
      }))
      .sort((a, b) => b.discount - a.discount); // Sort by discount descending
    
    console.log(`📡 API: Serving ${activeDeals.length} active deals out of ${allDeals.length} total`);
    
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.setHeader('X-Total-Deals', allDeals.length.toString());
    res.setHeader('X-Active-Deals', activeDeals.length.toString());
    
    res.json(activeDeals);
  } catch (error) {
    console.error("❌ Error serving deals API:", error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Failed to load deals from database'
    });
  }
});


app.get('/redirect/:dealId', redirectLimiter, async (req, res) => {
  try {
    const dealId = InputValidator.sanitizeText(req.params.dealId, 50);

    if (security.isHoneypot(`/redirect/${dealId}`) || dealId.includes('honey_')) {
      console.warn(`🍯 Honeypot accessed: ${dealId} from IP: ${req.ip}`);
      security.logSuspiciousActivity(req.ip, 'honeypot_access');
      security.blockIdentifier(req.ip, 1800000);
      return res.status(403).send(generateErrorPage("Access Denied", "Suspicious activity detected."));
    }

    if (!dealId || !/^[0-9a-f]{8,}$/i.test(dealId)) {
      return res.status(400).send(generateErrorPage("Invalid Deal ID", "The deal ID format is invalid"));
    }

    const snapshot = await dealsRef.child(dealId).once("value");
    const deal = snapshot.val();

    if (!deal) {
      return res.status(404).send(generateErrorPage("Deal Not Found", "The requested deal could not be found"));
    }

    if ((deal.timer || 0) <= Date.now()) {
      return res.status(410).send(generateErrorPage("Deal Expired", "This deal has expired"));
    }

    if (!InputValidator.validateURL(deal.amazonUrl)) {
      return res.status(400).send(generateErrorPage("Invalid Deal URL", "The deal URL is invalid"));
    }

    // If token provided, validate and redirect directly
    const token = req.query._vt;
    const fingerprint = req.query._fp;
    if (token && fingerprint && verify.validateToken(token, fingerprint, req.ip)) {
      console.log(`🔗 Redirect (verified) to deal ${dealId}: "${deal.title}" from IP ${req.ip}`);
      try { await dealsRef.child(dealId).child('clicks').transaction(c => (c || 0) + 1); } catch (e) {}
      res.setHeader('X-Robots-Tag', 'noindex, nofollow');
      res.setHeader('Referrer-Policy', 'no-referrer');
      return res.redirect(302, deal.amazonUrl);
    }

    // No token: serve verification page
    console.log(`📄 Serving redirect verification page for deal ${dealId} from IP ${req.ip}`);

    const honeypotLinks = verify.getHoneypotUrls()
      .map(u => `<a href="${u}" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden" aria-hidden="true">info</a>`)
      .join('');

    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');

    res.send(`<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Weiterleitung... - Rabatte&Deal&DE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a0a;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center}
.c{text-align:center;max-width:500px;padding:2rem}
.sp{width:40px;height:40px;border:3px solid #333;border-top-color:#6366f1;border-radius:50%;animation:s .8s linear infinite;margin:0 auto 1.5rem}
@keyframes s{to{transform:rotate(360deg)}}
.t{color:#a3a3a3;font-size:.95rem}
</style>
</head>
<body>
${honeypotLinks}
<div class="c"><div class="sp"></div><p class="t">Weiterleitung wird vorbereitet...</p></div>
<script>
(function(){
var _URL="${deal.amazonUrl.replace(/"/g,'\\"')}";
function _E(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
function _FP(){var cv='',w='',v='';try{var c=document.createElement('canvas');c.width=200;c.height=50;var x=c.getContext('2d');x.textBaseline='top';x.font='14px Arial';x.fillStyle='#f60';x.fillRect(125,1,62,20);x.fillStyle='#069';x.fillText('vrf',2,15);x.fillStyle='rgba(102,204,0,0.7)';x.fillText('vrf',4,17);cv=c.toDataURL().substring(0,100)}catch(e){}try{var g=document.createElement('canvas').getContext('webgl');if(g){w=g.getParameter(g.RENDERER)||'';v=g.getParameter(g.VENDOR)||''}}catch(e){}return cv+'|'+w+'|'+v+'|'+(navigator.hardwareConcurrency||0)+'|'+(navigator.platform||'')}
function _H(){if(navigator.webdriver)return!0;if(!navigator.languages||!navigator.languages.length)return!0;if(/HeadlessChrome|PhantomJS|Selenium|Puppeteer/i.test(navigator.userAgent))return!0;return!1}
function _showErr(msg){document.body.innerHTML='<div style="max-width:500px;margin:2rem auto;padding:2rem;text-align:center"><h1 style="font-size:1.5rem;font-weight:800;color:#6366f1;margin-bottom:1rem">Rabatte&Deal&DE</h1><p style="color:#a3a3a3;margin-bottom:1.5rem">'+_E(msg)+'</p><a href="'+_URL+'" style="display:inline-block;background:#6366f1;color:#fff;padding:.75rem 2rem;border-radius:8px;text-decoration:none;font-weight:600">Direkt zu Amazon</a><br><br><a href="/" style="color:#6366f1;text-decoration:none">Zur Startseite</a></div>'}
async function go(){
if(_H()){window.location.href='/';return}
var fp=_FP();
try{
var r=await fetch('/api/verify/simple',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({fingerprint:fp})});
var rs=await r.json();
if(rs&&rs.success&&rs.token){
sessionStorage.setItem('_v',JSON.stringify({token:rs.token,exp:rs.expires,fp:fp}));
window.location.href=_URL;
return;
}
}catch(e){}
_showErr('Verifizierung fehlgeschlagen');
}
var _timer=setTimeout(function(){_showErr('Zeitüberschreitung')},15000);
go().then(function(){clearTimeout(_timer)}).catch(function(){clearTimeout(_timer);_showErr('Fehler')});
})();
</script>
</body></html>`);

  } catch (error) {
    console.error("❌ Error handling redirect:", error);
    res.status(500).send(generateErrorPage("Server Error", "An error occurred"));
  }
});

app.get('/deal/:slug', async (req, res) => {
  try {
    const slug = InputValidator.sanitizeText(req.params.slug, 100);
    if (!slug || slug.length < 3) {
      return res.status(400).send(generateErrorPage("Invalid Deal URL", "The deal URL format is invalid"));
    }

    let deal = deals.find(d => d.slug === slug);
    if (!deal) {
      const slugParts = slug.split('-');
      for (const part of slugParts) {
        if (/^[0-9a-f]{8,}$/i.test(part)) {
          deal = deals.find(d => d.id === part);
          if (deal) break;
        }
      }
    }

    if (!deal) {
      return res.status(404).send(generateErrorPage("Deal Not Found", "The requested deal could not be found"));
    }

    if (deal.timer <= Date.now()) {
      return res.status(410).send(generateErrorPage("Deal Expired", "This deal has expired and is no longer available"));
    }

    if (!InputValidator.validateURL(deal.amazonUrl)) {
      return res.status(400).send(generateErrorPage("Invalid Deal URL", "The deal URL is invalid or unsafe"));
    }

    console.log(`📄 Serving deal page "${deal.title}" (ID: ${deal.id}) from IP ${req.ip}`);

    const honeypotLinks = verify.getHoneypotUrls()
      .map(u => `<a href="${u}" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden" aria-hidden="true">info</a>`)
      .join('');

    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');

    res.send(`<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${verify.escapeHtml(deal.title)} - Rabatte&Deal&DE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a0a;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center}
.c{text-align:center;max-width:500px;padding:2rem}
.sp{width:40px;height:40px;border:3px solid #333;border-top-color:#6366f1;border-radius:50%;animation:s .8s linear infinite;margin:0 auto 1.5rem}
@keyframes s{to{transform:rotate(360deg)}}
.t{color:#a3a3a3;font-size:.95rem}
</style>
</head>
<body>
${honeypotLinks}
<div class="c"><div class="sp"></div><p class="t">Laden...</p></div>
<script>
(function(){
var _D=${JSON.stringify({id:deal.id,title:deal.title,description:deal.description,price:deal.price,oldPrice:deal.oldPrice,discount:deal.discount,category:deal.category,coupon:deal.coupon,rating:deal.rating,reviews:deal.reviews,badge:deal.badge,slug:deal.slug,imageUrl:deal.imageUrl || '/secure-image/'+deal.id})};
function _E(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
function _FP(){var cv='',w='',v='';try{var c=document.createElement('canvas');c.width=200;c.height=50;var x=c.getContext('2d');x.textBaseline='top';x.font='14px Arial';x.fillStyle='#f60';x.fillRect(125,1,62,20);x.fillStyle='#069';x.fillText('vrf',2,15);x.fillStyle='rgba(102,204,0,0.7)';x.fillText('vrf',4,17);cv=c.toDataURL().substring(0,100)}catch(e){}try{var g=document.createElement('canvas').getContext('webgl');if(g){w=g.getParameter(g.RENDERER)||'';v=g.getParameter(g.VENDOR)||''}}catch(e){}return cv+'|'+w+'|'+v+'|'+(navigator.hardwareConcurrency||0)+'|'+(navigator.platform||'')}
function _H(){if(navigator.webdriver)return!0;if(!navigator.languages||!navigator.languages.length)return!0;if(/HeadlessChrome|PhantomJS|Selenium|Puppeteer/i.test(navigator.userAgent))return!0;return!1}
function _hdr(t,f){return{'Content-Type':'application/json','X-Verify-Token':t,'X-Browser-Fingerprint':f}}
function _showError(msg){document.body.innerHTML='<div style="max-width:500px;margin:2rem auto;padding:2rem;text-align:center"><h1 style="font-size:1.5rem;font-weight:800;color:#6366f1;margin-bottom:1rem">Rabatte&Deal&DE</h1><p style="color:#a3a3a3;margin-bottom:1.5rem">'+_E(msg)+'</p><button onclick="location.reload()" style="background:#6366f1;color:#fff;border:none;padding:.75rem 2rem;border-radius:8px;font-weight:600;cursor:pointer;font-size:1rem">Erneut versuchen</button><br><br><a href="/" style="color:#6366f1;text-decoration:none">Zur Startseite</a></div>'}
async function go(){
if(_H()){_showError('Browser nicht unterstützt');return}
var fp=_FP();
var st=null;try{st=JSON.parse(sessionStorage.getItem('_v')||'{}')}catch(e){st={}}
var tk=null;
if(st.token&&st.exp>Date.now()&&st.fp===fp){tk=st.token}
if(!tk){
try{
var r=await fetch('/api/verify/simple',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({fingerprint:fp})});
var rs=await r.json();
if(rs&&rs.success&&rs.token){tk=rs.token;sessionStorage.setItem('_v',JSON.stringify({token:tk,exp:rs.expires,fp:fp}))}
}catch(e){}
}
if(!tk){_showError('Verifizierung fehlgeschlagen');return}
document.title=_D.title+' - Rabatte&Deal&DE';
var sc=Math.round(((_D.oldPrice-_D.price)/_D.oldPrice)*100);
var cp=_D.coupon?'<div style="background:#f59e0b;color:#fff;padding:.75rem 1rem;border-radius:8px;margin-bottom:1rem;display:flex;align-items:center;justify-content:center;gap:.5rem;cursor:pointer" id="cpn" data-c="'+_E(_D.coupon)+'">🎫 Coupon: <code style="background:rgba(255,255,255,.2);padding:.2rem .5rem;border-radius:4px;font-family:monospace;font-weight:600">'+_E(_D.coupon)+'</code><span style="font-size:.75rem;opacity:.8">(klicken)</span></div>':'';
document.body.innerHTML='<div style="max-width:600px;margin:2rem auto;padding:1.5rem"><div style="text-align:center;margin-bottom:2rem"><h1 style="font-size:1.5rem;font-weight:800;color:#6366f1">Rabatte&Deal&DE</h1></div><div style="background:#1f1f1f;border-radius:16px;overflow:hidden;border:1px solid #262626"><div style="position:relative;height:300px;overflow:hidden"><img src="'+_E(_D.imageUrl)+'" alt="'+_E(_D.title)+'" style="width:100%;height:100%;object-fit:contain;background:#111" onerror="this.src=\'https://via.placeholder.com/400?text=Image\'"><div style="position:absolute;top:.75rem;left:.75rem;background:#6366f1;color:#fff;padding:.25rem .75rem;border-radius:20px;font-size:.75rem;font-weight:600;text-transform:uppercase">'+_E(_D.category)+'</div><div style="position:absolute;bottom:.75rem;left:.75rem;background:#10b981;color:#fff;padding:.25rem .5rem;border-radius:8px;font-weight:700;font-size:.8rem">-'+sc+'%</div></div><div style="padding:1.5rem"><h2 style="font-size:1.25rem;font-weight:600;margin-bottom:.75rem;line-height:1.4">'+_E(_D.title)+'</h2><p style="color:#a3a3a3;font-size:.95rem;margin-bottom:1rem;line-height:1.5">'+_E(_D.description)+'</p>'+cp+'<div style="display:flex;align-items:center;gap:.75rem;margin-bottom:1rem"><span style="font-size:1.5rem;font-weight:700;color:#10b981">€'+_D.price+'</span><span style="font-size:1rem;color:#737373;text-decoration:line-through">€'+_D.oldPrice+'</span><span style="color:#10b981;font-weight:600">-'+sc+'%</span></div><div style="display:flex;align-items:center;gap:1rem;margin-bottom:1.5rem;color:#a3a3a3;font-size:.9rem"><span>⭐ '+(_D.rating||'4.5')+'/5</span><span>('+( _D.reviews||'0')+' Bewertungen)</span></div><button id="gdl" style="width:100%;background:#6366f1;color:#fff;border:none;padding:1rem;border-radius:12px;font-weight:700;font-size:1.1rem;cursor:pointer;transition:background .2s">🛒 Zum Deal auf Amazon</button></div></div></div>';
if(document.getElementById('cpn')){document.getElementById('cpn').onclick=function(e){e.stopPropagation();navigator.clipboard.writeText(this.dataset.c)}}
document.getElementById('gdl').onclick=function(){
var b=this;b.disabled=true;b.textContent='Weiterleiten...';
fetch('/api/deal/'+_D.slug,{headers:_hdr(tk,fp)}).then(function(r){return r.json()}).then(function(d){
if(d.amazonUrl){window.location.href=d.amazonUrl}
else{b.disabled=false;b.textContent='🛒 Zum Deal auf Amazon'}
}).catch(function(){b.disabled=false;b.textContent='🛒 Zum Deal auf Amazon'})}
}
var _timer=setTimeout(function(){_showError('Zeitüberschreitung')},15000);
go().then(function(){clearTimeout(_timer)}).catch(function(){clearTimeout(_timer);_showError('Fehler')});
})();
</script>
</body></html>`);
  } catch (error) {
    console.error("❌ Error handling deal page:", error);
    res.status(500).send(generateErrorPage("Server Error", "An error occurred while processing your request"));
  }
});
app.get('/api/deal/:slug', apiLimiter, async (req, res) => {
  try {
    // Require verification token
    const token = req.headers['x-verify-token'] || req.query._vt;
    const fingerprint = req.headers['x-browser-fingerprint'] || '';
    if (!token || !fingerprint || !verify.validateToken(token, fingerprint, req.ip)) {
      return res.status(401).json({ error: 'verification_required' });
    }

    const slug = InputValidator.sanitizeText(req.params.slug, 100);
    if (!slug || slug.length < 3) {
      return res.status(400).json({ error: 'Invalid deal slug format' });
    }

    const snapshot = await dealsRef.once("value");
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
      amazonUrl: deal.amazonUrl,
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
  
  const blockedExtensions = ['.env', '.log', '.config'];
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
app.get('/api/deals/stream', (req, res) => {
  const token = req.query._vt;
  const fingerprint = req.query._fp;
  if (!token || !fingerprint || !verify.validateToken(token, fingerprint, req.ip)) {
    return res.status(401).json({ error: 'verification_required' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const sendUpdate = (allDeals) => {
    const now = Date.now();
    const deals = Object.values(allDeals || {}).filter(d =>
      d && d.id && d.title && (d.timer || 0) > now
    ).map(d => ({
      id: d.id, slug: d.slug, title: d.title, description: d.description,
      price: d.price, oldPrice: d.oldPrice, discount: d.discount,
      category: d.category, imageUrl: `/secure-image/${d.id}`,
      coupon: d.coupon, rating: d.rating, reviews: d.reviews,
      badge: d.badge, timer: d.timer
    }));
    res.write(`data: ${JSON.stringify(deals)}\n\n`);
  };

  const listener = (snapshot) => { sendUpdate(snapshot.val()); };
  dealsRef.on('value', listener);

  req.on('close', () => {
    dealsRef.off('value', listener);
  });
});

// Advanced Security API Endpoints
app.post('/api/security/behavior', (req, res) => {
  try {
    const { sessionId, behaviorData, fingerprint } = req.body;
    
    if (!sessionId || !behaviorData || !fingerprint) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const isHuman = security.analyzeBehavior(sessionId, behaviorData);
    res.json({ humanLike: isHuman, sessionId });
  } catch (error) {
    console.error('Behavior analysis error:', error);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

app.post('/api/security/protect-url', (req, res) => {
  try {
    const { dealId, originalUrl, sessionId, fingerprint, completedChallenges } = req.body;
    
    if (!dealId || !sessionId || !fingerprint) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Validate session and challenges
    if (!security.isTrustedSession(sessionId)) {
      return res.status(403).json({ error: 'Session not verified' });
    }
    
    if (!completedChallenges || completedChallenges.length < 2) {
      return res.status(403).json({ error: 'Insufficient challenges completed' });
    }
    
    // Find the deal
    const deal = deals.find(d => d.id === dealId);
    if (!deal) {
      return res.status(404).json({ error: 'Deal not found' });
    }
    
    // Generate protected URL
    const protectedUrl = security.createProtectedRedirectUrl(dealId, deal.amazonUrl, req);
    
    res.json({ protectedUrl });
  } catch (error) {
    console.error('URL protection error:', error);
    res.status(500).json({ error: 'Protection failed' });
  }
});

app.post('/api/security/violation', (req, res) => {
  try {
    const { type, sessionId, fingerprint, timestamp, behaviorData } = req.body;
    
    console.warn(`🚨 Security violation: ${type} from session ${sessionId}`);
    
    // Log the violation
    security.logSuspiciousActivity(req.ip, type);
    
    // Additional blocking for severe violations
    const severeViolations = ['honeypot_clicked', 'devtools_opened', 'inspection_attempt'];
    if (severeViolations.some(v => type.includes(v))) {
      security.blockIdentifier(req.ip, 600000); // 10 minutes
    }
    
    res.json({ logged: true });
  } catch (error) {
    console.error('Violation logging error:', error);
    res.status(500).json({ error: 'Logging failed' });
  }
});

// Invisible security validation endpoint
app.post('/api/security/validate-session', (req, res) => {
  try {
    const { sessionId, fingerprint, behaviorScore, isHuman, validationTime } = req.body;
    
    if (!sessionId || !fingerprint || typeof behaviorScore !== 'number') {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Additional server-side validation
    let serverValidation = isHuman;
    
    // Check for headless browser indicators
    const userAgent = req.headers['user-agent'] || '';
    if (userAgent.includes('HeadlessChrome') || userAgent.includes('PhantomJS')) {
      serverValidation = false;
    }
    
    // Check for missing expected headers
    const requiredHeaders = ['accept', 'accept-language', 'accept-encoding'];
    const missingHeaders = requiredHeaders.filter(h => !req.headers[h]);
    if (missingHeaders.length > 2) {
      serverValidation = false;
    }
    
    if (serverValidation && behaviorScore >= 60) {
      // Register trusted session
      security.trustedSessions.set(sessionId, {
        verified: Date.now(),
        expires: Date.now() + (24 * 60 * 60 * 1000), // 24 hours
        fingerprint,
        behaviorScore,
        ip: req.ip
      });
      
      console.log(`✅ Session validated: ${sessionId} (score: ${behaviorScore})`);
    } else {
      console.warn(`🚫 Session rejected: ${sessionId} (score: ${behaviorScore})`);
      security.logSuspiciousActivity(req.ip, 'session_validation_failed');
    }
    
    res.json({ 
      validated: serverValidation,
      sessionId,
      behaviorScore
    });
  } catch (error) {
    console.error('Session validation error:', error);
    res.status(500).json({ error: 'Validation failed' });
  }
});

// Get protected URL for invisible security
app.post('/api/security/get-protected-url', (req, res) => {
  try {
    const { dealId, sessionId, fingerprint, behaviorScore } = req.body;
    
    if (!dealId || !sessionId || !fingerprint) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Check if session is trusted
    if (!security.isTrustedSession(sessionId)) {
      security.logSuspiciousActivity(req.ip, 'untrusted_session');
      return res.status(403).json({ error: 'Session not verified' });
    }
    
    // Find the deal
    const deal = deals.find(d => d.id === dealId);
    if (!deal) {
      return res.status(404).json({ error: 'Deal not found' });
    }
    
    // Check if deal is still valid
    if (deal.timer <= Date.now()) {
      return res.status(410).json({ error: 'Deal expired' });
    }
    
    // Generate protected URL
    const protectedUrl = security.createProtectedRedirectUrl(dealId, deal.amazonUrl, req);
    
    console.log(`🔗 Protected URL generated for deal ${dealId}`);
    
    res.json({ protectedUrl });
  } catch (error) {
    console.error('Protected URL generation error:', error);
    res.status(500).json({ error: 'URL generation failed' });
  }
});

// Secure redirect handler
app.get('/secure-redirect/:key', (req, res) => {
  try {
    const { key } = req.params;
    const { token, session } = req.query;
    
    if (!key || !token || !session) {
      return res.status(400).send(generateErrorPage(
        'Invalid Request',
        'Missing required parameters'
      ));
    }
    
    // Get redirect data
    const redirectData = security.tempRedirects.get(key);
    if (!redirectData) {
      return res.status(404).send(generateErrorPage(
        'Link Expired',
        'This secure link has expired or is invalid'
      ));
    }
    
    // Validate token
    const tokenValidation = security.validateProtectionToken(
      token, 
      redirectData.dealId, 
      req.ip, 
      req.headers['user-agent'] || ''
    );
    
    if (!tokenValidation.valid) {
      security.logSuspiciousActivity(req.ip, 'invalid_token');
      return res.status(403).send(generateErrorPage(
        'Access Denied',
        'Security validation failed'
      ));
    }
    
    // Validate session
    if (redirectData.sessionId !== session) {
      security.logSuspiciousActivity(req.ip, 'session_mismatch');
      return res.status(403).send(generateErrorPage(
        'Access Denied',
        'Session validation failed'
      ));
    }
    
    // Check if session is trusted
    if (!security.isTrustedSession(session)) {
      return res.status(403).send(generateErrorPage(
        'Access Denied',
        'Session not verified'
      ));
    }
    
    // Clean up used redirect
    security.tempRedirects.delete(key);
    
    // Log successful redirect
    console.log(`✅ Secure redirect: ${redirectData.dealId} -> ${redirectData.amazonUrl}`);
    
    // Redirect to Amazon
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.redirect(302, redirectData.amazonUrl);
    
  } catch (error) {
    console.error('Secure redirect error:', error);
    res.status(500).send(generateErrorPage(
      'Server Error',
      'An error occurred during redirect'
    ));
  }
});
app.get('/secure-image/:id', async (req, res) => {
  try {
    const requestedId = req.params.id;
    
    // Find deal by ID or by image file ID
    let deal = deals.find(d => d.id === requestedId);
    
    if (!deal) {
      // Try to find by image info file_id
      deal = deals.find(d => d.imageInfo && d.imageInfo.file_id === requestedId);
    }
    
    if (!deal) {
      console.warn(`🖼️ Image not found for ID: ${requestedId}`);
      return res.redirect('https://via.placeholder.com/300?text=Image+Not+Available');
    }

    // Handle different image URL formats
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

    // Check for original Amazon image URL (from scrapers)
    if (deal.originalImageUrl && deal.originalImageUrl.startsWith('http')) {
      return res.redirect(deal.originalImageUrl);
    }
    
    // Fallback for external image URLs
    if (deal.imageUrl && deal.imageUrl.startsWith('http')) {
      return res.redirect(deal.imageUrl);
    }

    // Ultimate fallback
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
  console.error('❌ Telegram polling error:', error.code || error.message);
  if (error.code === 'ETELEGRAM' && error.response && error.response.statusCode === 409) {
    console.log('🔄 Restarting bot polling in 5 seconds...');
    bot.stopPolling();
    setTimeout(() => {
      bot.startPolling().catch(e => console.error('Failed to restart polling:', e.message));
    }, 5000);
  }
});

if (require.main === module) {
  startWebsite().catch(error => {
    console.error("❌ Failed to start application:", error);
    process.exit(1);
  });
}


module.exports = { 
  app, 
  startWebsite, 
  security,
  loadDeals,
  saveDeals,
  startPeriodicSync
};
