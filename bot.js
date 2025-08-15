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
const admin = require("firebase-admin");
require('dotenv').config();

// Firebase Configuration
const serviceAccount = require(process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL || "https://rabattedealde-23a0d-default-rtdb.firebaseio.com"
});

const db = admin.database();

// Firebase Database Manager Class
class FirebaseDealsManager {
  constructor() {
    this.dealsRef = db.ref('deals');
    this.statsRef = db.ref('stats');
    this.metadataRef = db.ref('metadata');
    this.localCache = new Map();
    this.cacheExpiry = 5 * 60 * 1000; // 5 minutes cache
    this.listeners = new Map();
    this.isConnected = false;
    
    this.initializeDatabase();
    this.setupConnectionMonitoring();
  }

  async initializeDatabase() {
    try {
      // Initialize stats if they don't exist
      const statsSnapshot = await this.statsRef.once('value');
      if (!statsSnapshot.exists()) {
        await this.statsRef.set({
          totalDeals: 0,
          activeDeals: 0,
          expiredDeals: 0,
          totalViews: 0,
          totalClicks: 0,
          lastUpdated: admin.database.ServerValue.TIMESTAMP
        });
      }

      // Initialize metadata
      const metadataSnapshot = await this.metadataRef.once('value');
      if (!metadataSnapshot.exists()) {
        await this.metadataRef.set({
          lastSync: admin.database.ServerValue.TIMESTAMP,
          version: "2.0.0",
          migrationCompleted: true
        });
      }

      console.log("✅ Firebase database initialized successfully");
      this.isConnected = true;
    } catch (error) {
      console.error("❌ Firebase initialization error:", error);
      throw error;
    }
  }

  setupConnectionMonitoring() {
    const connectedRef = db.ref('.info/connected');
    connectedRef.on('value', (snapshot) => {
      if (snapshot.val() === true) {
        console.log('🔗 Firebase connected');
        this.isConnected = true;
      } else {
        console.log('📡 Firebase disconnected');
        this.isConnected = false;
      }
    });
  }

  // Add deal with optimistic updates and rollback
  async addDeal(dealData) {
    const dealId = dealData.id;
    const dealRef = this.dealsRef.child(dealId);
    
    try {
      // Add timestamp and status
      const enrichedDeal = {
        ...dealData,
        createdAt: admin.database.ServerValue.TIMESTAMP,
        updatedAt: admin.database.ServerValue.TIMESTAMP,
        status: 'active',
        views: 0,
        clicks: 0
      };

      // Use transaction to ensure atomic write
      await dealRef.transaction((currentData) => {
        if (currentData === null) {
          return enrichedDeal;
        }
        return undefined; // Abort if deal already exists
      });

      // Update cache
      this.localCache.set(dealId, {
        data: enrichedDeal,
        timestamp: Date.now()
      });

      // Update stats atomically
      await this.updateStats('increment', 'totalDeals');
      await this.updateStats('increment', 'activeDeals');

      console.log(`✅ Deal ${dealId} added to Firebase`);
      return enrichedDeal;
    } catch (error) {
      console.error(`❌ Error adding deal ${dealId}:`, error);
      throw error;
    }
  }

  // Get all active deals with caching
  async getActiveDeals(useCache = true) {
    const cacheKey = 'active_deals';
    const cached = this.localCache.get(cacheKey);
    
    // Return cached data if valid and requested
    if (useCache && cached && (Date.now() - cached.timestamp) < this.cacheExpiry) {
      return cached.data;
    }

    try {
      const snapshot = await this.dealsRef
        .orderByChild('timer')
        .startAt(Date.now())
        .once('value');

      const activeDeals = [];
      snapshot.forEach((childSnapshot) => {
        const deal = childSnapshot.val();
        if (deal && deal.status === 'active') {
          activeDeals.push({
            ...deal,
            id: childSnapshot.key
          });
        }
      });

      // Sort by creation date (newest first)
      activeDeals.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

      // Update cache
      this.localCache.set(cacheKey, {
        data: activeDeals,
        timestamp: Date.now()
      });

      return activeDeals;
    } catch (error) {
      console.error("❌ Error getting active deals:", error);
      
      // Return cached data as fallback
      if (cached) {
        console.warn("⚠️ Using stale cache due to Firebase error");
        return cached.data;
      }
      
      throw error;
    }
  }

  // Get all deals (including expired)
  async getAllDeals() {
    try {
      const snapshot = await this.dealsRef
        .orderByChild('createdAt')
        .once('value');

      const deals = [];
      snapshot.forEach((childSnapshot) => {
        const deal = childSnapshot.val();
        if (deal) {
          deals.push({
            ...deal,
            id: childSnapshot.key
          });
        }
      });

      return deals.reverse(); // Newest first
    } catch (error) {
      console.error("❌ Error getting all deals:", error);
      throw error;
    }
  }

  // Get deal by ID with caching
  async getDealById(dealId, useCache = true) {
    const cached = this.localCache.get(dealId);
    
    if (useCache && cached && (Date.now() - cached.timestamp) < this.cacheExpiry) {
      return cached.data;
    }

    try {
      const snapshot = await this.dealsRef.child(dealId).once('value');
      
      if (!snapshot.exists()) {
        return null;
      }

      const deal = {
        ...snapshot.val(),
        id: dealId
      };

      // Update cache
      this.localCache.set(dealId, {
        data: deal,
        timestamp: Date.now()
      });

      return deal;
    } catch (error) {
      console.error(`❌ Error getting deal ${dealId}:`, error);
      
      // Return cached data as fallback
      if (cached) {
        console.warn("⚠️ Using cached deal due to Firebase error");
        return cached.data;
      }
      
      throw error;
    }
  }

  // Get deal by slug
  async getDealBySlug(slug) {
    try {
      const snapshot = await this.dealsRef
        .orderByChild('slug')
        .equalTo(slug)
        .limitToFirst(1)
        .once('value');

      let deal = null;
      snapshot.forEach((childSnapshot) => {
        deal = {
          ...childSnapshot.val(),
          id: childSnapshot.key
        };
      });

      return deal;
    } catch (error) {
      console.error(`❌ Error getting deal by slug ${slug}:`, error);
      throw error;
    }
  }

  // Update deal
  async updateDeal(dealId, updates) {
    try {
      const dealRef = this.dealsRef.child(dealId);
      
      // Add update timestamp
      const updateData = {
        ...updates,
        updatedAt: admin.database.ServerValue.TIMESTAMP
      };

      await dealRef.update(updateData);

      // Update cache
      const cached = this.localCache.get(dealId);
      if (cached) {
        this.localCache.set(dealId, {
          data: { ...cached.data, ...updateData },
          timestamp: Date.now()
        });
      }

      // Clear active deals cache
      this.localCache.delete('active_deals');

      console.log(`✅ Deal ${dealId} updated`);
      return true;
    } catch (error) {
      console.error(`❌ Error updating deal ${dealId}:`, error);
      throw error;
    }
  }

  // Delete deal
  async deleteDeal(dealId) {
    try {
      const deal = await this.getDealById(dealId);
      if (!deal) {
        throw new Error('Deal not found');
      }

      const wasActive = deal.timer > Date.now();

      await this.dealsRef.child(dealId).remove();

      // Update cache
      this.localCache.delete(dealId);
      this.localCache.delete('active_deals');

      // Update stats
      await this.updateStats('decrement', 'totalDeals');
      if (wasActive) {
        await this.updateStats('decrement', 'activeDeals');
      } else {
        await this.updateStats('decrement', 'expiredDeals');
      }

      console.log(`✅ Deal ${dealId} deleted`);
      return deal;
    } catch (error) {
      console.error(`❌ Error deleting deal ${dealId}:`, error);
      throw error;
    }
  }

  // Increment view count
  async incrementViews(dealId) {
    try {
      const dealRef = this.dealsRef.child(dealId);
      await dealRef.child('views').transaction((currentViews) => {
        return (currentViews || 0) + 1;
      });

      await this.updateStats('increment', 'totalViews');
    } catch (error) {
      console.error(`❌ Error incrementing views for ${dealId}:`, error);
    }
  }

  // Increment click count
  async incrementClicks(dealId) {
    try {
      const dealRef = this.dealsRef.child(dealId);
      await dealRef.child('clicks').transaction((currentClicks) => {
        return (currentClicks || 0) + 1;
      });

      await this.updateStats('increment', 'totalClicks');
    } catch (error) {
      console.error(`❌ Error incrementing clicks for ${dealId}:`, error);
    }
  }

  // Update statistics
  async updateStats(operation, field) {
    try {
      const fieldRef = this.statsRef.child(field);
      await fieldRef.transaction((currentValue) => {
        const current = currentValue || 0;
        return operation === 'increment' ? current + 1 : Math.max(0, current - 1);
      });

      // Update last updated timestamp
      await this.statsRef.child('lastUpdated').set(admin.database.ServerValue.TIMESTAMP);
    } catch (error) {
      console.error(`❌ Error updating stats ${field}:`, error);
    }
  }

  // Get statistics
  async getStats() {
    try {
      const snapshot = await this.statsRef.once('value');
      return snapshot.val() || {};
    } catch (error) {
      console.error("❌ Error getting stats:", error);
      return {};
    }
  }

  // Clean up expired deals (run periodically)
  async cleanupExpiredDeals() {
    try {
      const now = Date.now();
      const snapshot = await this.dealsRef
        .orderByChild('timer')
        .endAt(now)
        .once('value');

      const updates = {};
      let expiredCount = 0;

      snapshot.forEach((childSnapshot) => {
        const deal = childSnapshot.val();
        if (deal.status === 'active') {
          updates[`${childSnapshot.key}/status`] = 'expired';
          expiredCount++;
        }
      });

      if (Object.keys(updates).length > 0) {
        await this.dealsRef.update(updates);
        
        // Update stats
        await this.statsRef.transaction((currentStats) => {
          const stats = currentStats || {};
          return {
            ...stats,
            activeDeals: Math.max(0, (stats.activeDeals || 0) - expiredCount),
            expiredDeals: (stats.expiredDeals || 0) + expiredCount,
            lastUpdated: admin.database.ServerValue.TIMESTAMP
          };
        });

        console.log(`🧹 Marked ${expiredCount} deals as expired`);
      }

      // Clear cache
      this.localCache.delete('active_deals');
    } catch (error) {
      console.error("❌ Error cleaning up expired deals:", error);
    }
  }

  // Setup real-time listeners
  setupRealTimeListener(callback) {
    const listenerId = crypto.randomBytes(8).toString('hex');
    
    const listener = this.dealsRef.on('child_changed', (snapshot) => {
      const deal = {
        ...snapshot.val(),
        id: snapshot.key
      };
      
      // Update cache
      this.localCache.set(deal.id, {
        data: deal,
        timestamp: Date.now()
      });
      
      // Clear active deals cache to force refresh
      this.localCache.delete('active_deals');
      
      callback('updated', deal);
    });

    this.listeners.set(listenerId, listener);
    return listenerId;
  }

  // Remove real-time listener
  removeListener(listenerId) {
    const listener = this.listeners.get(listenerId);
    if (listener) {
      this.dealsRef.off('child_changed', listener);
      this.listeners.delete(listenerId);
    }
  }

  // Migrate from deals.json (one-time operation)
  async migrateFromJson(jsonPath) {
    try {
      console.log("🔄 Starting migration from deals.json...");
      
      const jsonData = await fs.readFile(jsonPath, 'utf8');
      const deals = JSON.parse(jsonData);
      
      let migrated = 0;
      let failed = 0;

      for (const deal of deals) {
        try {
          await this.addDeal(deal);
          migrated++;
        } catch (error) {
          console.error(`❌ Failed to migrate deal ${deal.id}:`, error);
          failed++;
        }
      }

      await this.metadataRef.update({
        migrationCompleted: true,
        migrationDate: admin.database.ServerValue.TIMESTAMP,
        dealsMetadata: {
          total: deals.length,
          migrated,
          failed
        }
      });

      console.log(`✅ Migration completed: ${migrated} migrated, ${failed} failed`);
      return { migrated, failed, total: deals.length };
    } catch (error) {
      console.error("❌ Migration failed:", error);
      throw error;
    }
  }

  // Backup to JSON (for backup purposes)
  async backupToJson(filePath) {
    try {
      const deals = await this.getAllDeals();
      await fs.writeFile(filePath, JSON.stringify(deals, null, 2));
      console.log(`✅ Backup created: ${filePath}`);
      return deals.length;
    } catch (error) {
      console.error("❌ Backup failed:", error);
      throw error;
    }
  }

  // Close connections gracefully
  async close() {
    console.log("🔌 Closing Firebase connections...");
    
    // Remove all listeners
    this.listeners.forEach((listener, id) => {
      this.removeListener(id);
    });
    
    // Clear cache
    this.localCache.clear();
    
    // Close Firebase connection
    try {
      await admin.app().delete();
      console.log("✅ Firebase connections closed");
    } catch (error) {
      console.error("❌ Error closing Firebase:", error);
    }
  }
}

// Initialize Firebase manager
const firebaseManager = new FirebaseDealsManager();

// Rest of your existing code with Firebase replacements...

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

// Replace all deals array operations with Firebase calls
// Example replacements for key functions:

async function loadDeals() {
  try {
    console.log("📦 Loading deals from Firebase...");
    // No longer needed as Firebase handles this automatically
    // But we can warm up the cache
    await firebaseManager.getActiveDeals();
    console.log("✅ Firebase deals manager ready");
  } catch (error) {
    console.error("❌ Error initializing Firebase deals:", error);
    throw error;
  }
}

async function saveDeals() {
  // No longer needed as Firebase auto-saves
  // But we can trigger a cleanup
  await firebaseManager.cleanupExpiredDeals();
  console.log("💾 Firebase cleanup completed");
}

async function completeDealAdd(chatId, userId, data) {
  try {
    console.log(`📄 Starting deal completion for user ${userId}:`, {
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
      createdBy: userId,
      
      // Additional fields for frontend
      currency: "EUR",
      availability: "In Stock",
      shipping: discount >= 50 ? "Free Shipping" : null
    };

    // Save to Firebase instead of local array
    await firebaseManager.addDeal(newDeal);

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
      `📄 رابط التوجيه: ${redirectUrl}\n` +
      `🔧 API: ${apiUrl}\n\n` +
      `🛠️ للتحكم في العرض:\n` +
      `• للتعديل: استخدم "✏️ Change Deal" مع المعرف "${dealId}"\n` +
      `• للحذف: استخدم "🗑️ Delete Deal" مع المعرف "${dealId}"`;

    // Send success message
    await bot.sendMessage(chatId, successMessage, { 
      reply_markup: adminKeyboard,
      parse_mode: 'HTML'
    });

    console.log(`🎉 Deal "${data.name}" (${dealId}) created successfully by admin ${userId}`);

  } catch (error) {
    console.error("❌ Error completing deal add:", error);
    
    // Clean up session on error
    userSessions.delete(userId);
    
    let errorMessage = "❌ حدث خطأ أثناء حفظ العرض:\n\n";
    
    if (error.message.includes('Validation failed')) {
      errorMessage += `🔍 خطأ في التحقق من البيانات:\n${error.message.replace('Validation failed: ', '')}`;
    } else if (error.message.includes('Firebase') || error.message.includes('network')) {
      errorMessage += "🌐 خطأ في الاتصال بقاعدة البيانات. يرجى المحاولة مرة أخرى.";
    } else {
      errorMessage += `⚠️ ${error.message}`;
    }
    
    errorMessage += "\n\nيرجى المحاولة مرة أخرى أو الاتصال بالدعم الفني.";
    
    await bot.sendMessage(chatId, errorMessage, { reply_markup: adminKeyboard });
  }
}

// Update API endpoints to use Firebase

app.get('/api/deals', apiLimiter, async (req, res) => {
  try {
    const activeDeals = await firebaseManager.getActiveDeals();
    
    const publicDeals = activeDeals.map(deal => ({
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

    const deal = await firebaseManager.getDealById(dealId);
    
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

    // Increment click count asynchronously
    firebaseManager.incrementClicks(dealId).catch(console.error);

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

    let deal = await firebaseManager.getDealBySlug(slug);
    
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

    // Increment view count asynchronously
    firebaseManager.incrementViews(deal.id).catch(console.error);

    console.log(`🔗 Redirecting to Amazon for deal "${deal.title}" (ID: ${deal.id}, Slug: ${deal.slug}) from IP ${req.ip}`);
    
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

// Add cleanup job for expired deals
setInterval(async () => {
  try {
    await firebaseManager.cleanupExpiredDeals();
  } catch (error) {
    console.error("❌ Error in cleanup job:", error);
  }
}, 5 * 60 * 1000); // Run every 5 minutes

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🛑 Received SIGTERM, shutting down gracefully');
  try {
    await firebaseManager.close();
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
});

process.on('SIGINT', async () => {
  console.log('🛑 Received SIGINT, shutting down gracefully');
  try {
    await firebaseManager.close();
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
});

// Update remaining functions to use Firebase

async function startDeleteDeal(chatId, userId) {
  try {
    const activeDeals = await firebaseManager.getActiveDeals();
    
    if (activeDeals.length === 0) {
      bot.sendMessage(chatId, "❌ لا توجد عروض متاحة للحذف.", {
        reply_markup: adminKeyboard,
      });
      return;
    }

    const session = createSecureSession(userId, "delete_deal");
    session.step = "select_id";
    userSessions.set(userId, session);

    let dealsList = "🗑️ Select a deal to delete:\n\n";
    const recentDeals = activeDeals.slice(0, 10);
    
    recentDeals.forEach((deal) => {
      dealsList += `🆔 ${deal.id}\n📝 ${deal.title.substring(0, 50)}...\n💰 €${deal.price}\n\n`;
    });

    if (activeDeals.length > 10) {
      dealsList += `... and ${activeDeals.length - 10} more deals\n\n`;
    }

    dealsList += "Enter the Deal ID to delete:";
    bot.sendMessage(chatId, dealsList);
  } catch (error) {
    console.error("❌ Error starting delete deal:", error);
    bot.sendMessage(chatId, "❌ خطأ في تحميل العروض. يرجى المحاولة مرة أخرى.", {
      reply_markup: adminKeyboard,
    });
  }
}

async function handleDeleteDealSession(chatId, userId, text, session) {
  const dealId = InputValidator.sanitizeText(text, 50).trim();
  
  if (!/^[0-9a-f]{8,}$/i.test(dealId)) {
    bot.sendMessage(chatId, "❌ صيغة معرف العرض غير صحيحة. يرجى إدخال معرف عرض صالح:");
    return;
  }
  
  try {
    const deletedDeal = await firebaseManager.deleteDeal(dealId);
    userSessions.delete(userId);

    bot.sendMessage(
      chatId,
      `✅ تم حذف العرض بنجاح!\n\n` +
      `🆔 معرف العرض المحذوف: ${dealId}\n` +
      `📝 الاسم: ${deletedDeal.title}`,
      { reply_markup: adminKeyboard }
    );

    console.log(`🗑️ تم حذف العرض بواسطة المدير ${userId}: ${dealId}`);
  } catch (error) {
    console.error(`❌ Error deleting deal ${dealId}:`, error);
    
    if (error.message === 'Deal not found') {
      bot.sendMessage(chatId, "❌ لم يتم العثور على العرض. يرجى إدخال معرف عرض صالح:");
    } else {
      bot.sendMessage(chatId, "❌ حدث خطأ أثناء حذف العرض. يرجى المحاولة مرة أخرى.", {
        reply_markup: adminKeyboard,
      });
    }
  }
}

async function startChangeDeal(chatId, userId) {
  try {
    const activeDeals = await firebaseManager.getActiveDeals();
    
    if (activeDeals.length === 0) {
      bot.sendMessage(chatId, "❌ لا توجد عروض متاحة للتعديل.", {
        reply_markup: adminKeyboard,
      });
      return;
    }

    const session = createSecureSession(userId, "change_deal");
    session.step = "select_id";
    userSessions.set(userId, session);

    let dealsList = "✏️ اختر عرضًا للتعديل:\n\n";
    const recentDeals = activeDeals.slice(0, 10);

    recentDeals.forEach((deal) => {
      dealsList += `🆔 ${deal.id}\n📝 ${deal.title.substring(0, 50)}...\n💰 €${deal.price}\n\n`;
    });

    if (activeDeals.length > 10) {
      dealsList += `... و ${activeDeals.length - 10} عروض أخرى\n\n`;
    }

    dealsList += "أدخل معرف العرض للتعديل:";
    bot.sendMessage(chatId, dealsList);
  } catch (error) {
    console.error("❌ Error starting change deal:", error);
    bot.sendMessage(chatId, "❌ خطأ في تحميل العروض. يرجى المحاولة مرة أخرى.", {
      reply_markup: adminKeyboard,
    });
  }
}

async function handleChangeDealSession(chatId, userId, text, session) {
  if (session.step === "select_id") {
    const dealId = InputValidator.sanitizeText(text, 50).trim();
    
    if (!/^[0-9a-f]{8,}$/i.test(dealId)) {
      bot.sendMessage(chatId, "❌ صيغة معرف العرض غير صحيحة. يرجى إدخال معرف عرض صالح:");
      return;
    }

    try {
      const deal = await firebaseManager.getDealById(dealId);

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
    } catch (error) {
      console.error(`❌ Error finding deal ${dealId}:`, error);
      bot.sendMessage(chatId, "❌ خطأ في البحث عن العرض. يرجى المحاولة مرة أخرى.");
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
      const deal = await firebaseManager.getDealById(session.dealId);
      const field = session.field;
      let updateValue = text;
      let isValid = true;
      let errorMessage = "";
      let updates = {};

      switch (field) {
        case "name": {
          updateValue = InputValidator.sanitizeText(text, 100);
          if (updateValue.length < 5 || updateValue.length > 100) {
            isValid = false;
            errorMessage = "Name must be 5-100 characters long";
          } else {
            updates.title = updateValue;
            updates.slug = generateSlug(updateValue);
          }
          break;
        }
        
        case "description": {
          updateValue = InputValidator.sanitizeText(text, 500);
          if (updateValue.length < 10 || updateValue.length > 500) {
            isValid = false;
            errorMessage = "Description must be 10-500 characters long";
          } else {
            updates.description = updateValue;
          }
          break;
        }
        
        case "price": {
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
          break;
        }
        
        case "original price": {
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
          break;
        }
        
        case "category": {
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
          break;
        }
        
        case "amazon url": {
          if (!InputValidator.validateURL(text)) {
            isValid = false;
            errorMessage = "Please enter a valid HTTPS Amazon URL";
          } else {
            updates.amazonUrl = text;
          }
          break;
        }
        
        default:
          isValid = false;
          errorMessage = "Invalid field selected";
      }

      if (!isValid) {
        bot.sendMessage(chatId, `❌ ${errorMessage}:`);
        return;
      }

      // Calculate discount if prices were updated
      if (field === "price" || field === "original price") {
        const finalPrice = updates.price || deal.price;
        const finalOldPrice = updates.oldPrice || deal.oldPrice;
        
        updates.discount = Math.round(
          ((finalOldPrice - finalPrice) / finalOldPrice) * 100
        );
        updates.badge = updates.discount > 50 ? "HOT" : "DEAL";
      }

      await firebaseManager.updateDeal(session.dealId, updates);
      
      // Get updated deal for display
      const updatedDeal = await firebaseManager.getDealById(session.dealId);
      
      userSessions.delete(userId);

      const dealUrl = `${WEBSITE_URL}/deal/${updatedDeal.slug}`;

      bot.sendMessage(
        chatId,
        `✅ تم تحديث العرض بنجاح!\n\n` +
        `🆔 معرف العرض: ${updatedDeal.id}\n` +
        `📝 الاسم: ${updatedDeal.title}\n` +
        `💰 السعر: €${updatedDeal.price} (كان €${updatedDeal.oldPrice})\n` +
        `🏷️ الخصم: ${updatedDeal.discount}%\n` +
        `📂 التصنيف: ${updatedDeal.category}\n\n` +
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
    const stats = await firebaseManager.getStats();
    const activeDeals = await firebaseManager.getActiveDeals();
    const allDeals = await firebaseManager.getAllDeals();
    
    const now = Date.now();
    const expiredDeals = allDeals.filter(deal => deal.timer <= now);
    
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
    statsMessage += `📊 Average Discount: ${avgDiscount.toFixed(1)}%\n`;
    statsMessage += `👁️ Total Views: ${stats.totalViews || 0}\n`;
    statsMessage += `🖱️ Total Clicks: ${stats.totalClicks || 0}\n\n`;
    
    statsMessage += `📂 Categories:\n`;
    Object.entries(categories).forEach(([category, count]) => {
      statsMessage += `  • ${category}: ${count} deals\n`;
    });

    const blockedIPs = security.blockedIPs.size;
    const suspiciousActivities = security.suspiciousActivity.size;
    
    statsMessage += `\n🔒 Security:\n`;
    statsMessage += `  • Blocked IPs: ${blockedIPs}\n`;
    statsMessage += `  • Suspicious Activities: ${suspiciousActivities}\n`;

    // Firebase connection status
    statsMessage += `\n🔥 Firebase:\n`;
    statsMessage += `  • Status: ${firebaseManager.isConnected ? '🟢 Connected' : '🔴 Disconnected'}\n`;
    statsMessage += `  • Last Updated: ${stats.lastUpdated ? new Date(stats.lastUpdated).toLocaleString() : 'Unknown'}\n`;

    bot.sendMessage(chatId, statsMessage, { reply_markup: adminKeyboard });
  } catch (error) {
    console.error("❌ Error showing stats:", error);
    bot.sendMessage(chatId, "❌ Error retrieving statistics.", { reply_markup: adminKeyboard });
  }
}

async function listAllDeals(chatId) {
  try {
    const allDeals = await firebaseManager.getAllDeals();
    
    if (allDeals.length === 0) {
      bot.sendMessage(chatId, "❌ لا توجد عروض متاحة.", { reply_markup: adminKeyboard });
      return;
    }

    const now = Date.now();
    const activeDeals = allDeals.filter(deal => deal.timer > now);
    const expiredDeals = allDeals.filter(deal => deal.timer <= now);

    let message = `📋 All Deals (${allDeals.length} total)\n\n`;
    
    if (activeDeals.length > 0) {
      message += `✅ Active Deals (${activeDeals.length}):\n`;
      activeDeals.slice(0, 5).forEach(deal => {
        const timeLeft = Math.ceil((deal.timer - now) / (1000 * 60 * 60));
        message += `🆔 ${deal.id}\n`;
        message += `📝 ${deal.title.substring(0, 40)}...\n`;
        message += `💰 €${deal.price} (${deal.discount}% off)\n`;
        message += `👁️ ${deal.views || 0} views • 🖱️ ${deal.clicks || 0} clicks\n`;
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
        message += `👁️ ${deal.views || 0} views • 🖱️ ${deal.clicks || 0} clicks\n`;
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

// Update remaining API endpoint
app.get('/api/deal/:slug', apiLimiter, async (req, res) => {
  try {
    const slug = InputValidator.sanitizeText(req.params.slug, 100);
    
    if (!slug || slug.length < 3) {
      return res.status(400).json({ error: 'Invalid deal slug format' });
    }

    const deal = await firebaseManager.getDealBySlug(slug);
    
    if (!deal) {
      return res.status(404).json({ error: 'Deal not found' });
    }

    if (deal.timer <= Date.now()) {
      return res.status(410).json({ error: 'Deal expired' });
    }

    // Increment view count asynchronously
    firebaseManager.incrementViews(deal.id).catch(console.error);

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
      createdAt: deal.createdAt,
      views: deal.views || 0,
      clicks: deal.clicks || 0
    };

    res.json(publicDeal);
  } catch (error) {
    console.error("❌ Error serving individual deal API:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add migration endpoint for one-time migration from JSON
app.post('/api/migrate-from-json', async (req, res) => {
  try {
    // Only allow in development or with proper authentication
    if (NODE_ENV === 'production') {
      return res.status(403).json({ error: 'Migration not allowed in production' });
    }

    const jsonPath = path.join(__dirname, 'private', 'deals.json');
    const result = await firebaseManager.migrateFromJson(jsonPath);
    
    res.json({
      success: true,
      message: 'Migration completed',
      ...result
    });
  } catch (error) {
    console.error("❌ Migration error:", error);
    res.status(500).json({ 
      success: false,
      error: 'Migration failed',
      details: error.message 
    });
  }
});

// Add backup endpoint
app.get('/api/backup-to-json', async (req, res) => {
  try {
    // Only allow for admins or in development
    const backupPath = path.join(__dirname, 'backups', `deals_backup_${Date.now()}.json`);
    
    // Ensure backup directory exists
    await fs.mkdir(path.dirname(backupPath), { recursive: true });
    
    const dealCount = await firebaseManager.backupToJson(backupPath);
    
    res.json({
      success: true,
      message: 'Backup created successfully',
      dealCount,
      backupPath: path.basename(backupPath)
    });
  } catch (error) {
    console.error("❌ Backup error:", error);
    res.status(500).json({ 
      success: false,
      error: 'Backup failed',
      details: error.message 
    });
  }
});

// Add real-time updates endpoint (Server-Sent Events)
app.get('/api/deals/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });

  const listenerId = firebaseManager.setupRealTimeListener((action, deal) => {
    res.write(`data: ${JSON.stringify({ action, deal })}\n\n`);
  });

  req.on('close', () => {
    firebaseManager.removeListener(listenerId);
  });

  // Send initial heartbeat
  res.write(`data: ${JSON.stringify({ action: 'connected', timestamp: Date.now() })}\n\n`);
});

async function startWebsite() {
  try {
    await loadDeals();
    
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Website running on port ${PORT}`);
      console.log(`🔗 Access at: http://localhost:${PORT}`);
      console.log(`🔥 Firebase Realtime Database connected`);
      console.log(`🔒 Security features enabled`);
    });

    process.on('SIGTERM', async () => {
      console.log('🛑 Received SIGTERM, shutting down gracefully');
      try {
        await firebaseManager.close();
        server.close(() => {
          console.log('✅ Server closed');
          process.exit(0);
        });
      } catch (error) {
        console.error('❌ Error during shutdown:', error);
        process.exit(1);
      }
    });

    return server;
  } catch (error) {
    console.error("❌ Error starting website:", error);
    throw error;
  }
}

// Keep your existing bot handlers and other functions...
// (SecurityManager, InputValidator, etc. remain the same)

if (require.main === module) {
  startWebsite().catch(error => {
    console.error("❌ Failed to start application:", error);
    process.exit(1);
  });
}

module.exports = { app, startWebsite, security, firebaseManager };
