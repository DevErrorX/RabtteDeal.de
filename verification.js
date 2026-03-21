const crypto = require('crypto');

class VerificationSystem {
  constructor(webhookSecret) {
    this.secret = webhookSecret || crypto.randomBytes(32).toString('hex');
    this.challenges = new Map();
    this.tokens = new Map();
    this.redirects = new Map();
    this.blockedFingerprints = new Set();
    this.honeypots = new Set();
    this.tokenUsage = new Map();
    this.requestLog = new Map();
    this.otTokens = new Map();
    this.fpRequests = new Map();

    this._generateHoneypots();
    setInterval(() => this._cleanup(), 5 * 60 * 1000);
  }

  // ==================== CHALLENGE MANAGEMENT ====================

  createChallenge() {
    const challenge = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(8).toString('hex');

    this.challenges.set(challenge, {
      nonce,
      created: Date.now(),
      expires: Date.now() + 60000,
      solved: false
    });

    return { challenge, nonce, difficulty: 3 };
  }

  validateSolution(challenge, nonce, solution) {
    const data = this.challenges.get(challenge);
    if (!data) { console.log('❌ Challenge not found'); return false; }
    if (Date.now() > data.expires) { console.log('❌ Challenge expired'); return false; }
    if (data.solved) { console.log('❌ Challenge already solved'); return false; }

    const hash = crypto.createHash('sha256')
      .update(challenge + nonce + solution)
      .digest('hex');

    const valid = hash.startsWith('000');
    if (!valid) console.log(`❌ PoW hash mismatch: ${hash.substring(0, 10)}... (need 000...)`);
    data.solved = valid;
    return valid;
  }

  // ==================== TOKEN MANAGEMENT ====================

  issueToken(fingerprint, ip) {
    const token = crypto.randomBytes(32).toString('hex');
    const now = Date.now();

    this.tokens.set(token, {
      fingerprint,
      ip,
      created: now,
      expires: now + 600000,
      requests: 0,
      usedRedirects: new Set()
    });

    return { token, expires: now + 600000 };
  }

  validateToken(token, fingerprint, ip) {
    if (!token) return false;

    const data = this.tokens.get(token);
    if (!data) return false;

    if (Date.now() > data.expires) {
      this.tokens.delete(token);
      return false;
    }

    if (data.fingerprint !== fingerprint) return false;
    if (data.ip !== ip) return false;

    data.requests++;

    // Anti-sharing: detect token used by multiple clients
    const usageKey = `usage_${token}`;
    const usage = this.tokenUsage.get(usageKey) || new Set();
    usage.add(fingerprint);
    this.tokenUsage.set(usageKey, usage);

    if (usage.size > 1) {
      this.tokens.delete(token);
      this.blockedFingerprints.add(fingerprint);
      return false;
    }

    return true;
  }

  // ==================== REDIRECT MANAGEMENT ====================

  storeRedirect(dealId, amazonUrl, fingerprint, ip) {
    const key = crypto.randomBytes(16).toString('hex');
    this.redirects.set(key, {
      dealId, amazonUrl, fingerprint, ip,
      created: Date.now(),
      expires: Date.now() + 15000
    });
    return key;
  }

  validateAndConsumeRedirect(key, fingerprint, ip) {
    const data = this.redirects.get(key);
    if (!data || Date.now() > data.expires) {
      this.redirects.delete(key);
      return null;
    }
    if (data.fingerprint !== fingerprint) return null;
    this.redirects.delete(key);
    return data.amazonUrl;
  }

  // ==================== ONE-TIME TOKENS ====================

  issueOTToken(fingerprint, ip) {
    const token = crypto.randomBytes(24).toString('hex');
    this.otTokens.set(token, {
      fingerprint, ip,
      created: Date.now(),
      expires: Date.now() + 30000
    });
    return token;
  }

  consumeOTToken(token, fingerprint, ip) {
    if (!token) return false;
    const data = this.otTokens.get(token);
    if (!data) return false;
    if (Date.now() > data.expires) { this.otTokens.delete(token); return false; }
    if (data.fingerprint !== fingerprint) return false;
    // Don't check IP - Cloudflare changes edge IPs between requests
    this.otTokens.delete(token);
    return true;
  }

  // ==================== RATE LIMITING PER FINGERPRINT ====================

  checkFPLimit(fingerprint, max = 30, windowMs = 3600000) {
    if (!fingerprint) return false;
    const now = Date.now();
    const log = this.fpRequests.get(fingerprint) || [];

    // Clean old entries
    const recent = log.filter(t => now - t < windowMs);

    // Block if too many requests
    if (recent.length >= max) return false;

    // Behavioral detection: if last 3 requests were within 10 seconds, block
    if (recent.length >= 3) {
      const last3 = recent.slice(-3);
      if (last3[2] - last3[0] < 10000) {
        console.warn(`🚫 Aggressive scraping detected from FP: ${fingerprint.substring(0, 20)}...`);
        this.blockedFingerprints.add(fingerprint);
        return false;
      }
    }

    // Minimum 1 second between requests
    const lastReq = recent[recent.length - 1] || 0;
    if (now - lastReq < 1000) return false;

    recent.push(now);
    this.fpRequests.set(fingerprint, recent);
    return true;
  }

  // ==================== BOT DETECTION ====================

  detectBot(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const botPatterns = [
      'headlesschrome', 'phantomjs', 'selenium', 'chromedriver',
      'puppeteer', 'playwright', 'slimerjs', 'electron',
      'curl/', 'wget/', 'python-requests', 'python-urllib',
      'go-http-client', 'java/', 'apache-httpclient', 'node-fetch',
      'axios/', 'scrapy', 'httpx', 'got/', 'request/',
      'crawler', 'bot/', 'spider', 'scraper'
    ];

    if (botPatterns.some(p => ua.includes(p))) return true;
    if (!req.headers['accept-language'] || !req.headers['accept-encoding']) return true;

    const fp = req.headers['x-browser-fingerprint'] || '';
    if (fp && !fp.includes('canvas') && !fp.includes('webgl')) return true;

    return false;
  }

  // ==================== HONEYPOT ====================

  _generateHoneypots() {
    for (let i = 0; i < 10; i++) {
      const id = crypto.randomBytes(8).toString('hex');
      const url = `/redirect/honey_${id}`;
      this.honeypots.add(url);
    }
  }

  isHoneypot(url) {
    return this.honeypots.has(url) || url.includes('honey_');
  }

  getHoneypotUrls() {
    return [...this.honeypots];
  }

  // ==================== MIDDLEWARE ====================

  botDetectionMiddleware() {
    return (req, res, next) => {
      if (this.detectBot(req)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      next();
    };
  }

  tokenRequired() {
    return (req, res, next) => {
      const token = req.headers['x-verify-token'] || req.query._vt;
      const fingerprint = req.headers['x-browser-fingerprint'] || '';
      const ip = req.ip || req.connection?.remoteAddress;

      if (!token || !fingerprint) {
        return res.status(401).json({
          error: 'verification_required',
          message: 'Browser verification required'
        });
      }

      if (this.blockedFingerprints.has(fingerprint)) {
        return res.status(403).json({ error: 'Access denied' });
      }

      if (!this.validateToken(token, fingerprint, ip)) {
        return res.status(401).json({
          error: 'verification_required',
          message: 'Token invalid or expired'
        });
      }

      next();
    };
  }

  rateLimit(maxRequests = 100, windowMs = 60000) {
    return (req, res, next) => {
      const token = req.headers['x-verify-token'] || '';
      if (!token) return next();

      const now = Date.now();
      const log = this.requestLog.get(token) || [];
      const recent = log.filter(t => now - t < windowMs);

      if (recent.length >= maxRequests) {
        return res.status(429).json({ error: 'Rate limit exceeded' });
      }

      recent.push(now);
      this.requestLog.set(token, recent);
      next();
    };
  }

  // ==================== UTILITIES ====================

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  getStats() {
    return {
      activeChallenges: this.challenges.size,
      activeTokens: this.tokens.size,
      oneTimeTokens: this.otTokens.size,
      pendingRedirects: this.redirects.size,
      blockedFingerprints: this.blockedFingerprints.size,
      honeypots: this.honeypots.size,
      trackedFingerprints: this.fpRequests.size
    };
  }

  // ==================== CLEANUP ====================

  _cleanup() {
    const now = Date.now();

    for (const [k, v] of this.challenges) {
      if (now > v.expires) this.challenges.delete(k);
    }
    for (const [k, v] of this.tokens) {
      if (now > v.expires) this.tokens.delete(k);
    }
    for (const [k, v] of this.otTokens) {
      if (now > v.expires) this.otTokens.delete(k);
    }
    for (const [k, v] of this.redirects) {
      if (now > v.expires) this.redirects.delete(k);
    }
    for (const [k, v] of this.fpRequests) {
      const recent = v.filter(t => now - t < 3600000);
      if (recent.length === 0) this.fpRequests.delete(k);
      else this.fpRequests.set(k, recent);
    }
    for (const [k, v] of this.tokenUsage) {
      if (v.size === 0) this.tokenUsage.delete(k);
    }
    for (const [k, v] of this.requestLog) {
      const recent = v.filter(t => now - t < 300000);
      if (recent.length === 0) this.requestLog.delete(k);
      else this.requestLog.set(k, recent);
    }
    if (Math.random() > 0.7) {
      this.blockedFingerprints.clear();
    }
  }
}

module.exports = VerificationSystem;
