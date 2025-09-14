const crypto = require('crypto');
const { promisify } = require('util');

class AdvancedSecurityManager {
  constructor() {
    this.challenges = new Map(); // Active challenges
    this.trustedSessions = new Map(); // Verified human sessions
    this.behaviorProfiles = new Map(); // User behavior tracking
    this.honeypots = new Set(); // Fake URLs for bot detection
    this.geoBlacklist = new Set(); // Suspicious locations
    this.botSignatures = new Map(); // Known bot patterns
    this.rotatingSecrets = []; // Multiple rotating secrets
    
    // Initialize rotating secrets
    this.initializeRotatingSecrets();
    
    // Clean up old data every 10 minutes
    setInterval(() => this.cleanup(), 10 * 60 * 1000);
    
    // Rotate secrets every hour
    setInterval(() => this.rotateSecrets(), 60 * 60 * 1000);
  }

  initializeRotatingSecrets() {
    for (let i = 0; i < 5; i++) {
      this.rotatingSecrets.push(crypto.randomBytes(64).toString('hex'));
    }
  }

  rotateSecrets() {
    // Remove oldest secret and add new one
    this.rotatingSecrets.shift();
    this.rotatingSecrets.push(crypto.randomBytes(64).toString('hex'));
    console.log('🔄 Security secrets rotated');
  }

  getCurrentSecret() {
    return this.rotatingSecrets[this.rotatingSecrets.length - 1];
  }

  isValidSecret(secret) {
    return this.rotatingSecrets.includes(secret);
  }

  // Generate dynamic protection token
  generateProtectionToken(dealId, ip, userAgent) {
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex');
    const challenge = crypto.randomBytes(8).toString('hex');
    
    // Create multiple hash components
    const components = [
      dealId,
      ip,
      timestamp.toString(),
      nonce,
      challenge,
      userAgent.substring(0, 50)
    ];
    
    const hash = crypto.createHmac('sha256', this.getCurrentSecret())
      .update(components.join('|'))
      .digest('hex');

    const token = {
      hash: hash.substring(0, 32),
      timestamp,
      nonce,
      challenge,
      expires: timestamp + (30 * 1000) // 30 seconds
    };

    return Buffer.from(JSON.stringify(token)).toString('base64').replace(/[+/=]/g, '');
  }

  // Validate protection token
  validateProtectionToken(tokenStr, dealId, ip, userAgent) {
    try {
      // Restore base64 padding
      let paddedToken = tokenStr;
      while (paddedToken.length % 4) {
        paddedToken += '=';
      }
      
      const token = JSON.parse(Buffer.from(paddedToken, 'base64').toString());
      
      // Check expiration
      if (Date.now() > token.expires) {
        return { valid: false, reason: 'Token expired' };
      }

      // Recreate hash with all possible secrets (for rotation tolerance)
      for (const secret of this.rotatingSecrets) {
        const components = [
          dealId,
          ip,
          token.timestamp.toString(),
          token.nonce,
          token.challenge,
          userAgent.substring(0, 50)
        ];
        
        const expectedHash = crypto.createHmac('sha256', secret)
          .update(components.join('|'))
          .digest('hex')
          .substring(0, 32);

        if (expectedHash === token.hash) {
          return { valid: true, challenge: token.challenge };
        }
      }

      return { valid: false, reason: 'Invalid token signature' };
    } catch (error) {
      return { valid: false, reason: 'Malformed token' };
    }
  }

  // Generate JavaScript challenge
  generateJavaScriptChallenge(sessionId) {
    const operations = [
      { a: Math.floor(Math.random() * 100), b: Math.floor(Math.random() * 100), op: '+' },
      { a: Math.floor(Math.random() * 50), b: Math.floor(Math.random() * 50), op: '*' },
      { a: Math.floor(Math.random() * 1000), b: Math.floor(Math.random() * 100), op: '-' },
    ];

    const expectedResults = operations.map(op => {
      switch (op.op) {
        case '+': return op.a + op.b;
        case '*': return op.a * op.b;
        case '-': return op.a - op.b;
        default: return 0;
      }
    });

    const challenge = {
      id: crypto.randomBytes(16).toString('hex'),
      operations,
      expectedResults,
      created: Date.now(),
      expires: Date.now() + (60 * 1000), // 1 minute
      completed: false
    };

    this.challenges.set(sessionId, challenge);
    return challenge;
  }

  // Validate JavaScript challenge response
  validateChallenge(sessionId, challengeId, results) {
    const challenge = this.challenges.get(sessionId);
    
    if (!challenge || challenge.id !== challengeId) {
      return false;
    }

    if (Date.now() > challenge.expires) {
      this.challenges.delete(sessionId);
      return false;
    }

    // Validate results
    const isValid = results.length === challenge.expectedResults.length &&
                   results.every((result, index) => result === challenge.expectedResults[index]);

    if (isValid) {
      challenge.completed = true;
      // Create trusted session
      this.trustedSessions.set(sessionId, {
        verified: Date.now(),
        expires: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
      });
    }

    return isValid;
  }

  // Check if session is trusted
  isTrustedSession(sessionId) {
    const session = this.trustedSessions.get(sessionId);
    if (!session) return false;

    if (Date.now() > session.expires) {
      this.trustedSessions.delete(sessionId);
      return false;
    }

    return true;
  }

  // Analyze behavioral patterns
  analyzeBehavior(sessionId, behaviorData) {
    if (!this.behaviorProfiles.has(sessionId)) {
      this.behaviorProfiles.set(sessionId, {
        mouseMovements: 0,
        scrollEvents: 0,
        keystrokes: 0,
        clickPatterns: [],
        timings: [],
        suspicionScore: 0,
        created: Date.now()
      });
    }

    const profile = this.behaviorProfiles.get(sessionId);
    
    // Update behavior data
    if (behaviorData.mouseMove) profile.mouseMovements++;
    if (behaviorData.scroll) profile.scrollEvents++;
    if (behaviorData.keystroke) profile.keystrokes++;
    if (behaviorData.click) {
      profile.clickPatterns.push({
        x: behaviorData.click.x,
        y: behaviorData.click.y,
        timestamp: Date.now()
      });
    }
    if (behaviorData.timing) {
      profile.timings.push(behaviorData.timing);
    }

    // Calculate suspicion score
    this.calculateSuspicionScore(profile);
    
    return profile.suspicionScore < 50; // Threshold for human-like behavior
  }

  calculateSuspicionScore(profile) {
    let score = 0;
    const age = Date.now() - profile.created;

    // Too few mouse movements
    if (age > 30000 && profile.mouseMovements < 10) score += 20;

    // No scroll events
    if (age > 20000 && profile.scrollEvents === 0) score += 15;

    // Click patterns too regular
    if (profile.clickPatterns.length > 3) {
      const intervals = [];
      for (let i = 1; i < profile.clickPatterns.length; i++) {
        intervals.push(profile.clickPatterns[i].timestamp - profile.clickPatterns[i-1].timestamp);
      }
      
      // Check for too regular timing
      if (intervals.length > 2) {
        const avgInterval = intervals.reduce((a, b) => a + b) / intervals.length;
        const variance = intervals.reduce((sum, interval) => sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
        
        if (variance < 100) score += 25; // Too regular = bot-like
      }
    }

    // Response timings analysis
    if (profile.timings.length > 2) {
      const avgTiming = profile.timings.reduce((a, b) => a + b) / profile.timings.length;
      if (avgTiming < 100) score += 20; // Too fast responses
      if (avgTiming > 10000) score += 15; // Suspiciously slow
    }

    profile.suspicionScore = Math.min(score, 100);
  }

  // Generate honeypot URLs
  generateHoneypotUrls(count = 10) {
    const honeypots = [];
    for (let i = 0; i < count; i++) {
      const fakeId = crypto.randomBytes(8).toString('hex');
      const fakeUrl = `/redirect/honey_${fakeId}`;
      this.honeypots.add(fakeUrl);
      honeypots.push(fakeUrl);
    }
    return honeypots;
  }

  // Check if URL is a honeypot
  isHoneypot(url) {
    return this.honeypots.has(url) || url.includes('honey_');
  }

  // Advanced fingerprinting
  generateAdvancedFingerprint(req) {
    const components = [
      req.headers['user-agent'] || '',
      req.headers['accept'] || '',
      req.headers['accept-language'] || '',
      req.headers['accept-encoding'] || '',
      req.headers['sec-ch-ua'] || '',
      req.headers['sec-ch-ua-mobile'] || '',
      req.headers['sec-ch-ua-platform'] || '',
      req.headers['sec-fetch-site'] || '',
      req.headers['sec-fetch-mode'] || '',
      req.headers['sec-fetch-dest'] || '',
      req.headers['dnt'] || '',
      req.headers['upgrade-insecure-requests'] || '',
      req.connection.remoteAddress || req.ip
    ];

    return crypto.createHash('sha256')
      .update(components.filter(c => c).join('|'))
      .digest('hex')
      .substring(0, 24);
  }

  // Detect headless browsers
  isHeadlessBrowser(req) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const headlessSignatures = [
      'headlesschrome',
      'phantomjs',
      'selenium',
      'chromedriver',
      'puppeteer',
      'playwright'
    ];

    if (headlessSignatures.some(sig => userAgent.includes(sig))) {
      return true;
    }

    // Check for missing expected headers in real browsers
    const browserHeaders = [
      'sec-fetch-site',
      'sec-fetch-mode',
      'sec-fetch-dest'
    ];

    const missingHeaders = browserHeaders.filter(header => !req.headers[header]);
    
    // Real browsers should have these headers
    if (userAgent.includes('chrome') && missingHeaders.length > 2) {
      return true;
    }

    return false;
  }

  // Create protected redirect URL
  createProtectedRedirectUrl(dealId, amazonUrl, req) {
    const sessionId = this.generateSessionId(req);
    const token = this.generateProtectionToken(dealId, req.ip, req.headers['user-agent'] || '');
    const fingerprint = this.generateAdvancedFingerprint(req);
    
    // Store the actual Amazon URL temporarily
    const redirectKey = crypto.randomBytes(16).toString('hex');
    this.tempRedirects.set(redirectKey, {
      amazonUrl,
      dealId,
      created: Date.now(),
      expires: Date.now() + (60 * 1000), // 1 minute
      sessionId,
      fingerprint
    });

    return `/secure-redirect/${redirectKey}?token=${token}&session=${sessionId}`;
  }

  generateSessionId(req) {
    const components = [
      req.ip,
      req.headers['user-agent'] || '',
      Date.now().toString(),
      crypto.randomBytes(8).toString('hex')
    ];

    return crypto.createHash('sha256')
      .update(components.join('|'))
      .digest('hex')
      .substring(0, 32);
  }

  // Clean up old data
  cleanup() {
    const now = Date.now();
    
    // Clean up challenges
    for (const [sessionId, challenge] of this.challenges.entries()) {
      if (now > challenge.expires) {
        this.challenges.delete(sessionId);
      }
    }

    // Clean up trusted sessions
    for (const [sessionId, session] of this.trustedSessions.entries()) {
      if (now > session.expires) {
        this.trustedSessions.delete(sessionId);
      }
    }

    // Clean up behavior profiles older than 24 hours
    for (const [sessionId, profile] of this.behaviorProfiles.entries()) {
      if (now - profile.created > 24 * 60 * 60 * 1000) {
        this.behaviorProfiles.delete(sessionId);
      }
    }

    // Clean up temp redirects
    if (this.tempRedirects) {
      for (const [key, redirect] of this.tempRedirects.entries()) {
        if (now > redirect.expires) {
          this.tempRedirects.delete(key);
        }
      }
    }
  }
}

// Initialize with temporary redirects storage
AdvancedSecurityManager.prototype.tempRedirects = new Map();

module.exports = AdvancedSecurityManager;
