// Advanced Security Configuration
const SecurityConfig = {
  // General security settings
  enabled: true,
  debug: process.env.NODE_ENV !== 'production',
  
  // Rate limiting
  rateLimit: {
    general: {
      windowMs: 60000, // 1 minute
      max: 100 // requests per window
    },
    redirect: {
      windowMs: 60000,
      max: 50
    },
    api: {
      windowMs: 60000,
      max: 60
    }
  },
  
  // Bot detection
  botDetection: {
    enabled: true,
    headlessDetection: true,
    fingerprintValidation: true,
    behaviorAnalysis: true,
    strictMode: true // Block on first suspicious activity
  },
  
  // Challenge system
  challenges: {
    enabled: true,
    requiredChallenges: 2,
    mathChallenges: true,
    timingChallenges: true,
    interactionChallenges: true,
    challengeTimeout: 60000 // 1 minute
  },
  
  // Behavioral analysis
  behavior: {
    enabled: true,
    minMouseMovements: 10,
    minScrollEvents: 2,
    minTimeOnSite: 5000, // 5 seconds
    maxSuspicionScore: 50,
    trackingInterval: 30000 // 30 seconds
  },
  
  // URL protection
  urlProtection: {
    enabled: true,
    tokenExpiration: 30000, // 30 seconds
    sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
    maxRedirectsPerSession: 20,
    requireBehaviorValidation: true
  },
  
  // Honeypot system
  honeypots: {
    enabled: true,
    count: 15, // Number of honeypot URLs to generate
    blockDuration: 30 * 60 * 1000, // 30 minutes
    patterns: [
      'honey_trap_',
      'test_deal_',
      'crawler_bait_',
      'bot_trap_',
      'scraper_check_'
    ]
  },
  
  // Security headers
  headers: {
    enforceCSP: true,
    blockFraming: true,
    noSniff: true,
    noIndex: true,
    noReferrer: true,
    hsts: {
      enabled: true,
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  },
  
  // IP blocking
  blocking: {
    enabled: true,
    defaultDuration: 10 * 60 * 1000, // 10 minutes
    severeDuration: 60 * 60 * 1000, // 1 hour
    permanentThreshold: 10, // Block permanently after 10 violations
    whitelist: [], // Whitelisted IPs
    blacklist: [] // Permanently blocked IPs
  },
  
  // Geographic restrictions
  geographic: {
    enabled: false, // Disabled by default
    allowedCountries: ['DE', 'AT', 'CH'], // Germany, Austria, Switzerland
    blockedCountries: [],
    vpnDetection: false
  },
  
  // Advanced features
  advanced: {
    rotatingSecrets: true,
    secretRotationInterval: 60 * 60 * 1000, // 1 hour
    encryptionStrength: 'high',
    auditLogging: true,
    realTimeMonitoring: true,
    autoAdaptive: true // Automatically adjust security based on threats
  },
  
  // Notification system
  notifications: {
    enabled: true,
    telegram: {
      enabled: false, // Set to true to enable Telegram notifications
      chatId: null, // Admin Telegram chat ID
      severityThreshold: 'high'
    },
    email: {
      enabled: false,
      recipients: [],
      severityThreshold: 'critical'
    }
  },
  
  // Performance optimization
  performance: {
    caching: true,
    compressionEnabled: true,
    memoryOptimization: true,
    cleanupInterval: 10 * 60 * 1000, // 10 minutes
    maxMemoryUsage: 500 * 1024 * 1024 // 500MB
  }
};

// Validation functions
SecurityConfig.validate = function() {
  const errors = [];
  
  if (this.rateLimit.general.max > 1000) {
    errors.push('General rate limit too high (max: 1000)');
  }
  
  if (this.challenges.challengeTimeout < 10000) {
    errors.push('Challenge timeout too short (min: 10 seconds)');
  }
  
  if (this.behavior.minTimeOnSite < 1000) {
    errors.push('Minimum time on site too short (min: 1 second)');
  }
  
  if (this.urlProtection.tokenExpiration > 300000) {
    errors.push('Token expiration too long (max: 5 minutes)');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
};

// Environment-specific overrides
if (process.env.NODE_ENV === 'development') {
  SecurityConfig.botDetection.strictMode = false;
  SecurityConfig.challenges.requiredChallenges = 1;
  SecurityConfig.behavior.minTimeOnSite = 1000;
  SecurityConfig.debug = true;
}

if (process.env.NODE_ENV === 'production') {
  SecurityConfig.advanced.auditLogging = true;
  SecurityConfig.advanced.realTimeMonitoring = true;
  SecurityConfig.botDetection.strictMode = true;
}

// Threat level adjustments
SecurityConfig.adjustForThreatLevel = function(level) {
  switch (level) {
    case 'low':
      this.challenges.requiredChallenges = 1;
      this.behavior.maxSuspicionScore = 70;
      this.botDetection.strictMode = false;
      break;
      
    case 'medium':
      this.challenges.requiredChallenges = 2;
      this.behavior.maxSuspicionScore = 50;
      this.botDetection.strictMode = true;
      break;
      
    case 'high':
      this.challenges.requiredChallenges = 3;
      this.behavior.maxSuspicionScore = 30;
      this.botDetection.strictMode = true;
      this.honeypots.count = 25;
      break;
      
    case 'critical':
      this.challenges.requiredChallenges = 4;
      this.behavior.maxSuspicionScore = 20;
      this.botDetection.strictMode = true;
      this.honeypots.count = 50;
      this.blocking.defaultDuration = 60 * 60 * 1000; // 1 hour
      break;
  }
};

module.exports = SecurityConfig;
