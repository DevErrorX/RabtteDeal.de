// Invisible Security Configuration
const InvisibleSecurityConfig = {
  // No user interaction required
  userInteraction: {
    challenges: false,          // No math problems or challenges
    popups: false,             // No popup windows
    confirmations: false,      // No confirmation dialogs
    notifications: false       // No visible notifications
  },
  
  // Behavioral detection without interaction
  detection: {
    // Browser fingerprinting
    fingerprinting: {
      enabled: true,
      canvas: true,
      webgl: true,
      fonts: true,
      plugins: true,
      hardware: true,
      timezone: true
    },
    
    // Automation detection
    automation: {
      webdriver: true,          // Check navigator.webdriver
      headless: true,           // Detect headless browsers
      selenium: true,           // Detect Selenium
      phantom: true,            // Detect PhantomJS
      puppeteer: true,          // Detect Puppeteer
      chrome: true              // Check missing Chrome properties
    },
    
    // Environment validation
    environment: {
      windowProperties: true,    // Validate window object
      navigatorProperties: true, // Validate navigator object
      documentProperties: true,  // Validate document object
      performanceAPI: true,      // Check Performance API
      timingValidation: true     // Validate page load timings
    }
  },
  
  // Scoring system
  scoring: {
    humanThreshold: 60,         // Minimum score to be considered human
    automationPenalty: 30,      // Points deducted per automation indicator
    environmentBonus: {
      validBrowser: 20,
      realisticTiming: 15,
      properHeaders: 10,
      webglSupport: 10,
      cookiesEnabled: 10
    }
  },
  
  // URL protection
  urlProtection: {
    enabled: true,
    tokenExpiration: 60000,     // 1 minute (longer for no user interaction)
    oneTimeUse: true,           // URLs can only be used once
    ipBinding: true,            // Bind URLs to IP address
    sessionValidation: true,    // Require valid session
    encryptionStrength: 'high'  // Strong encryption
  },
  
  // Session management
  sessions: {
    duration: 24 * 60 * 60 * 1000,  // 24 hours
    autoValidation: true,            // Validate automatically
    passiveTracking: true,           // Track without interference
    maxValidationTime: 3000          // 3 seconds max validation time
  },
  
  // Blocking behavior
  blocking: {
    silentBlock: true,          // Block without showing errors
    logViolations: true,        // Log all violations
    ipBlocking: true,           // Block IP addresses
    duration: {
      light: 10 * 60 * 1000,   // 10 minutes for light violations
      severe: 60 * 60 * 1000,  // 1 hour for severe violations
      honeypot: 24 * 60 * 60 * 1000  // 24 hours for honeypot access
    }
  },
  
  // Honeypot system
  honeypots: {
    enabled: true,
    count: 20,                  // More honeypots for better coverage
    invisible: true,            // Completely invisible to users
    patterns: [
      'honey_',
      'bot_trap_',
      'crawler_',
      'scraper_',
      'test_deal_',
      'fake_offer_',
      'hidden_link_',
      'auto_detect_'
    ]
  },
  
  // Performance optimization
  performance: {
    asyncValidation: true,      // Don't block page loading
    minimimalImpact: true,      // Optimize for speed
    backgroundProcessing: true, // Process in background
    memoryEfficient: true       // Use minimal memory
  },
  
  // Advanced detection methods
  advanced: {
    // Timing attacks
    timing: {
      pageLoadAnalysis: true,
      responseTimeAnalysis: true,
      renderingTimeCheck: true
    },
    
    // Network analysis
    network: {
      headerAnalysis: true,
      connectionAnalysis: false,  // May impact performance
      geoIpChecking: false       // Disabled for privacy
    },
    
    // Browser API validation
    apis: {
      webrtc: true,
      mediaDevices: true,
      batteryAPI: false,         // Deprecated
      gamepadAPI: true,
      vibrationAPI: true
    }
  },
  
  // Failure handling
  failureHandling: {
    gracefulDegradation: true,  // Allow access if validation fails
    fallbackToBasic: false,     // Don't fall back to basic protection
    errorLogging: true,         // Log errors for debugging
    retryAttempts: 2           // Number of validation retries
  }
};

// Validation function
InvisibleSecurityConfig.validate = function() {
  const errors = [];
  
  if (this.scoring.humanThreshold < 30 || this.scoring.humanThreshold > 90) {
    errors.push('Human threshold should be between 30-90');
  }
  
  if (this.urlProtection.tokenExpiration > 300000) {
    errors.push('Token expiration too long (max: 5 minutes)');
  }
  
  if (this.sessions.duration > 7 * 24 * 60 * 60 * 1000) {
    errors.push('Session duration too long (max: 7 days)');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
};

// Environment-specific settings
if (typeof process !== 'undefined' && process.env) {
  if (process.env.NODE_ENV === 'development') {
    InvisibleSecurityConfig.scoring.humanThreshold = 40;
    InvisibleSecurityConfig.failureHandling.gracefulDegradation = true;
    InvisibleSecurityConfig.blocking.silentBlock = false; // Show errors in dev
  }
  
  if (process.env.NODE_ENV === 'production') {
    InvisibleSecurityConfig.scoring.humanThreshold = 70;
    InvisibleSecurityConfig.blocking.silentBlock = true;
    InvisibleSecurityConfig.advanced.timing.pageLoadAnalysis = true;
  }
}

// Export for both Node.js and browser
if (typeof module !== 'undefined' && module.exports) {
  module.exports = InvisibleSecurityConfig;
} else if (typeof window !== 'undefined') {
  window.InvisibleSecurityConfig = InvisibleSecurityConfig;
}
