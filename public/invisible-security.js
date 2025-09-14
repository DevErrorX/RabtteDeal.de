// Invisible Security System - Zero User Interaction
class InvisibleSecurity {
  constructor() {
    this.sessionId = this.generateSessionId();
    this.fingerprint = this.generateFingerprint();
    this.behaviorScore = 0;
    this.startTime = Date.now();
    this.isHuman = false;
    this.autoValidated = false;
    
    // Start invisible validation immediately
    this.initializeInvisibleValidation();
  }

  generateSessionId() {
    const components = [
      navigator.userAgent,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset(),
      navigator.language,
      Date.now().toString(),
      Math.random().toString(36)
    ];
    return btoa(components.join('|')).substring(0, 32);
  }

  generateFingerprint() {
    // Advanced browser fingerprinting without user interaction
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Fingerprint', 2, 2);
    
    const fingerprint = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      canvas: canvas.toDataURL(),
      webgl: this.getWebGLFingerprint(),
      plugins: Array.from(navigator.plugins || []).map(p => p.name).join(','),
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack,
      hardwareConcurrency: navigator.hardwareConcurrency,
      deviceMemory: navigator.deviceMemory,
      connection: navigator.connection ? navigator.connection.effectiveType : 'unknown',
      touch: 'ontouchstart' in window,
      webdriver: navigator.webdriver,
      automation: this.detectAutomation()
    };

    return btoa(JSON.stringify(fingerprint)).substring(0, 48);
  }

  getWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'no-webgl';
      
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (!debugInfo) return 'no-debug-info';
      
      return gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) + '~' + 
             gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
    } catch (e) {
      return 'webgl-error';
    }
  }

  detectAutomation() {
    const indicators = [];
    
    // Check for automation properties
    if (navigator.webdriver) indicators.push('webdriver');
    if (window.callPhantom) indicators.push('phantom');
    if (window._phantom) indicators.push('phantom2');
    if (window.phantom) indicators.push('phantom3');
    if (window.selenium) indicators.push('selenium');
    if (window.domAutomation) indicators.push('domautomation');
    if (document.$cdc_asdjflasutopfhvcZLmcfl_) indicators.push('chromedriver');
    if (document.$chrome_asyncScriptInfo) indicators.push('chrome-async');
    if (document.__webdriver_script_fn) indicators.push('webdriver-script');

    // Check missing properties that real browsers have
    if (!window.chrome && navigator.userAgent.includes('Chrome')) {
      indicators.push('missing-chrome');
    }

    // Check for unnatural property descriptors
    try {
      const descriptor = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
      if (descriptor && descriptor.get && descriptor.get.toString().includes('return true')) {
        indicators.push('webdriver-override');
      }
    } catch (e) {}

    return indicators;
  }

  initializeInvisibleValidation() {
    // Immediate validations that don't require user interaction
    this.validateBrowserEnvironment();
    this.validateTiming();
    this.startPassiveTracking();
    
    // Auto-validate after minimal time
    setTimeout(() => {
      this.performAutoValidation();
    }, 1000); // 1 second delay
  }

  validateBrowserEnvironment() {
    let score = 100; // Start with full human score

    // Check for automation indicators
    const automation = this.detectAutomation();
    if (automation.length > 0) {
      score -= automation.length * 30; // Heavy penalty for automation
    }

    // Check for missing browser features
    if (!navigator.cookieEnabled) score -= 20;
    if (!navigator.language) score -= 15;
    if (!screen.width || screen.width < 100) score -= 25;

    // Check for headless indicators
    if (navigator.webdriver === true) score -= 50;
    if (!window.outerWidth || !window.outerHeight) score -= 30;

    // Check user agent quality
    const ua = navigator.userAgent;
    if (!ua || ua.length < 50) score -= 40;
    if (ua.includes('HeadlessChrome')) score -= 100;
    if (ua.includes('PhantomJS')) score -= 100;

    // Check for browser-specific properties
    if (ua.includes('Chrome') && !window.chrome) score -= 30;
    if (ua.includes('Firefox') && !navigator.mozGetUserMedia) score -= 20;

    this.behaviorScore = Math.max(score, 0);
    this.isHuman = this.behaviorScore >= 70; // 70% threshold
  }

  validateTiming() {
    const now = Date.now();
    const pageLoadTime = now - performance.timing.navigationStart;
    const domContentLoadedTime = performance.timing.domContentLoadedEventStart - performance.timing.navigationStart;

    // Real browsers take time to load and render
    if (pageLoadTime < 100) this.behaviorScore -= 30; // Too fast
    if (domContentLoadedTime < 50) this.behaviorScore -= 20;

    // Check if page loaded suspiciously fast
    if (document.readyState === 'complete' && pageLoadTime < 200) {
      this.behaviorScore -= 40; // Likely automated
    }
  }

  startPassiveTracking() {
    let interactions = 0;
    let naturalBehavior = 0;

    // Track any user interactions (mouse, keyboard, touch)
    const trackInteraction = (type) => {
      interactions++;
      naturalBehavior += 10;
      if (naturalBehavior > 50) this.isHuman = true;
    };

    // Passive event listeners (don't interfere with user)
    document.addEventListener('mousemove', () => trackInteraction('mouse'), { passive: true });
    document.addEventListener('scroll', () => trackInteraction('scroll'), { passive: true });
    document.addEventListener('keydown', () => trackInteraction('key'), { passive: true });
    document.addEventListener('click', () => trackInteraction('click'), { passive: true });
    document.addEventListener('touchstart', () => trackInteraction('touch'), { passive: true });

    // Check for natural browser events
    window.addEventListener('resize', () => naturalBehavior += 5, { passive: true });
    window.addEventListener('focus', () => naturalBehavior += 3, { passive: true });
    window.addEventListener('blur', () => naturalBehavior += 3, { passive: true });

    // Monitor for 2 seconds maximum
    setTimeout(() => {
      if (interactions > 0) {
        this.behaviorScore += naturalBehavior;
        this.isHuman = true;
      }
    }, 2000);
  }

  performAutoValidation() {
    // Advanced validations without user interaction
    this.validateWindowProperties();
    this.validateNavigatorProperties();
    this.validateDocumentProperties();
    this.validatePerformanceAPI();
    
    // Final human determination
    this.isHuman = this.behaviorScore >= 60 || this.hasNaturalBrowserBehavior();
    this.autoValidated = true;

    // Register as trusted if validated
    if (this.isHuman) {
      this.registerTrustedSession();
    }
  }

  validateWindowProperties() {
    let score = 0;

    // Check for expected window properties
    const expectedProps = [
      'document', 'navigator', 'location', 'history', 'screen',
      'localStorage', 'sessionStorage', 'console', 'setTimeout'
    ];

    expectedProps.forEach(prop => {
      if (window[prop]) score += 5;
    });

    // Check for browser-specific APIs
    if (window.requestAnimationFrame) score += 10;
    if (window.fetch) score += 10;
    if (window.Promise) score += 5;

    this.behaviorScore += score;
  }

  validateNavigatorProperties() {
    let score = 0;

    // Expected navigator properties
    if (navigator.userAgent && navigator.userAgent.length > 50) score += 20;
    if (navigator.language) score += 10;
    if (navigator.languages && navigator.languages.length > 0) score += 15;
    if (navigator.platform) score += 10;
    if (typeof navigator.onLine === 'boolean') score += 5;
    if (navigator.cookieEnabled) score += 10;

    // Hardware info (modern browsers)
    if (navigator.hardwareConcurrency > 0) score += 15;
    if (navigator.deviceMemory) score += 10;

    this.behaviorScore += score;
  }

  validateDocumentProperties() {
    let score = 0;

    // Document should have natural properties
    if (document.readyState) score += 10;
    if (document.title) score += 5;
    if (document.URL) score += 5;
    if (document.referrer !== undefined) score += 10;
    if (document.cookie !== undefined) score += 10;

    // Check for DOM manipulation capabilities
    if (document.createElement) score += 10;
    if (document.querySelector) score += 10;
    if (document.addEventListener) score += 10;

    this.behaviorScore += score;
  }

  validatePerformanceAPI() {
    if (!window.performance) {
      this.behaviorScore -= 30;
      return;
    }

    let score = 20; // Bonus for having performance API

    try {
      // Check performance timing
      const timing = performance.timing;
      if (timing && timing.navigationStart) {
        score += 20;
        
        // Validate realistic timing values
        const loadTime = timing.loadEventEnd - timing.navigationStart;
        if (loadTime > 100 && loadTime < 30000) score += 15; // Realistic load time
      }

      // Check for performance entries
      if (performance.getEntries && performance.getEntries().length > 0) {
        score += 15;
      }
    } catch (e) {
      score -= 10;
    }

    this.behaviorScore += score;
  }

  hasNaturalBrowserBehavior() {
    // Check for natural browser characteristics
    const indicators = [];

    // Realistic screen dimensions
    if (screen.width >= 800 && screen.height >= 600) indicators.push('realistic-screen');

    // Proper timezone
    const timezone = new Date().getTimezoneOffset();
    if (timezone >= -840 && timezone <= 720) indicators.push('valid-timezone');

    // Language settings
    if (navigator.language && navigator.languages) indicators.push('language-settings');

    // Cookie support
    if (navigator.cookieEnabled) indicators.push('cookies-enabled');

    // Plugins (if any - modern browsers may have none)
    if (navigator.plugins !== undefined) indicators.push('plugins-api');

    // WebGL support (common in real browsers)
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl');
      if (gl) indicators.push('webgl-support');
    } catch (e) {}

    return indicators.length >= 4; // Need at least 4 natural indicators
  }

  async registerTrustedSession() {
    try {
      const response = await fetch('/api/security/validate-session', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Session-ID': this.sessionId,
          'X-Fingerprint': this.fingerprint
        },
        body: JSON.stringify({
          sessionId: this.sessionId,
          fingerprint: this.fingerprint,
          behaviorScore: this.behaviorScore,
          isHuman: this.isHuman,
          validationTime: Date.now() - this.startTime
        })
      });

      if (response.ok) {
        console.log('✅ Session validated successfully');
      }
    } catch (error) {
      console.warn('Session validation failed:', error);
    }
  }

  async getProtectedUrl(dealId) {
    if (!this.autoValidated) {
      // Wait for auto-validation to complete (max 3 seconds)
      await new Promise(resolve => {
        const checkValidation = () => {
          if (this.autoValidated || Date.now() - this.startTime > 3000) {
            resolve();
          } else {
            setTimeout(checkValidation, 100);
          }
        };
        checkValidation();
      });
    }

    if (!this.isHuman) {
      // Block suspicious sessions
      console.warn('🚫 Session blocked - bot detected');
      return null;
    }

    try {
      const response = await fetch('/api/security/get-protected-url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Session-ID': this.sessionId,
          'X-Fingerprint': this.fingerprint
        },
        body: JSON.stringify({
          dealId,
          sessionId: this.sessionId,
          fingerprint: this.fingerprint,
          behaviorScore: this.behaviorScore
        })
      });

      if (response.ok) {
        const data = await response.json();
        return data.protectedUrl;
      } else {
        console.warn('🚫 URL protection failed');
        return null;
      }
    } catch (error) {
      console.warn('URL protection error:', error);
      return null;
    }
  }

  // Report security violations without user interaction
  reportViolation(type) {
    fetch('/api/security/violation', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Session-ID': this.sessionId
      },
      body: JSON.stringify({
        type,
        sessionId: this.sessionId,
        fingerprint: this.fingerprint,
        timestamp: Date.now(),
        userAgent: navigator.userAgent
      })
    }).catch(() => {}); // Silent failure
  }
}

// Initialize invisible security immediately
let invisibleSecurity;
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    invisibleSecurity = new InvisibleSecurity();
  });
} else {
  invisibleSecurity = new InvisibleSecurity();
}

// Hook into deal link clicks invisibly
document.addEventListener('click', async (e) => {
  const dealLink = e.target.closest('a[href*="/redirect/"]');
  if (dealLink && !dealLink.href.includes('honey_')) {
    e.preventDefault();
    
    const dealId = dealLink.href.split('/redirect/')[1]?.split('?')[0];
    if (dealId) {
      const protectedUrl = await invisibleSecurity.getProtectedUrl(dealId);
      if (protectedUrl) {
        // Direct redirect - no user interaction needed
        window.location.href = protectedUrl;
      } else {
        // Block silently - could redirect to error page
        invisibleSecurity.reportViolation('access_denied');
      }
    }
  }
});

// Block DevTools and inspection attempts silently
document.addEventListener('keydown', (e) => {
  // Block F12, Ctrl+Shift+I, Ctrl+U, Ctrl+Shift+C
  if (e.keyCode === 123 || 
      (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 67)) ||
      (e.ctrlKey && e.keyCode === 85)) {
    e.preventDefault();
    invisibleSecurity.reportViolation('devtools_attempt');
    return false;
  }
});

// Block right-click silently
document.addEventListener('contextmenu', (e) => {
  e.preventDefault();
  invisibleSecurity.reportViolation('context_menu');
  return false;
});

// Export for potential use
window.InvisibleSecurity = invisibleSecurity;
