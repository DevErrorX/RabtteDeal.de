// Advanced Client-Side Security System
class SecurityClient {
  constructor() {
    this.sessionId = this.generateSessionId();
    this.behaviorData = {
      mouseMovements: 0,
      scrollEvents: 0,
      keystrokes: 0,
      clickPatterns: [],
      timings: [],
      startTime: Date.now()
    };
    
    this.challenges = new Map();
    this.completedChallenges = new Set();
    this.trustedActions = new Set();
    this.initTime = Date.now();
    
    // Track browser environment
    this.browserFingerprint = this.generateBrowserFingerprint();
    
    // Initialize security measures
    this.initializeSecurityMeasures();
    this.startBehaviorTracking();
    this.initializeChallengeSystem();
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

  generateBrowserFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Security fingerprint check', 2, 2);
    
    const fingerprint = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack,
      screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      canvas: canvas.toDataURL(),
      webgl: this.getWebGLFingerprint(),
      fonts: this.getFontFingerprint(),
      plugins: Array.from(navigator.plugins).map(p => p.name).join(','),
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

  getFontFingerprint() {
    const testFonts = [
      'Arial', 'Times New Roman', 'Helvetica', 'Georgia', 'Verdana',
      'Courier New', 'Tahoma', 'Impact', 'Comic Sans MS', 'Trebuchet MS'
    ];
    
    const availableFonts = [];
    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    
    const s = document.createElement('span');
    s.style.fontSize = testSize;
    s.style.position = 'absolute';
    s.style.left = '-9999px';
    s.innerHTML = testString;
    document.body.appendChild(s);
    
    const defaultWidths = {};
    for (const baseFont of baseFonts) {
      s.style.fontFamily = baseFont;
      defaultWidths[baseFont] = s.offsetWidth;
    }
    
    for (const font of testFonts) {
      for (const baseFont of baseFonts) {
        s.style.fontFamily = `${font}, ${baseFont}`;
        if (s.offsetWidth !== defaultWidths[baseFont]) {
          availableFonts.push(font);
          break;
        }
      }
    }
    
    document.body.removeChild(s);
    return availableFonts.join(',');
  }

  detectAutomation() {
    const indicators = [];
    
    // Check for webdriver
    if (navigator.webdriver) indicators.push('webdriver');
    
    // Check for common automation properties
    const automationProps = [
      'window.callPhantom',
      'window._phantom',
      'window.phantom',
      'window.selenium',
      'window.webdriver',
      'document.__webdriver_script_fn',
      'document.$cdc_asdjflasutopfhvcZLmcfl_',
      'document.$chrome_asyncScriptInfo',
      'window.domAutomation',
      'window.domAutomationController'
    ];
    
    automationProps.forEach(prop => {
      if (this.getPropertyByPath(window, prop)) {
        indicators.push(prop.split('.').pop());
      }
    });
    
    // Check for missing properties that real browsers should have
    if (!window.chrome && navigator.userAgent.includes('Chrome')) {
      indicators.push('missing-chrome');
    }
    
    // Check for permission anomalies
    try {
      if (navigator.permissions) {
        navigator.permissions.query({name: 'notifications'}).catch(() => {
          indicators.push('permissions-error');
        });
      }
    } catch (e) {
      indicators.push('permissions-blocked');
    }
    
    return indicators.join(',');
  }

  getPropertyByPath(obj, path) {
    return path.split('.').reduce((current, prop) => {
      return current && current[prop];
    }, obj);
  }

  initializeSecurityMeasures() {
    // Disable common debugging tools
    Object.defineProperty(console, 'clear', {
      get() { return () => {}; },
      set() {}
    });
    
    // Monitor for DevTools
    let devtools = {open: false, orientation: null};
    const threshold = 160;
    
    setInterval(() => {
      if (window.outerHeight - window.innerHeight > threshold || 
          window.outerWidth - window.innerWidth > threshold) {
        if (!devtools.open) {
          devtools.open = true;
          this.handleSecurityViolation('devtools_opened');
        }
      } else {
        devtools.open = false;
      }
    }, 500);
    
    // Block common inspection shortcuts
    document.addEventListener('keydown', (e) => {
      // F12, Ctrl+Shift+I, Ctrl+U, Ctrl+Shift+C
      if (e.keyCode === 123 || 
          (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 67)) ||
          (e.ctrlKey && e.keyCode === 85)) {
        e.preventDefault();
        this.handleSecurityViolation('inspection_attempt');
        return false;
      }
    });
    
    // Block right-click context menu
    document.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      this.handleSecurityViolation('context_menu');
      return false;
    });
    
    // Block text selection on sensitive elements
    document.addEventListener('selectstart', (e) => {
      if (e.target.classList.contains('deal-card') || 
          e.target.closest('.deal-actions')) {
        e.preventDefault();
        return false;
      }
    });
  }

  startBehaviorTracking() {
    // Mouse movement tracking
    document.addEventListener('mousemove', (e) => {
      this.behaviorData.mouseMovements++;
      this.recordBehavior({
        type: 'mouseMove',
        x: e.clientX,
        y: e.clientY,
        timestamp: Date.now()
      });
    });
    
    // Scroll tracking
    document.addEventListener('scroll', () => {
      this.behaviorData.scrollEvents++;
      this.recordBehavior({
        type: 'scroll',
        scrollY: window.scrollY,
        timestamp: Date.now()
      });
    });
    
    // Keystroke tracking
    document.addEventListener('keydown', (e) => {
      this.behaviorData.keystrokes++;
      this.recordBehavior({
        type: 'keystroke',
        keyCode: e.keyCode,
        timestamp: Date.now()
      });
    });
    
    // Click tracking with patterns
    document.addEventListener('click', (e) => {
      const clickData = {
        x: e.clientX,
        y: e.clientY,
        timestamp: Date.now(),
        target: e.target.tagName
      };
      
      this.behaviorData.clickPatterns.push(clickData);
      this.recordBehavior({
        type: 'click',
        ...clickData
      });
    });
    
    // Send behavior data periodically
    setInterval(() => {
      this.sendBehaviorData();
    }, 30000); // Every 30 seconds
  }

  recordBehavior(behavior) {
    // Implement sophisticated timing analysis
    const now = Date.now();
    const timeSinceLastAction = this.lastActionTime ? now - this.lastActionTime : 0;
    this.behaviorData.timings.push(timeSinceLastAction);
    this.lastActionTime = now;
    
    // Keep only recent timings
    if (this.behaviorData.timings.length > 50) {
      this.behaviorData.timings = this.behaviorData.timings.slice(-25);
    }
  }

  async sendBehaviorData() {
    try {
      const response = await fetch('/api/security/behavior', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Session-ID': this.sessionId,
          'X-Fingerprint': this.browserFingerprint
        },
        body: JSON.stringify({
          sessionId: this.sessionId,
          behaviorData: this.behaviorData,
          fingerprint: this.browserFingerprint
        })
      });
      
      if (response.ok) {
        const result = await response.json();
        if (!result.humanLike) {
          this.handleSecurityViolation('suspicious_behavior');
        }
      }
    } catch (error) {
      console.warn('Behavior analysis failed:', error);
    }
  }

  initializeChallengeSystem() {
    // Create invisible challenge elements
    this.createHiddenChallenges();
    
    // Initialize math challenges
    this.mathChallenges = [
      () => this.generateMathChallenge(),
      () => this.generateTimingChallenge(),
      () => this.generateInteractionChallenge()
    ];
  }

  createHiddenChallenges() {
    // Create honeypot links that should never be clicked by humans
    const honeypots = [
      { text: '', class: 'hidden-link', href: '/redirect/honey_trap_1' },
      { text: 'Deals laden...', class: 'loading-fake', href: '/redirect/honey_trap_2' },
      { text: 'Preis aktualisieren', class: 'price-update', href: '/redirect/honey_trap_3' }
    ];
    
    honeypots.forEach((trap, index) => {
      const link = document.createElement('a');
      link.href = trap.href;
      link.textContent = trap.text;
      link.className = trap.class;
      link.style.cssText = `
        position: absolute !important;
        left: -9999px !important;
        width: 1px !important;
        height: 1px !important;
        opacity: 0 !important;
        font-size: 0 !important;
      `;
      
      link.addEventListener('click', (e) => {
        e.preventDefault();
        this.handleSecurityViolation(`honeypot_clicked_${index}`);
        return false;
      });
      
      document.body.appendChild(link);
    });
  }

  async generateMathChallenge() {
    const a = Math.floor(Math.random() * 50) + 1;
    const b = Math.floor(Math.random() * 50) + 1;
    const operations = ['+', '-', '*'];
    const op = operations[Math.floor(Math.random() * operations.length)];
    
    let expectedResult;
    switch (op) {
      case '+': expectedResult = a + b; break;
      case '-': expectedResult = a - b; break;
      case '*': expectedResult = a * b; break;
    }
    
    const challengeId = this.generateChallengeId();
    const challenge = {
      id: challengeId,
      type: 'math',
      question: `${a} ${op} ${b}`,
      expected: expectedResult,
      created: Date.now()
    };
    
    this.challenges.set(challengeId, challenge);
    return challenge;
  }

  generateTimingChallenge() {
    const challengeId = this.generateChallengeId();
    const startTime = Date.now();
    
    const challenge = {
      id: challengeId,
      type: 'timing',
      startTime,
      minTime: 2000, // Minimum 2 seconds
      maxTime: 30000, // Maximum 30 seconds
      created: Date.now()
    };
    
    this.challenges.set(challengeId, challenge);
    return challenge;
  }

  generateInteractionChallenge() {
    const challengeId = this.generateChallengeId();
    const requiredActions = ['mouseMove', 'click', 'scroll'];
    
    const challenge = {
      id: challengeId,
      type: 'interaction',
      requiredActions: [...requiredActions],
      completedActions: [],
      created: Date.now()
    };
    
    this.challenges.set(challengeId, challenge);
    return challenge;
  }

  generateChallengeId() {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
  }

  async solveMathChallenge(challengeId, userAnswer) {
    const challenge = this.challenges.get(challengeId);
    if (!challenge || challenge.type !== 'math') return false;
    
    const isCorrect = parseInt(userAnswer) === challenge.expected;
    if (isCorrect) {
      this.completedChallenges.add(challengeId);
      this.challenges.delete(challengeId);
    }
    
    return isCorrect;
  }

  validateTimingChallenge(challengeId) {
    const challenge = this.challenges.get(challengeId);
    if (!challenge || challenge.type !== 'timing') return false;
    
    const elapsed = Date.now() - challenge.startTime;
    const isValid = elapsed >= challenge.minTime && elapsed <= challenge.maxTime;
    
    if (isValid) {
      this.completedChallenges.add(challengeId);
      this.challenges.delete(challengeId);
    }
    
    return isValid;
  }

  updateInteractionChallenge(challengeId, action) {
    const challenge = this.challenges.get(challengeId);
    if (!challenge || challenge.type !== 'interaction') return false;
    
    if (challenge.requiredActions.includes(action) && 
        !challenge.completedActions.includes(action)) {
      challenge.completedActions.push(action);
    }
    
    const isComplete = challenge.requiredActions.every(action => 
      challenge.completedActions.includes(action));
    
    if (isComplete) {
      this.completedChallenges.add(challengeId);
      this.challenges.delete(challengeId);
      return true;
    }
    
    return false;
  }

  // Enhanced URL protection for deal links
  async protectDealUrl(dealId, originalUrl) {
    // Check if user has completed enough challenges
    if (this.completedChallenges.size < 2) {
      await this.triggerChallengeSequence();
      return null;
    }
    
    // Check behavior score
    if (!await this.validateBehavior()) {
      this.handleSecurityViolation('behavior_validation_failed');
      return null;
    }
    
    // Generate protected URL
    try {
      const response = await fetch('/api/security/protect-url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Session-ID': this.sessionId,
          'X-Fingerprint': this.browserFingerprint,
          'X-Challenge-Count': this.completedChallenges.size.toString()
        },
        body: JSON.stringify({
          dealId,
          originalUrl,
          sessionId: this.sessionId,
          fingerprint: this.browserFingerprint,
          completedChallenges: Array.from(this.completedChallenges)
        })
      });
      
      if (response.ok) {
        const result = await response.json();
        return result.protectedUrl;
      }
    } catch (error) {
      console.warn('URL protection failed:', error);
    }
    
    return null;
  }

  async triggerChallengeSequence() {
    const overlay = this.createChallengeOverlay();
    document.body.appendChild(overlay);
    
    return new Promise((resolve) => {
      this.resolveChallengeSequence = resolve;
    });
  }

  createChallengeOverlay() {
    const overlay = document.createElement('div');
    overlay.className = 'security-challenge-overlay';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.8);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
      backdrop-filter: blur(5px);
    `;
    
    const challengeBox = document.createElement('div');
    challengeBox.className = 'challenge-box';
    challengeBox.style.cssText = `
      background: white;
      padding: 2rem;
      border-radius: 12px;
      text-align: center;
      max-width: 400px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.3);
    `;
    
    // Start with math challenge
    this.displayMathChallenge(challengeBox);
    
    overlay.appendChild(challengeBox);
    return overlay;
  }

  async displayMathChallenge(container) {
    const challenge = await this.generateMathChallenge();
    
    container.innerHTML = `
      <h3>🔐 Sicherheitsprüfung</h3>
      <p>Bitte lösen Sie diese einfache Rechenaufgabe:</p>
      <div style="font-size: 1.5rem; margin: 1rem 0;">
        ${challenge.question} = ?
      </div>
      <input type="number" id="mathAnswer" style="padding: 0.5rem; font-size: 1rem; width: 100px;">
      <div style="margin-top: 1rem;">
        <button id="submitMath" style="padding: 0.5rem 1rem; background: #007bff; color: white; border: none; border-radius: 4px;">
          Bestätigen
        </button>
      </div>
    `;
    
    const input = container.querySelector('#mathAnswer');
    const button = container.querySelector('#submitMath');
    
    const handleSubmit = async () => {
      const answer = input.value;
      if (await this.solveMathChallenge(challenge.id, answer)) {
        container.innerHTML = `
          <h3>✅ Korrekt!</h3>
          <p>Sie werden weitergeleitet...</p>
        `;
        setTimeout(() => {
          const overlay = container.closest('.security-challenge-overlay');
          if (overlay) overlay.remove();
          if (this.resolveChallengeSequence) this.resolveChallengeSequence();
        }, 1500);
      } else {
        input.style.borderColor = 'red';
        input.value = '';
        input.placeholder = 'Falsche Antwort, versuchen Sie es erneut';
      }
    };
    
    button.addEventListener('click', handleSubmit);
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') handleSubmit();
    });
    
    input.focus();
  }

  async validateBehavior() {
    // Check minimum interaction requirements
    const minMouseMoves = 10;
    const minScrolls = 2;
    const timeOnSite = Date.now() - this.initTime;
    const minTimeOnSite = 5000; // 5 seconds
    
    return this.behaviorData.mouseMovements >= minMouseMoves &&
           this.behaviorData.scrollEvents >= minScrolls &&
           timeOnSite >= minTimeOnSite;
  }

  handleSecurityViolation(type) {
    console.warn(`Security violation detected: ${type}`);
    
    // Report to server
    fetch('/api/security/violation', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Session-ID': this.sessionId
      },
      body: JSON.stringify({
        type,
        sessionId: this.sessionId,
        fingerprint: this.browserFingerprint,
        timestamp: Date.now(),
        behaviorData: this.behaviorData
      })
    }).catch(() => {});
    
    // Show security message
    this.showSecurityMessage();
  }

  showSecurityMessage() {
    const existing = document.querySelector('.security-message');
    if (existing) return;
    
    const message = document.createElement('div');
    message.className = 'security-message';
    message.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #dc3545;
      color: white;
      padding: 1rem;
      border-radius: 8px;
      z-index: 9999;
      max-width: 300px;
      box-shadow: 0 10px 20px rgba(0,0,0,0.2);
    `;
    
    message.innerHTML = `
      <strong>🔒 Sicherheitswarnung</strong><br>
      Verdächtige Aktivität erkannt. Der Zugriff wird überwacht.
    `;
    
    document.body.appendChild(message);
    
    setTimeout(() => {
      if (message.parentNode) {
        message.parentNode.removeChild(message);
      }
    }, 5000);
  }
}

// Initialize security client when page loads
let securityClient;
document.addEventListener('DOMContentLoaded', () => {
  securityClient = new SecurityClient();
  
  // Hook into existing deal button clicks
  document.addEventListener('click', async (e) => {
    const dealButton = e.target.closest('.btn-primary[href*="/redirect/"]');
    if (dealButton && !dealButton.href.includes('honey_')) {
      e.preventDefault();
      
      const originalUrl = dealButton.href;
      const dealId = originalUrl.split('/redirect/')[1]?.split('?')[0];
      
      if (dealId) {
        const protectedUrl = await securityClient.protectDealUrl(dealId, originalUrl);
        if (protectedUrl) {
          window.open(protectedUrl, '_blank', 'noopener,noreferrer');
        } else {
          securityClient.handleSecurityViolation('url_protection_failed');
        }
      }
    }
  });
  
  // Update interaction challenges based on user behavior
  document.addEventListener('mousemove', () => {
    Array.from(securityClient.challenges.values())
      .filter(c => c.type === 'interaction')
      .forEach(c => securityClient.updateInteractionChallenge(c.id, 'mouseMove'));
  });
  
  document.addEventListener('scroll', () => {
    Array.from(securityClient.challenges.values())
      .filter(c => c.type === 'interaction')
      .forEach(c => securityClient.updateInteractionChallenge(c.id, 'scroll'));
  });
  
  document.addEventListener('click', () => {
    Array.from(securityClient.challenges.values())
      .filter(c => c.type === 'interaction')
      .forEach(c => securityClient.updateInteractionChallenge(c.id, 'click'));
  });
});

// Export for potential external use
window.SecurityClient = SecurityClient;
