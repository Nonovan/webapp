/**
 * Common authentication-related JavaScript functions
 * 
 * This file contains shared functionality for login and registration forms
 * to improve maintainability, security, and code reuse.
 * 
 * Security features implemented:
 * - Password strength checking using NIST 800-63B guidelines
 * - Visual password requirement feedback
 * - Client-side brute force protection
 * - Form validation with immediate feedback
 * - reCAPTCHA integration
 * - Secure form submission helpers
 */

/**
 * Toggles password visibility between text and password types
 * @param {string} passwordId - The ID of the password input element
 * @param {string} toggleId - The ID of the toggle button element
 */
function togglePasswordVisibility(passwordId, toggleId) {
  const passwordInput = document.getElementById(passwordId);
  const toggleButton = document.getElementById(toggleId);
  
  if (!passwordInput || !toggleButton) return;
  
  toggleButton.addEventListener('click', function() {
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    
    const icon = this.querySelector('i');
    if (icon) {
      icon.classList.toggle('bi-eye');
      icon.classList.toggle('bi-eye-slash');
    }
    
    // Focus back on password field for better UX
    passwordInput.focus();
  });
}

/**
 * Checks password strength according to NIST 800-63B guidelines
 * @param {string} password - The password to check
 * @returns {number} Strength score between 0-4
 */
function checkPasswordStrength(password) {
  let strength = 0;
  
  // No strength if empty
  if (!password) return 0;
  
  // NIST recommends 8+ chars, we require 12+
  if (password.length >= 12) strength++; 
  
  // Check character diversity
  if (password.match(/[a-z]/)) strength++;
  if (password.match(/[A-Z]/)) strength++;
  if (password.match(/[0-9]/)) strength++;
  if (password.match(/[^A-Za-z0-9]/)) strength++; // Special characters
  
  // Detect common patterns that weaken passwords
  const commonPatterns = [
    /12345/, /qwerty/i, /password/i, /admin/i, /welcome/i, 
    /abc123/i, /(.)\\1{2,}/  // Repeating characters
  ];
  
  for (const pattern of commonPatterns) {
    if (pattern.test(password)) {
      strength = Math.max(1, strength - 1); // Reduce strength but don't go below 1
      break;
    }
  }
  
  return Math.min(4, strength);
}

/**
 * Returns the Bootstrap color class for a given password strength
 * @param {number} strength - Strength value between 0-4
 * @returns {string} Bootstrap color class
 */
function getStrengthColor(strength) {
  const colors = ['danger', 'warning', 'info', 'primary', 'success'];
  return colors[strength] || 'danger';
}

/**
 * Sets up password strength meter on registration forms
 * @param {string} passwordId - ID of password input
 * @param {string} strengthBarId - ID of strength progress bar
 * @param {string} strengthTextId - ID of password strength text
 */
function setupPasswordStrengthMeter(passwordId, strengthBarId, strengthTextId) {
  const passwordInput = document.getElementById(passwordId);
  const progressBar = document.querySelector(strengthBarId);
  const strengthText = document.querySelector(strengthTextId);
  
  if (!passwordInput || !progressBar || !strengthText) return;

  // Initial state
  updateStrengthMeter('');
  
  // Update on password change
  passwordInput.addEventListener("input", function() {
    updateStrengthMeter(this.value);
  });
  
  function updateStrengthMeter(password) {
    const strength = checkPasswordStrength(password);
    const strengthLabels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"];
    
    progressBar.style.width = `${strength * 25}%`;
    progressBar.className = `progress-bar bg-${getStrengthColor(strength)}`;
    strengthText.textContent = `Password strength: ${strengthLabels[strength] || "Very Weak"}`;
    
    // Add ARIA attributes for accessibility
    progressBar.setAttribute('aria-valuenow', strength * 25);
    progressBar.setAttribute('aria-valuetext', strengthLabels[strength] || "Very Weak");
    
    // Add more descriptive feedback for screen readers
    progressBar.setAttribute('aria-description', `Password strength level ${strength + 1} out of 5`);
  }
}

/**
 * Sets up password matching validation for registration forms
 * @param {string} passwordId - ID of password input
 * @param {string} confirmId - ID of confirm password input
 */
function setupPasswordMatchValidation(passwordId, confirmId) {
  const passwordInput = document.getElementById(passwordId);
  const confirmInput = document.getElementById(confirmId);
  
  if (!passwordInput || !confirmInput) return;
  
  // Check match on input to both fields
  const checkMatch = () => {
    if (confirmInput.value && confirmInput.value !== passwordInput.value) {
      confirmInput.setCustomValidity('Passwords do not match');
      confirmInput.classList.add('is-invalid');
      
      // Add a data attribute for custom styling
      confirmInput.setAttribute('data-validation-state', 'invalid');
      
      // Update feedback message if a feedback element exists
      const feedbackElement = confirmInput.nextElementSibling?.classList.contains('invalid-feedback') ? 
        confirmInput.nextElementSibling : document.querySelector(`[data-feedback-for="${confirmId}"]`);
      
      if (feedbackElement) {
        feedbackElement.textContent = 'The passwords you entered do not match.';
      }
    } else {
      confirmInput.setCustomValidity('');
      confirmInput.classList.remove('is-invalid');
      confirmInput.removeAttribute('data-validation-state');
    }
  };
  
  confirmInput.addEventListener('input', checkMatch);
  passwordInput.addEventListener('input', checkMatch);
  
  // Also check when fields lose focus
  confirmInput.addEventListener('blur', checkMatch);
}

/**
 * Updates password requirement indicators based on password content
 * @param {string} passwordId - ID of password input
 * @param {string} requirementListId - ID of requirements list element
 */
function setupPasswordRequirementsFeedback(passwordId, requirementListId) {
  const passwordInput = document.getElementById(passwordId);
  const requirementList = document.getElementById(requirementListId);
  
  if (!passwordInput || !requirementList) return;
  
  // Create dictionary for requirements with human-readable descriptions
  const requirementDescriptions = {
    length: "At least 12 characters long",
    lowercase: "Contains lowercase letters (a-z)",
    uppercase: "Contains uppercase letters (A-Z)",
    number: "Contains numbers (0-9)",
    special: "Contains special characters (!@#$%, etc.)",
    noCommon: "No common patterns or dictionary words"
  };
  
  // Populate requirement list if it's empty
  if (requirementList.children.length === 0) {
    Object.entries(requirementDescriptions).forEach(([req, description]) => {
      const item = document.createElement('li');
      item.setAttribute('data-requirement', req);
      item.className = 'text-muted';
      item.innerHTML = `• ${description}`;
      requirementList.appendChild(item);
    });
  }
  
  // Initialize requirement states
  updateRequirements('');
  
  // Update on password change
  passwordInput.addEventListener('input', function() {
    updateRequirements(this.value);
    
    // Update form validity based on all requirements being met
    const allRequirementsMet = Array.from(requirementList.children)
      .every(item => item.classList.contains('text-success'));
      
    if (!allRequirementsMet && this.value.length > 0) {
      this.setCustomValidity('Password does not meet all requirements');
    } else {
      this.setCustomValidity('');
    }
  });
  
  function updateRequirements(password) {
    const requirements = {
      length: password.length >= 12,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password)
    };
    
    Object.entries(requirements).forEach(([req, met]) => {
      const item = requirementList.querySelector(`[data-requirement="${req}"]`);
      if (item) {
        item.classList.toggle('text-success', met);
        item.classList.toggle('text-muted', !met);
        const icon = met ? '✓' : '•';
        item.innerHTML = `${icon} ${item.innerHTML.replace(/^[✓•] /, '')}`;
      }
    });
  }
}

/**
 * Sets up form validation using Bootstrap validation classes
 */
function setupFormValidation() {
  const forms = document.querySelectorAll('.needs-validation');
  
  Array.from(forms).forEach(form => {
    // Prevent submission if validation fails
    form.addEventListener('submit', event => {
      if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
      }
      form.classList.add('was-validated');
    }, false);
    
    // Live validation as user types
    const inputs = form.querySelectorAll('input, select, textarea');
    inputs.forEach(input => {
      input.addEventListener('blur', () => {
        if (input.value) {
          input.classList.add('was-validated');
        }
      });
    });
  });
}

/**
 * Tracks login attempts to prevent brute force attacks
 * @param {HTMLElement} form - The login form element
 * @param {string} submitBtnId - ID of the submit button
 */
function setupBruteForceProtection(form, submitBtnId) {
  if (!form) return;
  
  // Get stored attempt data with expiry check
  const getAttemptData = () => {
    try {
      const data = localStorage.getItem('loginAttemptData');
      if (!data) return { count: 0, timestamp: Date.now() };
      
      const parsed = JSON.parse(data);
      // Reset if older than 30 minutes
      if (Date.now() - parsed.timestamp > 30 * 60 * 1000) {
        return { count: 0, timestamp: Date.now() };
      }
      return parsed;
    } catch (e) {
      console.warn("Error accessing localStorage:", e);
      return { count: 0, timestamp: Date.now() };
    }
  };
  
  // Update stored attempt data
  const setAttemptData = (data) => {
    try {
      localStorage.setItem('loginAttemptData', JSON.stringify(data));
    } catch (e) {
      console.warn("Error writing to localStorage:", e);
    }
  };
  
  form.addEventListener('submit', function(e) {
    const attemptData = getAttemptData();
    attemptData.count++;
    attemptData.timestamp = Date.now();
    setAttemptData(attemptData);
    
    // Progressive delay based on number of attempts
    if (attemptData.count > 3) {
      const submitBtn = document.getElementById(submitBtnId);
      if (submitBtn) {
        submitBtn.disabled = true;
        
        // Exponential backoff: 1s, 2s, 4s, 8s...
        const delay = Math.min(Math.pow(2, attemptData.count - 3) * 1000, 30000);
        
        setTimeout(() => {
          submitBtn.disabled = false;
        }, delay);
        
        if (attemptData.count > 5) {
          // Show warning after multiple attempts
          showToastIfAvailable("Security Alert", 
            "Multiple failed login attempts detected. Please verify your credentials.", 
            "warning");
        }
      }
    }
  });
}

/**
 * reCAPTCHA callback for enabling submit buttons
 * @param {string} token - reCAPTCHA verification token
 */
function onRecaptchaVerified(token) {
  if (token) {
    const submitButton = document.querySelector('button[type="submit"][disabled]');
    if (submitButton) {
      submitButton.removeAttribute('disabled');
    }
  }
}

/**
 * Shows a toast message if the toast function is available
 * @param {string} title - Toast title
 * @param {string} message - Toast message
 * @param {string} type - Toast type (success, danger, warning, info)
 */
function showToastIfAvailable(title, message, type = "info") {
  // Check if the global showToast function exists
  if (typeof window.showToast === 'function') {
    window.showToast(title, message, type);
  } else {
    console.log(`${type.toUpperCase()}: ${title} - ${message}`);
  }
}

/**
 * Perform a secure fetch with CSRF protection
 * @param {string} url - URL to fetch
 * @param {Object} options - Fetch options
 * @returns {Promise} - Fetch promise
 */
function secureFetch(url, options = {}) {
  // Get the CSRF token from the meta tag
  const tokenElement = document.querySelector('meta[name="csrf-token"]');
  const token = tokenElement ? tokenElement.getAttribute('content') : '';
  
  // Set default options with CSRF token
  const defaultOptions = {
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': token,
      ...options.headers
    }
  };
  
  // Merge options
  const finalOptions = {...defaultOptions, ...options};
  
  // Return fetch promise
  return fetch(url, finalOptions);
}

document.addEventListener('DOMContentLoaded', function() {
    // Initialize auth components
    togglePasswordVisibility('password', 'togglePassword');
    setupFormValidation();
    setupBruteForceProtection(document.querySelector('form'), 'loginButton');
    
    // reCAPTCHA callback defined globally for Google API usage
    window.onRecaptchaVerified = function() {
        const loginButton = document.getElementById('loginButton');
        if (loginButton) {
            loginButton.disabled = false;
        }
    };

    // Add login button loading state
    const submitBtn = document.getElementById("loginButton");
    if (submitBtn) {
        submitBtn.addEventListener("click", function() {
            if (document.querySelector('form').checkValidity()) {
                const spinner = this.querySelector(".spinner-border");
                if (spinner) {
                    spinner.classList.remove("d-none");
                }
            }
        });
    }
    
    // Handle account lockout if present
    // This should be handled by server-side code rather than Jinja template syntax in JS
    const isAccountLocked = document.querySelector('.alert-danger[data-lockout="true"]') !== null;
    if (isAccountLocked && submitBtn) {
        submitBtn.disabled = true;
        setTimeout(() => {
            submitBtn.disabled = false;
        }, 5000); // Short delay to prevent rapid retries
    }
});