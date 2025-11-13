// Employee Portal - Client-side interactions
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initSidebarToggle();
  initDropdown();
  initFormValidation();
  initStatusBadges();
  autoHideFlashMessages();
});

// Theme Management
function initTheme() {
  const savedTheme = localStorage.getItem("theme") || "light";
  setTheme(savedTheme);
  createThemeToggle();
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("theme", theme);
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
  const newTheme = currentTheme === "light" ? "dark" : "light";
  setTheme(newTheme);
}

function createThemeToggle() {
  // Check if theme toggle already exists
  if (document.querySelector(".theme-toggle")) {
    return;
  }

  const toggle = document.createElement("button");
  toggle.className = "theme-toggle";
  toggle.setAttribute("aria-label", "Toggle theme");
  const icon = document.createElement("span");
  icon.className = "material-symbols-outlined";
  icon.textContent = "dark_mode";
  toggle.appendChild(icon);

  toggle.addEventListener("click", () => {
    toggleTheme();
    const icon = toggle.querySelector(".material-symbols-outlined");
    const currentTheme = document.documentElement.getAttribute("data-theme");
    icon.textContent = currentTheme === "dark" ? "light_mode" : "dark_mode";
  });

  // Set initial icon
  const currentTheme = document.documentElement.getAttribute("data-theme");
  if (currentTheme === "dark") {
    toggle.querySelector(".material-symbols-outlined").textContent = "light_mode";
  }

  // Append to header-actions instead of body
  const customHost = document.querySelector(".theme-toggle-host");
  const headerActions = document.querySelector(".header-actions");

  if (customHost) {
    customHost.appendChild(toggle);
  } else if (headerActions) {
    headerActions.appendChild(toggle);
  } else {
    // Fallback to body if no host container exists
    document.body.appendChild(toggle);
  }
}


// Sidebar navigation toggle functionality with overlay
function initSidebarToggle() {
  const menuToggle = document.getElementById("menuToggle");
  const sidebar = document.getElementById("appSidebar");
  const overlay = document.getElementById("sidebarOverlay");

  if (!menuToggle || !sidebar || !overlay) return;

  const toggleSidebar = () => {
    const isActive = sidebar.classList.toggle("active");
    overlay.classList.toggle("active");
    document.body.classList.toggle("sidebar-open", isActive);
    menuToggle.setAttribute("aria-expanded", isActive);
  };

  const closeSidebar = () => {
    sidebar.classList.remove("active");
    overlay.classList.remove("active");
    document.body.classList.remove("sidebar-open");
    menuToggle.setAttribute("aria-expanded", "false");
  };

  menuToggle.addEventListener("click", toggleSidebar);

  // Close sidebar when clicking overlay
  overlay.addEventListener("click", closeSidebar);

  // Close sidebar on Escape key press
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && sidebar.classList.contains("active")) {
      closeSidebar();
    }
  });

  // Auto-close sidebar on nav link click
  sidebar.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", () => {
      if (sidebar.classList.contains("active")) {
        setTimeout(closeSidebar, 100);
      }
    });
  });
}

// Enhanced dropdown with keyboard navigation support
function initDropdown() {
  const username = document.getElementById("username");
  const list = document.getElementById("nameList");
  const roleInput = document.getElementById("roleInput");

  if (!username || !list) return;

  // Toggle dropdown on click
  username.addEventListener("click", (e) => {
    e.stopPropagation();
    const isVisible = list.style.display === "block";
    list.style.display = isVisible ? "none" : "block";
    username.setAttribute("aria-expanded", !isVisible);
  });

  // Close dropdown when clicking outside
  document.addEventListener("click", (e) => {
    if (!username.contains(e.target) && !list.contains(e.target)) {
      list.style.display = "none";
      username.setAttribute("aria-expanded", "false");
    }
  });

  // Handle option selection and keyboard navigation
  const options = document.querySelectorAll(".option");
  options.forEach((opt, index) => {
    opt.addEventListener("click", () => {
      username.value = opt.dataset.name;
      if (roleInput) roleInput.value = opt.dataset.role;
      list.style.display = "none";
      username.classList.add("selected");
      username.setAttribute("aria-expanded", "false");
    });

    // Accessibility attributes
    opt.setAttribute("role", "option");
    opt.setAttribute("tabindex", "0");

    opt.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        opt.click();
      } else if (e.key === "ArrowDown" && options[index + 1]) {
        e.preventDefault();
        options[index + 1].focus();
      } else if (e.key === "ArrowUp" && options[index - 1]) {
        e.preventDefault();
        options[index - 1].focus();
      }
    });
  });
}

// Enhanced real-time form validation with comprehensive rules
function initFormValidation() {
  const forms = document.querySelectorAll("form:not(.no-auto-validation)");

  forms.forEach((form) => {
    // Skip forms that have their own validation
    if (form.classList.contains('no-auto-validation') || form.hasAttribute('data-custom-validation')) {
      return;
    }

    const allFields = form.querySelectorAll("input:not([type='hidden']):not([type='submit']), textarea, select");
    const submitButton = form.querySelector('button[type="submit"]');

    // Add validation to all fields
    allFields.forEach((field) => {
      // Real-time validation on input - ALWAYS update button state
      field.addEventListener("input", () => {
        if (field.dataset.touched === "true") {
          validateField(field);
        }
        // Always update button state even if not showing errors yet
        updateSubmitButton(form, submitButton);
      });

      // Validation on blur (mark as touched and validate)
      field.addEventListener("blur", () => {
        field.dataset.touched = "true";
        validateField(field);
        updateSubmitButton(form, submitButton);
      });

      // Mark as touched on first interaction
      field.addEventListener("focus", () => {
        if (!field.dataset.touched) {
          field.dataset.touched = "false";
        }
      });

      // Also update on change (for selects and checkboxes)
      field.addEventListener("change", () => {
        if (field.dataset.touched === "true") {
          validateField(field);
        }
        updateSubmitButton(form, submitButton);
      });
    });

    // Prevent form submission if invalid (only for simple forms)
    if (!form.classList.contains('skip-submit-validation')) {
      form.addEventListener("submit", (e) => {
        let isValid = true;

        allFields.forEach((field) => {
          field.dataset.touched = "true";
          if (!validateField(field)) {
            isValid = false;
          }
        });

        if (!isValid) {
          e.preventDefault();
          const firstError = form.querySelector(".error");
          if (firstError) {
            firstError.focus();
            firstError.scrollIntoView({ behavior: "smooth", block: "center" });
          }
        }
      });
    }

    // Initial button state (only if not disabled by default)
    if (submitButton && !submitButton.hasAttribute('data-keep-enabled')) {
      updateSubmitButton(form, submitButton);
    }
  });
}

// Comprehensive field validation with visual feedback
function validateField(field) {
  const value = field.value.trim();
  const fieldType = field.type;
  const fieldName = field.name || field.id;
  let isValid = true;
  let errorMessage = "";

  // Remove previous error message
  removeErrorMessage(field);

  // Skip validation for hidden fields, disabled fields, and untouched fields
  if (field.type === "hidden" || field.disabled) {
    return true;
  }
  
  // Don't show validation errors until user has interacted with the field
  if (field.dataset.touched !== "true") {
    // Still validate for button state, but don't show errors
    if (field.hasAttribute("required") && !value) {
      return false;
    }
    return true;
  }

  // Required field validation
  if (field.hasAttribute("required") && !value) {
    isValid = false;
    errorMessage = "This field is required";
  }
  // Email validation
  else if (fieldType === "email" && value) {
    if (!isValidEmail(value)) {
      isValid = false;
      errorMessage = "Please enter a valid email address";
    }
  }
  // Phone validation
  else if (fieldType === "tel" && value) {
    if (!isValidPhone(value)) {
      isValid = false;
      errorMessage = "Please enter a valid phone number (min 10 digits)";
    }
  }
  // Password validation (only for new passwords, not confirm)
  else if (fieldType === "password" && value && (fieldName === "password" || fieldName === "new_password")) {
    const passwordValidation = validatePassword(value);
    if (!passwordValidation.isValid) {
      isValid = false;
      errorMessage = passwordValidation.message;
    }
  }
  // Confirm password validation
  else if ((fieldName === "confirm_password" || fieldName === "confirm_new_password") && value) {
    const passwordField = field.form.querySelector('[name="password"], [name="new_password"]');
    if (passwordField && value !== passwordField.value) {
      isValid = false;
      errorMessage = "Passwords do not match";
    }
  }
  // Username validation with sanitization
  else if (fieldName === "username" && value) {
    // Sanitize: remove any potentially dangerous characters
    const sanitized = value.replace(/[<>'"]/g, '');
    if (sanitized !== value) {
      isValid = false;
      errorMessage = "Username contains invalid characters";
    } else if (!/^[a-zA-Z0-9._-]+$/.test(value)) {
      isValid = false;
      errorMessage = "Username can only contain letters, numbers, dots, underscores, and hyphens";
    } else if (value.length < 3) {
      isValid = false;
      errorMessage = "Username must be at least 3 characters";
    }
  }
  // Number validation
  else if (fieldType === "number" && value) {
    const min = field.getAttribute("min");
    const max = field.getAttribute("max");
    const numValue = parseFloat(value);
    
    if (isNaN(numValue)) {
      isValid = false;
      errorMessage = "Please enter a valid number";
    } else if (min !== null && numValue < parseFloat(min)) {
      isValid = false;
      errorMessage = `Value must be at least ${min}`;
    } else if (max !== null && numValue > parseFloat(max)) {
      isValid = false;
      errorMessage = `Value must be at most ${max}`;
    }
  }
  // Min/Max length validation
  else if (value) {
    const minLength = field.getAttribute("minlength");
    const maxLength = field.getAttribute("maxlength");
    
    if (minLength && value.length < parseInt(minLength)) {
      isValid = false;
      errorMessage = `Must be at least ${minLength} characters`;
    } else if (maxLength && value.length > parseInt(maxLength)) {
      isValid = false;
      errorMessage = `Must be at most ${maxLength} characters`;
    }
  }

  // Update field appearance (only if field has been touched)
  if (!isValid && field.dataset.touched === "true") {
    field.classList.add("error");
    field.setAttribute("aria-invalid", "true");
    showErrorMessage(field, errorMessage);
  } else {
    field.classList.remove("error");
    field.removeAttribute("aria-invalid");
    // Only add valid class if field has value and is not confirm password
    if (value && fieldName !== "confirm_password" && fieldName !== "confirm_new_password" && field.dataset.touched === "true") {
      field.classList.add("valid");
    }
  }

  return isValid;
}

// Password strength validation
function validatePassword(password) {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (password.length < minLength) {
    return { isValid: false, message: "Password must be at least 8 characters" };
  }
  if (!hasUpperCase) {
    return { isValid: false, message: "Password must contain an uppercase letter" };
  }
  if (!hasLowerCase) {
    return { isValid: false, message: "Password must contain a lowercase letter" };
  }
  if (!hasNumber) {
    return { isValid: false, message: "Password must contain a number" };
  }
  if (!hasSpecialChar) {
    return { isValid: false, message: "Password must contain a special character" };
  }

  return { isValid: true, message: "" };
}

// Email validation
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Phone validation
function isValidPhone(phone) {
  const digitsOnly = phone.replace(/\D/g, "");
  return digitsOnly.length >= 10 && digitsOnly.length <= 15;
}

// Show error message below field
function showErrorMessage(field, message) {
  // Find the appropriate container (form-group or parent)
  let container = field.closest('.form-group') || field.parentElement;
  
  // Create error message element
  const errorDiv = document.createElement("div");
  errorDiv.className = "field-error-message";
  errorDiv.textContent = message;
  errorDiv.setAttribute("role", "alert");
  
  // Insert after the field
  if (field.nextSibling) {
    container.insertBefore(errorDiv, field.nextSibling);
  } else {
    container.appendChild(errorDiv);
  }
}

// Remove error message
function removeErrorMessage(field) {
  const container = field.closest('.form-group') || field.parentElement;
  const existingError = container.querySelector(".field-error-message");
  if (existingError) {
    existingError.remove();
  }
}

// Update submit button state based on form validity
function updateSubmitButton(form, submitButton) {
  if (!submitButton) return;

  const allFields = form.querySelectorAll("input:not([type='hidden']):not([type='submit']), textarea, select");
  let allValid = true;
  let hasRequiredFields = false;

  allFields.forEach((field) => {
    // Check if field is required and empty
    if (field.hasAttribute("required")) {
      hasRequiredFields = true;
      const value = field.value.trim();
      
      if (!value) {
        allValid = false;
        return;
      }
      
      // Additional validation for specific field types
      if (field.type === "email" && value) {
        if (!isValidEmail(value)) {
          allValid = false;
          return;
        }
      }
      
      if (field.type === "tel" && value) {
        if (!isValidPhone(value)) {
          allValid = false;
          return;
        }
      }
      
      // Check for password strength if it's a password field
      if (field.type === "password" && (field.name === "password" || field.name === "new_password") && value) {
        const passwordValidation = validatePassword(value);
        if (!passwordValidation.isValid) {
          allValid = false;
          return;
        }
      }
      
      // Check confirm password match
      if ((field.name === "confirm_password" || field.name === "confirm_new_password") && value) {
        const passwordField = form.querySelector('[name="password"], [name="new_password"]');
        if (passwordField && value !== passwordField.value) {
          allValid = false;
          return;
        }
      }
    }
    
    // Check if field has error class
    if (field.classList.contains("error")) {
      allValid = false;
    }
  });

  // Enable button if all required fields are valid
  submitButton.disabled = !allValid;
  
  if (allValid) {
    submitButton.classList.remove("btn-disabled");
    submitButton.style.opacity = "1";
    submitButton.style.cursor = "pointer";
  } else {
    submitButton.classList.add("btn-disabled");
    submitButton.style.opacity = "0.5";
    submitButton.style.cursor = "not-allowed";
  }
}

// Convert plain status text to styled badge components
function initStatusBadges() {
  const statusCells = document.querySelectorAll("td");
  const cfg = (window.APP_CONFIG && window.APP_CONFIG.statusBadges) || [];
  const cfgLower = cfg.map((s) => String(s).toLowerCase());

  statusCells.forEach((cell) => {
    const raw = cell.textContent.trim();
    const text = raw.toLowerCase();
    const idx = cfgLower.indexOf(text);
    if (idx !== -1) {
      const display = cfg[idx];
      const cls = `status-${text}`;
      // Use textContent instead of innerHTML to prevent XSS
      const badge = document.createElement('span');
      badge.className = `status-badge ${cls}`;
      badge.textContent = display;
      cell.textContent = '';
      cell.appendChild(badge);
    }
  });
}

// Auto-dismiss flash notifications after 5 seconds
function autoHideFlashMessages() {
  const flashMessages = document.querySelectorAll(".flash");

  flashMessages.forEach((flash) => {
    const closeBtn = document.createElement("button");
    closeBtn.textContent = "✕";
    closeBtn.style.cssText = `
      background: none;
      border: none;
      color: inherit;
      cursor: pointer;
      font-size: 1rem;
      padding: 0;
      margin-left: auto;
      opacity: 0.5;
      transition: opacity 100ms;
      line-height: 1;
    `;
    closeBtn.setAttribute("aria-label", "Close notification");

    closeBtn.addEventListener("mouseenter", () => {
      closeBtn.style.opacity = "1";
    });

    closeBtn.addEventListener("mouseleave", () => {
      closeBtn.style.opacity = "0.5";
    });

    closeBtn.addEventListener("click", () => {
      flash.remove();
    });

    flash.appendChild(closeBtn);

    setTimeout(() => {
      flash.remove();
    }, 5000);
  });
}
