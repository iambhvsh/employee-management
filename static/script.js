// Employee Portal - Client-side interactions
// Initialize all interactive components on page load
document.addEventListener("DOMContentLoaded", () => {
  initSidebarToggle();
  initDropdown();
  initFormValidation();
  initStatusBadges();
  autoHideFlashMessages();
});

// Mobile-responsive sidebar with overlay
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


  overlay.addEventListener("click", closeSidebar);


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

// Login page: username dropdown with keyboard navigation
// Enhanced dropdown with keyboard navigation support
function initDropdown() {
  const username = document.getElementById("username");
  const list = document.getElementById("nameList");
  const roleInput = document.getElementById("roleInput");

  if (!username || !list) return;


  username.addEventListener("click", (e) => {
    e.stopPropagation();
    const isVisible = list.style.display === "block";
    list.style.display = isVisible ? "none" : "block";
    username.setAttribute("aria-expanded", !isVisible);
  });


  document.addEventListener("click", (e) => {
    if (!username.contains(e.target) && !list.contains(e.target)) {
      list.style.display = "none";
      username.setAttribute("aria-expanded", "false");
    }
  });


  const options = document.querySelectorAll(".option");
  options.forEach((opt, index) => {
    opt.addEventListener("click", () => {
      username.value = opt.dataset.name;
      if (roleInput) roleInput.value = opt.dataset.role;
      list.style.display = "none";
      username.classList.add("selected");
      username.setAttribute("aria-expanded", "false");
    });


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

// Client-side form validation for required fields
// Real-time form validation with accessibility support
function initFormValidation() {
  const forms = document.querySelectorAll("form");

  forms.forEach((form) => {
    const requiredFields = form.querySelectorAll("[required]");

    requiredFields.forEach((field) => {
      field.addEventListener("blur", () => {
        validateField(field);
      });

      field.addEventListener("input", () => {
        if (field.classList.contains("error")) {
          validateField(field);
        }
      });
    });

    form.addEventListener("submit", (e) => {
      let isValid = true;

      requiredFields.forEach((field) => {
        if (!validateField(field)) {
          isValid = false;
        }
      });

      if (!isValid) {
        e.preventDefault();
        const firstError = form.querySelector(".error");
        if (firstError) {
          firstError.focus();
        }
      }
    });
  });
}

// Validate individual form field with visual feedback
function validateField(field) {
  const value = field.value.trim();
  let isValid = true;

  if (!value) {
    isValid = false;
  } else if (field.type === "email" && !isValidEmail(value)) {
    isValid = false;
  } else if (field.type === "tel" && !isValidPhone(value)) {
    isValid = false;
  }

  if (!isValid) {
    field.classList.add("error");
    field.setAttribute("aria-invalid", "true");
  } else {
    field.classList.remove("error");
    field.removeAttribute("aria-invalid");
  }

  return isValid;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPhone(phone) {
  return /^[\d\s\-\+\(\)]+$/.test(phone) && phone.replace(/\D/g, "").length >= 10;
}

// Dynamically convert text status to styled badges
// Convert plain status text to styled badge components
function initStatusBadges() {
  const statusCells = document.querySelectorAll("td");

  statusCells.forEach((cell) => {
    const text = cell.textContent.trim().toLowerCase();

    if (text === "pending") {
      cell.innerHTML = `<span class="status-badge status-pending">Pending</span>`;
    } else if (text === "approved") {
      cell.innerHTML = `<span class="status-badge status-approved">Approved</span>`;
    } else if (text === "rejected") {
      cell.innerHTML = `<span class="status-badge status-rejected">Rejected</span>`;
    }
  });
}

// Auto-dismiss flash messages after 5s
// Auto-dismiss flash notifications after 5 seconds
function autoHideFlashMessages() {
  const flashMessages = document.querySelectorAll(".flash");

  flashMessages.forEach((flash) => {
    const closeBtn = document.createElement("button");
    closeBtn.innerHTML = "✕";
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
