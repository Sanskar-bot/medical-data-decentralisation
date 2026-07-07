/**
 * app.js — MedVault micro-interactions
 * Flash dismiss · Sidebar active state · Fade-in stagger · Tab switching
 */

(function () {
  'use strict';

  /* ── Flash message auto-dismiss ──────────────────────────────────── */
  function initFlashDismiss() {
    document.querySelectorAll('.alert').forEach(function (el) {
      setTimeout(function () {
        el.style.transition = 'opacity 300ms ease, transform 300ms ease';
        el.style.opacity = '0';
        el.style.transform = 'translateY(-4px)';
        setTimeout(function () { el.remove(); }, 320);
      }, 4000);
    });
  }

  /* ── Sidebar active state ────────────────────────────────────────── */
  function initSidebarActive() {
    var current = window.location.pathname + window.location.hash;
    document.querySelectorAll('.sidebar-item').forEach(function (link) {
      var href = link.getAttribute('href');
      if (href && current.startsWith(href) && href !== '/') {
        link.classList.add('active');
      }
    });
  }

  /* ── Mobile sidebar toggle ─────────────────────────────────────── */
  function initMobileNav() {
    var toggle = document.getElementById('sidebar-toggle');
    var overlay = document.getElementById('page-overlay');
    if (!toggle) return;

    function closeNav() {
      document.body.classList.remove('sidebar-open');
      toggle.setAttribute('aria-expanded', 'false');
    }

    function openNav() {
      document.body.classList.add('sidebar-open');
      toggle.setAttribute('aria-expanded', 'true');
    }

    toggle.addEventListener('click', function () {
      if (document.body.classList.contains('sidebar-open')) {
        closeNav();
      } else {
        openNav();
      }
    });

    if (overlay) {
      overlay.addEventListener('click', closeNav);
    }

    window.addEventListener('resize', function () {
      if (window.innerWidth > 960) closeNav();
    });
  }

  /* ── Fade-in stagger for stat cards ─────────────────────────────── */
  function initFadeIn() {
    var delay = 0;
    document.querySelectorAll('.stat-card:not([style*="animation-delay"])').forEach(function (el) {
      el.style.animationDelay = delay + 'ms';
      el.classList.add('fade-in');
      delay += 60;
    });
  }

  /* ── Tab switching ───────────────────────────────────────────────── */
  function initTabs() {
    document.querySelectorAll('[data-tab-group]').forEach(function (group) {
      var tabs  = group.querySelectorAll('[data-tab]');
      // Panels are siblings of the tab-group element, not descendants.
      // Search in the parent container so the lookup always works regardless
      // of DOM depth.
      var scope  = group.parentElement || group;
      var panels = scope.querySelectorAll('[data-tab-panel]');

      tabs.forEach(function (tab) {
        tab.addEventListener('click', function () {
          var target = tab.dataset.tab;
          tabs.forEach(function (t)   { t.classList.remove('active'); });
          panels.forEach(function (p) { p.classList.add('hidden'); });
          tab.classList.add('active');
          var panel = scope.querySelector('[data-tab-panel="' + target + '"]');
          if (panel) panel.classList.remove('hidden');
        });
      });
    });
  }

  /* ── Auth page role tabs ─────────────────────────────────────────── */
  function initAuthTabs() {
    var tabs = document.querySelectorAll('.auth-tab');
    if (!tabs.length) return;

    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () {
        var target = tab.dataset.role;
        tabs.forEach(function (t) { t.classList.remove('active'); });
        tab.classList.add('active');

        document.querySelectorAll('.auth-role-panel').forEach(function (panel) {
          panel.classList.add('hidden');
        });
        var panel = document.getElementById('role-' + target);
        if (panel) panel.classList.remove('hidden');
      });
    });
  }

  /* ── Inline confirm expand ───────────────────────────────────────── */
  function initInlineConfirm() {
    document.querySelectorAll('[data-confirm-trigger]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var target = document.getElementById(btn.dataset.confirmTrigger);
        if (!target) return;
        var isHidden = target.classList.contains('hidden');
        // Close all open confirmations first
        document.querySelectorAll('.inline-confirm').forEach(function (c) {
          c.classList.add('hidden');
        });
        if (isHidden) target.classList.remove('hidden');
      });
    });
    document.querySelectorAll('[data-confirm-cancel]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var target = document.getElementById(btn.dataset.confirmCancel);
        if (target) target.classList.add('hidden');
      });
    });
  }

  /* ── Input validation feedback ───────────────────────────────────── */
  function initInputFeedback() {
    document.querySelectorAll('.input-field').forEach(function (input) {
      input.addEventListener('blur', function () {
        if (input.value.trim().length > 0) {
          input.classList.add('valid');
          input.classList.remove('error');
        }
      });
    });
  }

  /* ── Table row click navigation ──────────────────────────────────── */
  function initTableRows() {
    document.querySelectorAll('[data-href]').forEach(function (row) {
      row.style.cursor = 'pointer';
      row.addEventListener('click', function (e) {
        if (e.target.closest('button') || e.target.closest('a')) return;
        window.location.href = row.dataset.href;
      });
    });
  }

  /* ── Copy to clipboard ───────────────────────────────────────────── */
  function initCopyButtons() {
    document.querySelectorAll('[data-copy]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var text = btn.dataset.copy || btn.textContent.trim();
        navigator.clipboard.writeText(text).then(function () {
          var orig = btn.textContent;
          btn.textContent = 'Copied';
          setTimeout(function () { btn.textContent = orig; }, 1500);
        });
      });
    });
  }

  /* ── Password toggle ─────────────────────────────────────────────── */
  function initPasswordToggle() {
    document.querySelectorAll('[data-toggle-password]').forEach(function (btn) {
      var target = document.getElementById(btn.dataset.togglePassword);
      if (!target) return;
      btn.addEventListener('click', function () {
        var isPassword = target.type === 'password';
        target.type = isPassword ? 'text' : 'password';
        btn.textContent = isPassword ? 'Hide' : 'Show';
      });
    });
  }

  /* ── Landing page smooth scroll ──────────────────────────────────── */
  function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(function (link) {
      link.addEventListener('click', function (e) {
        var target = document.querySelector(link.getAttribute('href'));
        if (!target) return;
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });
  }

  /* ── Show/hide password strength ─────────────────────────────────── */
  function initPasswordStrength() {
    var pwInput = document.getElementById('password');
    var meter   = document.getElementById('password-strength');
    if (!pwInput || !meter) return;

    pwInput.addEventListener('input', function () {
      var val = pwInput.value;
      var score = 0;
      if (val.length >= 8)        score++;
      if (/[A-Z]/.test(val))      score++;
      if (/[0-9]/.test(val))      score++;
      if (/[^A-Za-z0-9]/.test(val)) score++;

      var labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
      var colors = ['', 'var(--r5)', 'var(--g4)', 'var(--g5)', 'var(--t5)'];
      meter.textContent = val.length > 0 ? labels[score] : '';
      meter.style.color = colors[score] || '';
    });
  }

  /* ── Init all ────────────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    initFlashDismiss();
    initSidebarActive();
    initMobileNav();
    initFadeIn();
    initTabs();
    initAuthTabs();
    initInlineConfirm();
    initInputFeedback();
    initTableRows();
    initCopyButtons();
    initPasswordToggle();
    initSmoothScroll();
    initPasswordStrength();
  });

})();
