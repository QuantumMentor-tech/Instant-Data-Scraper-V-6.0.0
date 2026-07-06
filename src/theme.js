/**
 * DataForge Scraper — Theme Controller
 *
 * Loaded via <script src="theme.js"> in <head> — CSP-safe, no inline scripts.
 *
 * The theme is applied SYNCHRONOUSLY at parse time (before any paint) to
 * eliminate any flash of unstyled content (FOUC). The toggle button is wired
 * up after DOMContentLoaded when the button element exists in the DOM.
 */
(function () {
  'use strict';

  var THEME_KEY = 'df-theme';
  var DARK  = 'dark';
  var LIGHT = 'light';

  /* ── 1. Apply saved theme IMMEDIATELY (parse-time, blocks render) ─────── */
  var saved = localStorage.getItem(THEME_KEY) || LIGHT;
  document.documentElement.setAttribute('data-theme', saved);

  /* ── 2. Wire the toggle button once the DOM is ready ────────────────────  */
  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('df-theme-toggle');
    if (!btn) return;

    // Sync button icon to the already-applied theme
    updateButton(btn, document.documentElement.getAttribute('data-theme'));

    btn.addEventListener('click', function () {
      var current = document.documentElement.getAttribute('data-theme');
      var next = (current === DARK) ? LIGHT : DARK;
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem(THEME_KEY, next);
      updateButton(btn, next);
    });
  });

  /* ── Helper: swap icon and aria-label to match current theme ────────────  */
  function updateButton(btn, theme) {
    var sun  = btn.querySelector('.df-icon-sun');
    var moon = btn.querySelector('.df-icon-moon');
    if (!sun || !moon) return;

    if (theme === DARK) {
      // Dark mode active → show sun so user can click back to light
      sun.style.display  = 'block';
      moon.style.display = 'none';
      btn.setAttribute('aria-label', 'Switch to light mode');
      btn.setAttribute('title',      'Switch to light mode');
    } else {
      // Light mode active → show moon so user can click to dark
      sun.style.display  = 'none';
      moon.style.display = 'block';
      btn.setAttribute('aria-label', 'Switch to dark mode');
      btn.setAttribute('title',      'Switch to dark mode');
    }
  }

}());
