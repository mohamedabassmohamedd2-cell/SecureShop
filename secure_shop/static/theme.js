// Light/dark theme toggle for SecureShop.
// Runs in <head> so the theme is applied before the page paints (no flash),
// and honours a saved preference or the OS colour scheme.
(function () {
  "use strict";
  var KEY = "secureshop-theme";

  function preferredTheme() {
    var saved = null;
    try { saved = localStorage.getItem(KEY); } catch (e) { /* ignore */ }
    if (saved === "light" || saved === "dark") { return saved; }
    try {
      if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
        return "dark";
      }
    } catch (e) { /* ignore */ }
    return "light";
  }

  function apply(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    var btn = document.getElementById("theme-toggle");
    if (btn) { btn.setAttribute("aria-pressed", theme === "dark" ? "true" : "false"); }
  }

  var theme = preferredTheme();
  apply(theme);

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("theme-toggle");
    if (!btn) { return; }
    btn.addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "dark"
        ? "light" : "dark";
      try { localStorage.setItem(KEY, next); } catch (e) { /* ignore */ }
      apply(next);
    });
  });
})();
