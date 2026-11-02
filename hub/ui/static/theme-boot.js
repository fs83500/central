// Anti-FOUC: apply the saved theme before first paint. Kept as a SEPARATE
// file because the sandbox preview proxy serves a CSP with script-src 'self'
// and NO 'unsafe-inline' — inline <script> blocks are silently blocked there.
(function () {
  try {
    var t = localStorage.getItem('ug-theme');
    if (t) document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* private mode */ }
})();