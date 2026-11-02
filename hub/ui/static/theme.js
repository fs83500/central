'use strict';
// Theme manager: auto (OS) / light / dark. Choice persisted in localStorage
// AND (when logged in) in the user profile via PATCH /api/v1/me/theme.
// Applied on <html data-theme> before paint via the inline script in layouts.

function applyTheme(mode) {
  document.documentElement.setAttribute('data-theme', mode);
  for (const b of document.querySelectorAll('[data-set-theme]')) {
    b.classList.toggle('on', b.getAttribute('data-set-theme') === mode);
  }
}

function savedTheme() {
  try { return localStorage.getItem('ug-theme') || 'auto'; }
  catch { return 'auto'; }
}

function setTheme(mode, persist) {
  applyTheme(mode);
  try { localStorage.setItem('ug-theme', mode); } catch { /* private mode */ }
  if (persist) {
    fetch('/api/v1/me/theme', { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ theme: mode }) }).catch(() => {});
  }
}

function initTheme() {
  applyTheme(savedTheme());
  for (const b of document.querySelectorAll('[data-set-theme]')) {
    b.addEventListener('click', () => setTheme(b.getAttribute('data-set-theme'), true));
  }
}

// Server-side theme (user profile) wins over localStorage on shared machines.
function initThemeFromServer(theme) {
  if (theme && theme !== savedTheme()) {
    applyTheme(theme);
    try { localStorage.setItem('ug-theme', theme); } catch { /* noop */ }
  }
  initTheme();
}