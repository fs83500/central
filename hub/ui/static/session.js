'use strict';
// Session carrier for the sandbox preview (dev only).
//
// The preview proxy strips cookie traffic in BOTH directions, so the UI
// carries the session token as ?st= on every API/page URL. The raw token
// arrives once via the one-time bridge: dev-login redirects to
// hosts?t=<one-time>, which is exchanged here for ?st=<session> and stored
// in sessionStorage (cleared when the tab closes — it is a preview session).
//
// In production this module is a no-op: the cookie does everything and
// sessionStorage holds no token (get() returns '').

function ugSessionGet() {
  try { return sessionStorage.getItem('ug-st') || ''; } catch { return ''; }
}

function ugSessionSet(tok) {
  try { sessionStorage.setItem('ug-st', tok); } catch { /* private mode */ }
}

// ugApi(path, params) → absolute-free, session-carrying URL.
// path: 'api/v1/hosts' (no leading slash — prefix-agnostic).
// params: plain object appended as query params.
function ugApi(path, params) {
  const p = new URLSearchParams(params || {});
  const st = ugSessionGet();
  if (st && !p.has('st')) p.set('st', st);
  const q = p.toString();
  return q ? path + '?' + q : path;
}

// One-time bridge: exchange ?t= (from dev-login redirect) for the session
// token, then clean the URL (keep it shareable and out of history).
const ugBridgeReady = (async function ugBridgeInit() {
  const u = new URL(location.href);
  const oneTime = u.searchParams.get('t');
  if (!oneTime) return;
  try {
    const r = await fetch(ugApi('dev/session/redeem', { t: oneTime }), { headers: { 'Content-Type': 'application/json' } });
    const data = await r.json().catch(() => ({}));
    if (r.ok && data.st) {
      ugSessionSet(data.st);
    } else {
      // One-time token expired/already used: back to a clean login.
      location.href = 'login';
      return;
    }
  } catch { /* network hiccup: user retries the login link */ }
  u.searchParams.delete('t');
  history.replaceState(null, '', u.pathname + (u.searchParams.toString() ? '?' + u.searchParams.toString() : '') + u.hash);
})();
// Logout link: purge the preview session before navigating so a back-button
// press cannot resurrect a revoked token (the server revokes it anyway).
(function ugLogoutHook() {
  document.addEventListener('click', (e) => {
    const a = e.target.closest && e.target.closest('a[href$="logout"], a[href*="logout"]');
    if (a) {
      try { sessionStorage.removeItem('ug-st'); } catch { /* noop */ }
    }
  });
})();
