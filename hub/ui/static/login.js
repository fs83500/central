// Login page logic (extracted from inline <script> for the preview CSP,
// which has script-src 'self' and blocks inline scripts).
'use strict';
initTheme();

// Preview-sandbox detection: under the /preview/<agent>/<port>/ prefix the
// proxy blocks POST (405) — surface the one-click GET fallback right away.
(function () {
  if (location.pathname.indexOf('/preview/') === 0) {
    document.getElementById('preview-note').hidden = false;
  }
  // dev-login failures redirect here with ?err=<reason>.
  const qerr = new URLSearchParams(location.search).get('err');
  if (qerr) {
    const el = document.getElementById('err');
    el.textContent = 'Connexion directe refusée : ' + qerr + '.';
    el.hidden = false;
  }
})();

const err = document.getElementById('err');
function showErr(msg) { err.textContent = msg; err.hidden = false; }

// post() reports request failures explicitly instead of falling back to a
// misleading "invalid credentials": network error, non-JSON body (e.g. an
// HTML page served by a proxy), and JSON API errors are all distinct cases.
async function post(url, body) {
  let r;
  try {
    r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  } catch (e) {
    return { status: 0, data: {}, network: true };
  }
  const data = await r.json().catch(() => ({ __nonjson: true }));
  return { status: r.status, data };
}

// apiErr renders the right user-facing message for each failure class.
function apiErr(step, status, data) {
  if (status === 0) return 'Réseau indisponible — vérifiez votre connexion et réessayez.';
  if (status === 429) return 'Trop de tentatives — réessayez dans une minute.';
  if (status === 405 || data.__nonjson) return 'Le serveur a refusé la requête (' + status + '). ' +
    'Si vous utilisez la preview sandbox, les POST y sont bloqués : utilisez la connexion directe (GET) ci-dessous.';
  if (status === 401) return step === 'mfa' ? 'Code invalide ou expiré.' : (data.error === 'account not activated' ? 'Compte non activé.' : 'E-mail ou mot de passe incorrect.');
  if (status >= 500) return 'Erreur serveur (' + status + ') — réessayez plus tard.';
  if (data.error) return data.error;
  return 'Réponse inattendue du serveur (' + status + ').';
}

// One-click GET login (dev): the preview proxy only forwards GET, so the
// link navigates to dev-login?email=…&password=… which logs in server-side
// and redirects to the dashboard. Credentials never leave this page's origin.
(function () {
  const link = document.getElementById('dev-login-link');
  if (!link) return;
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    if (!email || !password) { showErr('Renseignez e-mail et mot de passe, puis cliquez la connexion directe.'); return; }
    const q = new URLSearchParams({ email, password });
    location.href = 'dev-login?' + q.toString();
  });
})();

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  err.hidden = true;
  const { status, data } = await post('api/v1/auth/login', {
    email: document.getElementById('email').value,
    password: document.getElementById('password').value,
  });
  if (status === 200 && data.mfa_required) {
    document.getElementById('login-form').hidden = true;
    document.getElementById('mfa-form').hidden = false;
    document.getElementById('code').focus();
    if (data.dev_mfa_code) {
      const hint = document.createElement('p');
      hint.className = 'sub mfa-code';
      hint.innerHTML = 'Code dev (SMTP arrive en J9) : <b>' + data.dev_mfa_code + '</b>';
      document.getElementById('mfa-form').prepend(hint);
    }
    return;
  }
  if (status === 200 && data.ok) { location.href = 'hosts'; return; }
  showErr(apiErr('login', status, data));
});

document.getElementById('mfa-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  err.hidden = true;
  const { status, data } = await post('api/v1/auth/mfa', {
    email: document.getElementById('email').value,
    code: document.getElementById('code').value,
  });
  if (status === 200 && data.ok) { location.href = 'hosts'; return; }
  showErr(apiErr('mfa', status, data));
});