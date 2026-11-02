// Enrollment page logic (external file: preview CSP blocks inline JS).
'use strict';
initTheme();
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

document.getElementById('create').addEventListener('click', async () => {
  // Normal path: POST. Under the sandbox preview proxy POST is blocked (405),
  // so we fall back to the dev-only GET twin endpoint.
  let r = await fetch('api/v1/enroll/tokens', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label: document.getElementById('label').value || '' }) });
  if (r.status === 405) {
    r = await fetch('dev/enroll/tokens?label=' + encodeURIComponent(document.getElementById('label').value || ''));
  }
  if (r.status === 401) { location.href = 'login'; return; }
  const data = await r.json();
  const tok = document.getElementById('tok');
  tok.hidden = false;
  tok.innerHTML = `<b>Token (copiez-le maintenant) :</b> <span class="mono">${esc(data.token)}</span>`;
  document.getElementById('oneliner').textContent = `curl -fsSL https://${location.host}/install.sh | bash -s -- --token=${data.token}`;
});

document.getElementById('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(document.getElementById('oneliner').textContent); } catch { /* noop */ }
});

(async () => {
  const u = await fetch('api/v1/me').then((r) => r.json());
  document.getElementById('user').textContent = u.email + ' · ' + u.role;
  document.getElementById('site').textContent = location.host;
  initThemeFromServer(u.theme);
})();