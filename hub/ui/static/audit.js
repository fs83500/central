// Audit page logic (external file: preview CSP blocks inline JS).
'use strict';
initTheme();
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function refresh() {
  const v = await fetch(ugApi('api/v1/audit/verify')).then((r) => r.json());
  document.getElementById('verify').innerHTML = v.ok
    ? `<span class="chip ok">CHAÎNE INTACTE</span> <span class="sub verify-sub">${v.events} événements vérifiés (double vérification DB + Go)</span>`
    : `<span class="chip crit">CHAÎNE ROMPUE</span> <span class="sub verify-sub">${esc(v.error || '')}</span>`;
  const r = await fetch(ugApi('api/v1/audit/events'));
  if (r.status === 401) { location.href = 'login'; return; }
  const data = await r.json();
  document.getElementById('arows').innerHTML = (data.events || []).map((a) => `
    <tr>
      <td class="mono">${a.seq}</td><td class="mono">${esc(a.ts)}</td><td class="mono">${esc(a.actor)}</td><td>${esc(a.action)}</td>
      <td class="mono">${esc(a.target_type)}:${esc(a.target_id)}</td>
      <td><span class="chip ${a.result === 'ok' ? 'ok' : (a.result === 'denied' ? 'warn' : 'crit')}">${esc(a.result)}</span></td>
      <td class="mono" title="${esc(a.hash)}">${esc((a.hash || '').slice(0, 12))}…</td>
    </tr>`).join('');
  const u = await fetch(ugApi('api/v1/me')).then((r) => r.json());
  document.getElementById('user').textContent = u.email + ' · ' + u.role;
  initThemeFromServer(u.theme);
}
ugBridgeReady.then(refresh);
setInterval(refresh, 10000);