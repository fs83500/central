// Hosts dashboard page logic (external file: preview CSP blocks inline JS).
'use strict';
initTheme();

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function refresh() {
  const r = await fetch('api/v1/hosts');
  if (r.status === 401) { location.href = 'login'; return; }
  const data = await r.json();
  document.getElementById('site').textContent = data.domain || '';
  const online = data.hosts.filter((h) => h.status === 'online').length;
  const stale  = data.hosts.filter((h) => h.status === 'stale').length;
  const off    = data.hosts.length - online - stale;
  document.getElementById('kpis').innerHTML = `
    <div class="card ok"><div class="k">En ligne</div><div class="v">${online}</div><div class="d">heartbeat &lt; 90 s</div></div>
    <div class="card warn"><div class="k">Stale</div><div class="v">${stale}</div><div class="d">heartbeat &gt; 90 s</div></div>
    <div class="card crit"><div class="k">Hors ligne</div><div class="v">${off}</div><div class="d">déconnecté</div></div>
    <div class="card"><div class="k">Total</div><div class="v">${data.hosts.length}</div><div class="d">quota ${data.quota_used}/${data.quota}</div></div>`;
  document.getElementById('rows').innerHTML = data.hosts.map((h) => `
    <tr>
      <td><a href="hosts?id=${esc(h.id)}"><b>${esc(h.hostname)}</b></a></td>
      <td>${esc(h.os)} ${esc(h.os_version)}</td>
      <td>${esc(h.fw_type || '—')}</td>
      <td class="mono">${esc(h.agent_version || '—')}</td>
      <td><span class="chip ${h.status === 'online' ? 'ok' : (h.status === 'stale' ? 'warn' : 'off')}">${esc(h.status)}</span></td>
      <td class="mono">${esc(h.last_seen || 'jamais')}</td>
      <td class="mono">${h.rtt_ms ? esc(h.rtt_ms) + ' ms' : '—'}</td>
    </tr>`).join('');
  const u = await fetch('api/v1/me').then((r) => r.json());
  document.getElementById('user').textContent = u.email + ' · ' + u.role;
  initThemeFromServer(u.theme);
}
refresh();
setInterval(refresh, 10000);