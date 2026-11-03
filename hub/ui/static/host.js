// Host detail page logic (external file: preview CSP blocks inline JS).
'use strict';
initTheme();
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// J3 — host status captured at refresh (for the offline-queue hint).
let sHostStatus = '';

// Host id from the query param (?id=<uuid>) — the page is served at
// /hosts?id=… so the relative-asset trick works behind any proxy prefix
// (sandbox preview, Caddy…) as well as at the root in production.
const hostID = new URLSearchParams(location.search).get('id');

function sparkSVG(points, w, h, color) {
  if (!points.length) return `<p class="sub">Pas encore de télémétrie.</p>`;
  const max = 100, step = w / Math.max(1, points.length - 1);
  const pts = points.map((p, i) => `${(i * step).toFixed(1)},${(h - (p / max) * h).toFixed(1)}`).join(' ');
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" class="spark">
    <line x1="0" y1="${h * 0.25}" x2="${w}" y2="${h * 0.25}" stroke="var(--svg-grid)"/>
    <line x1="0" y1="${h * 0.5}"  x2="${w}" y2="${h * 0.5}"  stroke="var(--svg-grid)"/>
    <line x1="0" y1="${h * 0.75}" x2="${w}" y2="${h * 0.75}" stroke="var(--svg-grid)"/>
    <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2"/>
  </svg>`;
}

function fmtBytes(b) {
  if (b == null) return '—';
  const u = ['o', 'Ko', 'Mo', 'Go', 'To'];
  let i = 0; while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(b >= 100 || i === 0 ? 0 : 1) + ' ' + u[i];
}
function fmtUptime(s) {
  if (!s) return '—';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return (d ? d + ' j ' : '') + h + ' h ' + m + ' min';
}

async function refresh() {
  const r = await fetch(ugApi('api/v1/hosts/' + hostID));
  if (r.status === 401) { location.href = 'login'; return; }
  const h = await r.json();
  document.getElementById('site').textContent = h.domain || '';
  document.getElementById('hostname').textContent = h.hostname;
  document.getElementById('hostsub').textContent = h.os + ' ' + h.os_version + ' · agent ' + (h.agent_version || '?') + ' · pare-feu ' + (h.fw_type || 'inconnu');
  document.getElementById('kpis').innerHTML = `
    <div class="card"><div class="k">Statut</div><div class="v statut"><span class="chip ${h.status === 'online' ? 'ok' : (h.status === 'stale' ? 'warn' : 'off')}">${esc(h.status)}</span></div><div class="d">vu ${esc(h.last_seen || 'jamais')}</div></div>
    <div class="card"><div class="k">CPU</div><div class="v">${h.cpu_pct != null ? h.cpu_pct.toFixed(0) + '%' : '—'}</div><div class="d">dernier point</div></div>
    <div class="card"><div class="k">RAM</div><div class="v">${h.mem_pct != null ? h.mem_pct.toFixed(0) + '%' : '—'}</div><div class="d">dernier point</div></div>
    <div class="card"><div class="k">Charge</div><div class="v">${h.load1 != null ? h.load1.toFixed(2) : '—'}</div><div class="d">load1 · up ${esc(fmtUptime(h.uptime_s))}</div></div>`;
  document.getElementById('chart').innerHTML =
    '<h2>CPU 24 h</h2>' + sparkSVG(h.telemetry.map((t) => t.cpu_pct), 720, 120, 'var(--acc)') +
    '<h2 class="chart-title">RAM 24 h</h2>' + sparkSVG(h.telemetry.map((t) => t.mem_pct), 720, 120, 'var(--ok)');
  document.getElementById('drows').innerHTML = (h.disks || []).map((d) => `
    <tr><td class="mono">${esc(d.device)}</td><td class="mono">${esc(d.mount)}</td>
    <td>${fmtBytes(d.total_bytes)}</td><td>${fmtBytes(d.used_bytes)}</td>
    <td><span class="chip ${d.used_pct > 85 ? 'crit' : (d.used_pct > 70 ? 'warn' : 'ok')}">${d.used_pct.toFixed(0)}%</span></td></tr>`).join('') || '<tr><td colspan="5" class="sub">Pas encore de données.</td></tr>';
  document.getElementById('nrows').innerHTML = (h.net || []).map((n) => `
    <tr><td class="mono">${esc(n.iface)}</td><td>${fmtBytes(n.bytes_in)}</td><td>${fmtBytes(n.bytes_out)}</td></tr>`).join('') || '<tr><td colspan="3" class="sub">Pas encore de données.</td></tr>';
  document.getElementById('srows').innerHTML = (h.services || []).map((s) => `
    <tr><td class="mono">${esc(s.name)}</td><td><span class="chip ${s.status === 'running' ? 'ok' : 'crit'}">${esc(s.status)}</span></td></tr>`).join('') || '<tr><td colspan="2" class="sub">Pas encore de données.</td></tr>';
  document.getElementById('arows').innerHTML = (h.audit || []).map((a) => `
    <tr><td class="mono">${a.seq}</td><td class="mono">${esc(a.ts)}</td><td class="mono">${esc(a.actor)}</td><td>${esc(a.action)}</td>
    <td><span class="chip ${a.result === 'ok' ? 'ok' : 'crit'}">${esc(a.result)}</span></td><td class="mono">${esc((a.hash || '').slice(0, 12))}…</td></tr>`).join('');
  sHostStatus = h.status || '';
  loadActions();
  const u = await fetch(ugApi('api/v1/me')).then((r) => r.json());
  document.getElementById('user').textContent = u.email + ' · ' + u.role;
  initThemeFromServer(u.theme);
}

// J3 — actions distantes : ping applicatif + file d'actions.
async function loadActions() {
  const r = await fetch(ugApi('api/v1/hosts/' + hostID + '/actions'));
  if (r.status === 401) { location.href = 'login'; return; }
  const d = await r.json();
  const chip = (s) => `<span class="chip ${s === 'done' ? 'ok' : (s === 'failed' || s === 'timeout' ? 'crit' : (s === 'delivered' ? 'warn' : 'off'))}">${esc(s)}</span>`;
  document.getElementById('actrows').innerHTML = (d.actions || []).map((a) => `
    <tr><td>${esc(a.type)}</td><td>${chip(a.status)}</td><td class="mono">${esc(a.created_by)}</td>
    <td class="mono">${esc(a.created_at)}</td><td class="mono">${esc(a.delivered_at) || '—'}</td>
    <td class="mono">${esc(a.finished_at) || '—'}</td>
    <td class="mono sub">${esc((a.error || a.result || '').toString().slice(0, 60)) || '—'}</td></tr>`).join('')
    || '<tr><td colspan="7" class="sub">Aucune action.</td></tr>';
}

async function doPing() {
  const out = document.getElementById('ping-out');
  out.textContent = 'ping…';
  let r = await fetch(ugApi('api/v1/hosts/' + hostID + '/ping'), { method: 'POST' });
  if (r.status === 405) {
    // preview proxy forwards GET only → dev-only GET twin
    r = await fetch(ugApi('dev/hosts/' + hostID + '/ping'));
  }
  if (r.status === 401) { location.href = 'login'; return; }
  const d = await r.json().catch(() => ({}));
  if (r.ok) { out.textContent = `RTT ${d.rtt_ms} ms`; refresh(); }
  else out.textContent = d.error || 'échec du ping';
}

async function doInventory() {
  const out = document.getElementById('ping-out');
  out.textContent = 'action empilée…';
  // Normal POST path; preview proxy fallback → dev GET twin.
  let r = await fetch(ugApi('api/v1/hosts/' + hostID + '/actions'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'inventory_refresh' }) });
  if (r.status === 405) {
    r = await fetch(ugApi('dev/hosts/' + hostID + '/actions', { type: 'inventory_refresh' }));
  }
  if (r.status === 401) { location.href = 'login'; return; }
  const d = await r.json().catch(() => ({}));
  if (r.ok) {
    out.textContent = (d.status === 'pending' && sHostStatus !== 'online')
      ? 'hôte hors-ligne : livrée à sa reconnexion'
      : 'envoyée à l\'agent';
    setTimeout(loadActions, 400);
  } else out.textContent = d.error || 'échec';
}

document.getElementById('btn-ping')?.addEventListener('click', doPing);
document.getElementById('btn-inventory')?.addEventListener('click', doInventory);
ugBridgeReady.then(refresh);
setInterval(refresh, 10000);