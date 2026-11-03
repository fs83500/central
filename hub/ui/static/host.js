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
  fwSetType(h.fw_type);
  loadActions();
  loadFW();
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

// ============================================================
// J4 — Pare-feu commit-confirm (SPEC §3.5)
// ============================================================
let fwSession = null;   // pending session {id, deadline (epoch ms)}
let fwTimerID = null;

function fwSetType(t) {
  document.getElementById('fw-type').textContent = t || 'inconnu';
  document.getElementById('btn-fw-open').disabled = !t || t === 'none' || t === '';
}

async function loadFW() {
  // Sessions
  let r = await fetch(ugApi('api/v1/hosts/' + hostID + '/fw/sessions'));
  if (r.status === 401) { location.href = 'login'; return; }
  const d = await r.json().catch(() => ({ sessions: [] }));
  const chip = (s) => `<span class="chip ${s === 'confirmed' ? 'ok' : (s === 'rolled_back' ? 'warn' : (s === 'failed' ? 'crit' : 'pending'))}">${esc(s)}</span>`;
  document.getElementById('fwrows').innerHTML = (d.sessions || []).map((s) => `
    <tr><td class="mono">${esc(s.id.slice(0, 8))}</td><td>${chip(s.state)}</td><td>${s.ttl_s}s</td>
    <td class="mono">${esc(s.applied_at) || '—'}</td><td class="mono">${esc(s.confirmed_at) || '—'}</td>
    <td class="mono">${esc(s.rolled_back_at) || '—'}</td>
    <td class="mono sub">${esc((s.detail?.outcome || s.detail?.error || '').toString().slice(0, 80)) || '—'}</td></tr>`).join('')
    || '<tr><td colspan="7" class="sub">Aucune session pare-feu.</td></tr>';
  // Any pending session? → arm the countdown.
  const pend = (d.sessions || []).find((s) => s.state === 'pending_confirm');
  const btn = document.getElementById('btn-fw-confirm');
  if (pend) {
    fwSession = { id: pend.id, deadline: Date.now() + pend.ttl_s * 1000 };
    btn.hidden = false;
    if (!fwTimerID) fwTimerID = setInterval(fwTick, 1000);
  } else {
    fwSession = null;
    btn.hidden = true;
    if (fwTimerID) { clearInterval(fwTimerID); fwTimerID = null; }
  }
  // Snapshots
  r = await fetch(ugApi('api/v1/hosts/' + hostID + '/fw/snapshots'));
  const snaps = await r.json().catch(() => ({ snapshots: [] }));
  document.getElementById('fwsnaprows').innerHTML = (snaps.snapshots || []).map((n) => `
    <tr><td class="mono">${esc(n.id.slice(0, 8))}</td><td>${esc(n.fw_type)}</td>
    <td class="mono sub">${esc((n.sha256 || '').slice(0, 16))}…</td><td>${fmtBytes(n.size_bytes)}</td>
    <td class="mono">${esc(n.created_at)}</td>
    <td><a class="btn small sec" href="api/v1/fw/snapshots/${esc(n.id)}/download${stParam()}" target="_blank">Télécharger</a></td></tr>`).join('')
    || '<tr><td colspan="6" class="sub">Aucun snapshot.</td></tr>';
}

// stParam() — appends ?st=<session token> when running behind the dev
// preview proxy (GET-only, cookies stripped).
function stParam() {
  const st = sessionStorage.getItem('ug-st');
  return st ? `?st=${encodeURIComponent(st)}` : '';
}

function fwTick() {
  if (!fwSession) return;
  const left = Math.max(0, Math.round((fwSession.deadline - Date.now()) / 1000));
  document.getElementById('fw-count').textContent = `${String(Math.floor(left / 60)).padStart(2, '0')}:${String(left % 60).padStart(2, '0')}`;
  if (left === 0) { loadFW(); }
}

async function doFWApply() {
  const out = document.getElementById('fw-out');
  const rulesTxt = document.getElementById('fw-rules').value.trim();
  const ttl = parseInt(document.getElementById('fw-ttl').value, 10);
  let rules;
  try { rules = JSON.parse(rulesTxt); } catch (e) { out.textContent = 'JSON invalide : ' + e.message; return; }
  if (!Array.isArray(rules) || !rules.length) { out.textContent = 'Le ruleset doit être un tableau JSON non vide.'; return; }
  out.textContent = 'application…';
  let r = await fetch(ugApi('api/v1/hosts/' + hostID + '/fw/apply'), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rules, ttl_s: ttl }),
  });
  if (r.status === 405) {
    // preview proxy → dev GET twin (rules in base64)
    r = await fetch(ugApi(`dev/hosts/${hostID}/fw/apply?ttl_s=${ttl}&rules=${encodeURIComponent(btoa(unescape(encodeURIComponent(JSON.stringify(rules)))))}`));
  }
  const d = await r.json().catch(() => ({}));
  if (r.ok) {
    out.textContent = `session ${d.session_id.slice(0, 8)} — compte à rebours ${d.ttl_s}s enclenché`;
    document.getElementById('fw-form').hidden = true;
    loadFW();
  } else {
    out.textContent = d.error || 'échec de l\'application';
  }
}

async function doFWConfirm() {
  if (!fwSession) return;
  const out = document.getElementById('fw-out');
  out.textContent = 'confirmation…';
  let r = await fetch(ugApi('api/v1/hosts/' + hostID + '/fw/confirm'), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: fwSession.id }),
  });
  if (r.status === 405) {
    r = await fetch(ugApi(`dev/hosts/${hostID}/fw/confirm?session_id=${encodeURIComponent(fwSession.id)}`));
  }
  const d = await r.json().catch(() => ({}));
  if (r.ok) { out.textContent = 'règles confirmées ✓'; loadFW(); }
  else out.textContent = d.error || 'échec de la confirmation';
}

document.getElementById('btn-fw-open')?.addEventListener('click', () => {
  document.getElementById('fw-form').hidden = !document.getElementById('fw-form').hidden;
});
document.getElementById('btn-fw-apply')?.addEventListener('click', doFWApply);
document.getElementById('btn-fw-confirm')?.addEventListener('click', doFWConfirm);
document.getElementById('btn-fw-cancel')?.addEventListener('click', () => {
  document.getElementById('fw-form').hidden = true;
});

ugBridgeReady.then(refresh);
setInterval(refresh, 10000);