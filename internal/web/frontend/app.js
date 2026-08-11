// shroud web console — vanilla JS, no deps. The bearer token is read from ?token=
// (set by `shroud web --browser`) or pasted by the operator; kept in sessionStorage.
const TOKEN_KEY = 'shroudToken';
let TOKEN = new URLSearchParams(location.search).get('token') || sessionStorage.getItem(TOKEN_KEY) || '';

function setToken(t) { TOKEN = (t || '').trim(); if (TOKEN) sessionStorage.setItem(TOKEN_KEY, TOKEN); }
function headers() { return TOKEN ? { 'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' }; }

async function api(path, opts) {
  const r = await fetch(path, Object.assign({ headers: headers() }, opts || {}));
  let body = null;
  const ct = r.headers.get('content-type') || '';
  if (ct.includes('application/json')) body = await r.json();
  else body = await r.text();
  if (!r.ok) {
    const msg = (body && body.error) ? body.error : ('HTTP ' + r.status);
    throw new Error(msg);
  }
  return body;
}

function el(id) { return document.getElementById(id); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c])); }

// ---- tabs ----
document.querySelectorAll('#tabs button').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('#tabs button').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('main > section').forEach(s => s.classList.add('hidden'));
  b.classList.add('active');
  el(b.dataset.tab).classList.remove('hidden');
}));

// ---- token gate ----
function ensureToken() {
  if (TOKEN) return true;
  const t = prompt('shroud web bearer token (printed by `shroud web`):');
  if (t) { setToken(t); return true; }
  return false;
}

// ---- status / authorize badge ----
async function loadStatus() {
  try {
    const s = await api('/api/status');
    const b = el('authbadge');
    if (s.authorized) { b.textContent = 'authorized'; b.className = 'badge ok'; }
    else { b.textContent = 'not authorized (generate blocked)'; b.className = 'badge no'; }
  } catch (e) {
    const b = el('authbadge');
    if (String(e).includes('401')) { b.textContent = 'bad/missing token'; b.className = 'badge no'; }
    else { b.textContent = 'error'; b.className = 'badge no'; }
  }
}

// ---- catalog ----
async function loadCatalog() {
  const techs = await api('/api/catalog');
  el('catcount').textContent = techs.length + ' techniques (' + techs.filter(t => t.implemented).length + ' implemented)';
  const tb = el('cattable').querySelector('tbody');
  tb.innerHTML = techs.map(t => `<tr>
    <td><code>${esc(t.id)}</code></td>
    <td>${esc(t.name)}</td>
    <td>${esc(t.category)}</td>
    <td><code>${esc(t.subtech)}</code></td>
    <td><span class="st ${t.implemented ? 'imp' : 'planned'}">${t.implemented ? 'implemented' : 'planned'}</span></td>
    <td>${esc(t.summary)}</td>
  </tr>`).join('');
  el('techlist').innerHTML = techs.map(t => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('');
}

// ---- evasion ----
async function loadEvasion() {
  const ev = await api('/api/evasion');
  const tb = el('evasiontable').querySelector('tbody');
  tb.innerHTML = ev.map(l => `<tr>
    <td><span class="st ${l.implemented ? 'imp' : 'planned'}">${l.implemented ? '✓' : '·'}</span></td>
    <td><code>${esc(l.layer)}</code></td>
    <td>${esc(l.help)}</td>
  </tr>`).join('');
}

// ---- formats ----
let FORMATS = null;
async function loadFormats() {
  FORMATS = await api('/api/formats');
  el('deliverfmt').innerHTML = FORMATS.delivery.map(f => `<option value="${f}">${f}</option>`).join('');
}

// ---- c2 ----
async function loadC2() {
  const list = await api('/api/c2');
  // populate both c2 selects
  const opts = ['<option value="">(none — raw -s)</option>']
    .concat(list.map(p => `<option value="${esc(p.name)}">${esc(p.name)}</option>`)).join('');
  el('genc2').innerHTML = opts;
  el('deliverc2').innerHTML = opts;
  // c2 tab cards
  el('c2list').innerHTML = list.map(p => `<div class="c2card">
    <h3>${esc(p.name)}</h3>
    <div class="h">${esc(p.help)}</div>
    ${p.flags && p.flags.length ? `<table><thead><tr><th>flag</th><th>type</th><th>default</th><th>usage</th></tr></thead>
      <tbody>${p.flags.map(f => `<tr><td><code>--${esc(f.name)}</code></td><td>${esc(f.type)}</td><td>${esc(f.default)}</td><td>${esc(f.usage)}</td></tr>`).join('')}</tbody></table>` : '<div class="h">(no flags)</div>'}
  </div>`).join('');
  // wire dynamic flag forms on c2 change
  el('genc2').onchange = () => renderC2Flags(el('genc2').value, 'c2flags', list);
  el('deliverc2').onchange = () => renderC2Flags(el('deliverc2').value, 'deliverc2flags', list);
}

function renderC2Flags(name, target, list) {
  const card = list.find(p => p.name === name);
  const box = el(target);
  if (!card || !card.flags || !card.flags.length) { box.innerHTML = ''; return; }
  box.innerHTML = '<fieldset><legend>' + esc(name) + ' flags</legend>' +
    card.flags.map(f => {
      const lbl = f.name;
      if (f.type === 'bool') return `<label class="chk"><input type="checkbox" data-flag="${esc(f.name)}"> ${esc(lbl)} <small>${esc(f.usage)}</small></label>`;
      return `<label>${esc(lbl)} <small>(${esc(f.usage)})</small><input data-flag="${esc(f.name)}" placeholder="${esc(f.default)}"></label>`;
    }).join('') + '</fieldset>';
}

function collectC2Flags(boxId) {
  const out = {};
  el(boxId).querySelectorAll('[data-flag]').forEach(i => {
    const n = i.getAttribute('data-flag');
    if (i.type === 'checkbox') { if (i.checked) out[n] = true; }
    else if (i.value) out[n] = i.value;
  });
  return out;
}

// ---- generate ----
el('genform').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!ensureToken()) return;
  const out = el('genout'); out.textContent = 'working…';
  const fd = new FormData(e.target);
  const flags = {};
  for (const [k, v] of fd.entries()) if (v !== '') flags[k] = v;
  // checkboxes
  ['no-build', 'garble', 'tiny'].forEach(n => { if (fd.get(n) === 'on' || fd.get(n) === true) flags[n] = true; });
  // fix checkbox values (FormData sends "on" for checked)
  ['no-build', 'garble', 'tiny'].forEach(n => { if (flags[n] === 'on') flags[n] = true; else delete flags[n]; });
  Object.assign(flags, collectC2Flags('c2flags'));
  const req = { id: fd.get('id') || '', flags };
  try {
    const res = await api('/api/generate', { method: 'POST', body: JSON.stringify(req) });
    out.textContent = formatResult(res);
  } catch (err) { out.textContent = 'error: ' + err.message; }
});

// ---- deliver ----
el('delivermode').addEventListener('change', () => {
  const remote = el('delivermode').value === 'remote';
  el('deliverform').querySelector('[name="shellcode"]').disabled = remote;
  el('deliverform').querySelector('[name="c2"]').disabled = remote;
  el('deliverform').querySelector('[name="url"]').disabled = !remote;
});
el('delivermode').dispatchEvent(new Event('change'));

el('deliverform').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!ensureToken()) return;
  const out = el('deliverout'); out.textContent = 'working…';
  const fd = new FormData(e.target);
  const flags = { format: fd.get('format') || '' };
  const remote = fd.get('mode') === 'remote';
  if (remote) { if (fd.get('url')) flags.url = fd.get('url'); }
  else { if (fd.get('shellcode')) flags.shellcode = fd.get('shellcode'); if (fd.get('c2')) flags.c2 = fd.get('c2'); }
  if (fd.get('launcher')) flags.launcher = fd.get('launcher');
  if (fd.get('out')) flags.out = fd.get('out');
  Object.assign(flags, collectC2Flags('deliverc2flags'));
  const req = { id: fd.get('id') || '', flags };
  try {
    const res = await api('/api/generate', { method: 'POST', body: JSON.stringify(req) });
    out.textContent = formatResult(res);
  } catch (err) { out.textContent = 'error: ' + err.message; }
});

function formatResult(res) {
  const lines = [];
  if (res.technique_id) lines.push(`technique : ${res.technique_id} — ${res.technique_name}`);
  lines.push(`format    : ${res.format}`);
  if (res.mode) lines.push(`mode      : ${res.mode}`);
  if (res.evasion) lines.push(`evasion   : ${res.evasion}`);
  if (res.outdir) lines.push(`output dir: ${res.outdir}`);
  if (res.built) lines.push(`built     : ${res.built_path} (${res.built_bytes} bytes)`);
  else if (res.built === false) lines.push(`built     : (source only / no-build)`);
  if (res.source) lines.push(`shellcode : ${res.source}`);
  if (res.sleep_ms) lines.push(`sleep demo: ${res.sleep_ms}ms`);
  if (res.artifacts && res.artifacts.length) {
    lines.push('artifacts :');
    res.artifacts.forEach(a => {
      const dl = a.download_url ? `  → ${a.path} (${a.bytes} bytes)  [${a.download_url}]` : `  → ${a.path} (${a.bytes} bytes)`;
      lines.push(dl);
    });
  }
  if (res.project_files && res.project_files.length) {
    lines.push('project files:');
    res.project_files.forEach(f => lines.push('  ' + f));
  }
  if (res.note) lines.push(res.note);
  return lines.join('\n');
}

// ---- boot ----
(async function boot() {
  if (TOKEN) { try { await loadStatus(); } catch (e) { el('authbadge').textContent = 'bad token'; } }
  else { el('authbadge').textContent = 'enter token (open a tab)'; }
  try { await loadCatalog(); await loadEvasion(); await loadFormats(); await loadC2(); } catch (e) {
    if (String(e).includes('401')) { el('authbadge').textContent = 'token required'; if (ensureToken()) location.reload(); }
  }
})();