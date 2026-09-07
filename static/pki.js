'use strict';
const $  = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));

const SECTIONS = {
  conf: 'CONFIG', yubikey: 'YUBIKEY', cert: 'CERTIFICATES', server: 'SERVERS',
  ldaps: 'LDAPS', webmin: 'WEBMIN CHAIN', nextcloud: 'NEXTCLOUD'
};
const out = $('#out');
let busy = false;

// ---------------------------------------------------------------- output --
function esc(s){ return s.replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function write(text, cls){
  const span = document.createElement('span');
  if (cls) span.className = cls;
  span.textContent = text;
  out.appendChild(span);
  out.scrollTop = out.scrollHeight;
}

function writeLines(chunk){
  // colour the terse OK/ERR/WARN prefixes the shell emits
  for (const line of chunk.split(/(?<=\n)/)) {
    let cls = '';
    if (/^OK\b/.test(line))        cls = 'l-ok';
    else if (/^ERR\b/.test(line))  cls = 'l-err';
    else if (/^WARN\b/.test(line)) cls = 'l-warn';
    else if (/^\$ /.test(line) || /^==/.test(line)) cls = 'l-cmd';
    write(line, cls);
  }
}

function clearOut(){ out.textContent = ''; }

// ---------------------------------------------------------------- status --
async function loadStatus(){
  const dash = $('#dash');
  try {
    const r = await fetch('/api/status', {cache:'no-store'});
    if (r.status === 401) { location.href = '/login'; return; }
    const d = await r.json();
    if (d.error) { dash.innerHTML = `<p class="msg-err">${esc(d.error)}</p>`; return; }
    render(d);
  } catch (e) {
    dash.innerHTML = `<p class="msg-err">status request failed: ${esc(String(e))}</p>`;
  }
}

function render(d){
  const groups = {};
  for (const rec of d.sections) (groups[rec.section] ||= []).push(rec);

  const dash = $('#dash');
  dash.innerHTML = '';
  for (const [key, title] of Object.entries(SECTIONS)) {
    const rows = groups[key];
    if (!rows || !rows.length) continue;
    const worst = rows.reduce((w, r) =>
      r.state === 'err' ? 'err' :
      (r.state === 'warn' && w !== 'err') ? 'warn' :
      (r.state === 'unknown' && w === 'ok') ? 'unknown' : w, 'ok');

    const card = document.createElement('div');
    card.className = `card ${worst}`;
    card.innerHTML = `<h3>${title}</h3>` + rows.map(r => `
      <div class="row">
        <span class="id">${esc(r.id)}</span>
        <span class="label"><span class="badge ${r.state}">${esc(r.label)}</span></span>
        ${r.detail ? `<span class="detail">${esc(r.detail)}</span>` : ''}
      </div>`).join('');
    dash.appendChild(card);
  }

  const b = $('#overall');
  b.className = `badge ${d.overall}`;
  b.textContent = d.overall;
  $('#stamp').textContent = d.generated;
}

// ---------------------------------------------------------------- actions --
function confirmBox(text){
  return new Promise(resolve => {
    const m = $('#modal');
    $('#modal-text').textContent = text;
    m.classList.remove('hidden');
    const done = v => { m.classList.add('hidden'); resolve(v); };
    $('#modal-yes').onclick = () => done(true);
    $('#modal-no').onclick  = () => done(false);
    m.onclick = e => { if (e.target === m) done(false); };
  });
}

function setBusy(v){
  busy = v;
  $$('.btn.act').forEach(b => { b.disabled = v; });
}

async function runAction(action, kind, needsConfirm){
  if (busy) return;
  let arg = '';
  if (kind === 'host' || kind === 'host?') arg = $('#host').value;
  if (kind === 'mode') arg = $('#mode').value;
  if (action === 'verify-tls') arg = $('#host').value;

  if (needsConfirm) {
    const target = arg ? ` on ${arg}` : '';
    if (!await confirmBox(`Run "${action}"${target}? This changes live servers.`)) return;
  }

  setBusy(true);
  write(`\n`, '');
  try {
    const r = await fetch('/api/action', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': window.PKI.csrf},
      body: JSON.stringify({action, arg, csrf: window.PKI.csrf})
    });
    if (r.status === 401) { location.href = '/login'; return; }
    if (!r.ok && r.headers.get('content-type')?.includes('json')) {
      const e = await r.json();
      writeLines(`ERR ${e.error}\n`);
      return;
    }
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      writeLines(dec.decode(value, {stream: true}));
    }
  } catch (e) {
    writeLines(`ERR request failed: ${e}\n`);
  } finally {
    setBusy(false);
    loadStatus();          // auto-refresh after every action
  }
}

// ------------------------------------------------------------------- wire --
$$('.btn.act').forEach(btn => {
  btn.addEventListener('click', () => {
    const a = btn.dataset.action;
    if (a === 'status') { clearOut(); write('refreshing status...\n'); loadStatus(); return; }
    runAction(a, btn.dataset.kind, btn.dataset.confirm === '1');
  });
});
$('#refresh').addEventListener('click', loadStatus);
$('#clear').addEventListener('click', clearOut);

let timer = null;
function arm(){
  clearInterval(timer);
  if ($('#autorefresh').checked) timer = setInterval(() => { if (!busy) loadStatus(); }, 60000);
}
$('#autorefresh').addEventListener('change', arm);

loadStatus();
arm();
