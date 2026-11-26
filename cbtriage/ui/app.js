//
// Copyright (c) 2026-Present Couchbase, Inc All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Single-file timeline UI logic. Talks to the local JSON API only.

const CAT_COLORS = {
  connectivity:'#36cfc9', failover:'#ff4d4f', rebalance:'#9254de',
  orchestrator:'#4ea1ff', crash:'#ff7a45', config:'#73d13d',
  os_kernel:'#ffc53d', boot:'#f759ab', http:'#8c8c8c', other:'#3a4150',
};
const FACETS = [
  ['nodes','node'], ['severities','severity'], ['categories','category'],
  ['sources','source'], ['services','service'], ['subsystems','subsystem'],
];

let META = null;
let sel = {};                 // facet -> Set of selected values
let range = {start:null, end:null};
let pinned = null;            // event IDs from a clicked finding (null = off)
let sortBy = null;            // null = oldest first; 'ts_desc' = newest first;
                              // 'resp_ms' = slowest HTTP first
// Page-at-a-time state for the timeline/HTTP table. The server pages via
// limit/offset; each page REPLACES the table body rather than appending, so
// the DOM stays bounded to one page no matter how large the result set (an
// unfiltered http_access view is easily hundreds of thousands of rows). Prev/
// Next/jump move the offset; row expansions reset on a page change by design.
const PAGE = 1000;
let pgOffset = 0;             // start row (offset) of the page currently shown
let pgTotal = 0;             // total rows matching the current query
let pgShown = 0;             // rows rendered on the current page
let pgLoading = false;       // a fetch is in flight (guards the pager controls)
let pgHttp = false;          // current render is HTTP-scoped (column layout)
let pgNcol = 6;              // colspan for the raw/placeholder rows
// Display timezone: 'utc' or 'local'. 'local' = collection-local time, shown
// per-event at the offset that line's log actually recorded — so it is
// DST-correct across a months-long collection (and per-node-correct in a
// multi-zone cluster). All event times are stored as UTC epoch; timezone is
// purely a display + input-parsing layer on top.
let displayMode = 'local';
let OFFSET_TL = [];   // [{ts, off}] offset transition points (UTC), from meta

const $ = (id) => document.getElementById(id);
const qsv = (s) => encodeURIComponent(s);

function fmtOffset(min) {
  const s = min < 0 ? '-' : '+', a = Math.abs(min);
  return s + String(Math.floor(a/60)).padStart(2,'0') + ':'
           + String(a%60).padStart(2,'0');
}
function distinctOffsets() { return [...new Set(OFFSET_TL.map(s => s.off))]; }
// Offset (minutes) in effect at a UTC epoch: last transition whose start <= ts.
function offsetAt(utc) {
  let off = OFFSET_TL.length ? OFFSET_TL[0].off : 0;
  for (const s of OFFSET_TL) { if (s.ts <= utc) off = s.off; else break; }
  return off;
}
// Offset for DISPLAY: an event's own captured offset in local mode (falling
// back to the timeline when a row lacks one), else 0 (UTC).
function dispOffFor(evOff, epoch) {
  if (displayMode !== 'local') return 0;
  return (evOff != null) ? evOff : offsetAt(epoch);
}
// Label for the active zone. A single offset is named precisely; a varying one
// (DST or multi-zone) is just "local" since each row carries its own.
function tzLabel() {
  if (displayMode !== 'local') return 'UTC';
  const offs = distinctOffsets();
  if (offs.length === 1) {
    const names = [...new Set((META.nodes||[]).map(n => n.tz_name)
      .filter(Boolean))];
    return (names.length === 1 ? names[0] + ' ' : '') + fmtOffset(offs[0]);
  }
  return 'local';
}
// epoch -> 'YYYY-MM-DD HH:MM:SS' at a given offset (toISOString renders UTC, so
// we pre-add the offset to land on local wall-clock).
function fmtAtOff(epoch, offMin) {
  if (epoch == null) return '—';
  return new Date((epoch + offMin*60) * 1000)
    .toISOString().replace('T',' ').slice(0,19);
}
// Table cell: render at the event's own offset.
function fmtTime(epoch, evOff) { return fmtAtOff(epoch, dispOffFor(evOff, epoch)); }
// Point with no event offset (histogram labels, range box): use the timeline.
function fmtAt(epoch) {
  return fmtAtOff(epoch, displayMode === 'local' ? offsetAt(epoch) : 0);
}
function fmtInput(epoch) { return epoch == null ? '' : fmtAt(epoch); }
// Human uptime from seconds: largest units down to minutes ("12d 4h 30m").
function fmtDur(secs) {
  if (secs == null || secs < 0) return '—';
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const parts = [];
  if (d) parts.push(d + 'd');
  if (d || h) parts.push(h + 'h');
  parts.push(m + 'm');
  return parts.join(' ');
}
// Parse 'YYYY-MM-DD[ HH:MM[:SS]]' typed in the active zone -> UTC epoch.
// Date-only defaults to 00:00:00. An explicit offset/Z is honored as-is. In
// local mode the wall clock is mapped back to UTC using the offset in effect
// at the target instant (one correction step handles a DST boundary).
//
// asEnd makes a coarse upper bound INCLUSIVE of its last unit: a `to` of
// 08:32:32 covers the whole 08:32:32 second (so an event at 08:32:32.856 is
// included, not excluded as just-past-the-bound); a `to` of 08:32 covers that
// minute; a date-only `to` covers that whole day. Give explicit sub-seconds to
// get an exact bound.
function parseTs(s, asEnd=false) {
  s = (s || '').trim();
  if (!s) return null;
  let bump = 0;
  if (asEnd) {
    if (/\d:\d\d:\d\d\.\d/.test(s)) bump = 0;        // sub-second given: exact
    else if (/\d:\d\d:\d\d/.test(s)) bump = 1;       // whole second
    else if (/\d:\d\d/.test(s)) bump = 60;           // whole minute
    else bump = 86400;                               // date only: whole day
    if (bump) bump -= 0.001;
  }
  let iso = s.replace(' ', 'T');
  if (/^\d{4}-\d{2}-\d{2}$/.test(iso)) iso += 'T00:00:00';
  if (/[zZ]|[+\-]\d\d:?\d\d$/.test(iso)) {
    const ms = Date.parse(iso);
    return isNaN(ms) ? null : ms / 1000 + bump;
  }
  const naive = Date.parse(iso + 'Z');   // wall clock read as if UTC
  if (isNaN(naive)) return null;
  const nsec = naive / 1000;
  if (displayMode !== 'local') return nsec + bump;
  let off = OFFSET_TL.length ? OFFSET_TL[OFFSET_TL.length - 1].off : 0;
  let utc = nsec - off*60;
  const off2 = offsetAt(utc);
  if (off2 !== off) utc = nsec - off2*60;   // correct across a DST boundary
  return utc + bump;
}
// Reflect the current range into the start/end inputs (in the active zone).
function syncRangeInputs() {
  $('tstart').value = fmtInput(range.start);
  $('tend').value = fmtInput(range.end);
}
// Update timezone-dependent labels: time column header + input hint.
function syncTZLabels() {
  const lbl = tzLabel();
  // Rebuild the head (vs. textContent) so the sort arrow + handlers survive.
  if ($('th-time')) renderHead();
  if ($('tzlabel')) $('tzlabel').textContent = lbl;
}

function qstring(extra={}) {
  const p = [];
  for (const [k,_] of FACETS) {
    if (sel[k] && sel[k].size) p.push(`${k}=${qsv([...sel[k]].join(','))}`);
  }
  if (pinned && pinned.length) p.push(`ids=${qsv(pinned.join(','))}`);
  if (range.start!=null) p.push(`start=${range.start}`);
  if (range.end!=null) p.push(`end=${range.end}`);
  const q = $('q').value.trim();
  if (q) p.push(`q=${qsv(q)}`);
  const minms = $('minms').value.trim();
  if (minms) p.push(`min_resp_ms=${qsv(minms)}`);
  const status = $('status').value.trim();
  if (status) p.push(`status=${qsv(status)}`);
  const path = $('path').value.trim();
  if (path) p.push(`path=${qsv(path)}`);
  if (sortBy) p.push(`order=${qsv(sortBy)}`);
  if ($('anchored').checked) p.push('anchored_only=1');
  for (const k in extra) p.push(`${k}=${qsv(extra[k])}`);
  return p.join('&');
}

async function getJSON(url) { return (await fetch(url)).json(); }

// ---- meta banner + facets ----
function renderPills() {
  const pl = META.info.platform || {};
  const pills = [];
  pills.push(`<span class="pill">v ${META.info.version||'?'}</span>`);
  if (pl.is_capella) pills.push(`<span class="pill capella">Capella (provisioned)</span>`);
  else pills.push(`<span class="pill">profile ${pl.profile||'?'}</span>`);
  if (pl.is_kubernetes) pills.push(`<span class="pill k8s">Kubernetes</span>`);
  if (pl.cloud) pills.push(`<span class="pill">${pl.cloud}</span>`);
  if (META.info.redacted) pills.push(`<span class="pill redact">REDACTED</span>`);
  pills.push(`<span class="pill">${(META.nodes||[]).length} nodes</span>`);
  pills.push(`<span class="pill">${META.total_events} events</span>`);
  const r = META.time_range;
  if (r.lo) pills.push(`<span class="pill">${fmtAt(r.lo)} → ${fmtAt(r.hi)} ${tzLabel()}</span>`);
  $('meta-pills').innerHTML = pills.join(' ');
}

function facetValues(key) {
  if (key==='nodes') return (META.nodes||[]).map(n=>n.name);
  return META[key] || [];
}
function renderFacets() {
  const host = $('filters');
  host.innerHTML = '';
  for (const [key,_] of FACETS) {
    const vals = facetValues(key);
    if (!vals.length) continue;
    const div = document.createElement('div');
    div.className = 'facet';
    const items = vals.map(v => {
      const id = `f_${key}_${v}`;
      const checked = sel[key] && sel[key].has(v) ? 'checked' : '';
      const color = key==='categories' ? `style="color:${CAT_COLORS[v]||''}"`:'';
      // Services get a second action beside the filter checkbox: open the
      // drawer with that service's lifecycle + rebalance calls.
      const open = key==='services'
        ? ` <span class="svc-open" data-svc="${escapeHtml(v)}"
             title="lifecycle + rebalance calls for ${escapeHtml(v)}">▸</span>` : '';
      return `<label><input type="checkbox" data-k="${key}" data-v="${v}" ${checked}>
              <span ${color}>${v}</span>${open}</label>`;
    }).join('');
    div.innerHTML = `<h3>${key} <a href="#" data-clear="${key}" class="muted">clear</a></h3>
                     <div class="facet-list">${items}</div>`;
    host.appendChild(div);
  }
  host.querySelectorAll('input[type=checkbox]').forEach(cb => {
    cb.onchange = () => {
      const k = cb.dataset.k, v = cb.dataset.v;
      sel[k] = sel[k] || new Set();
      cb.checked ? sel[k].add(v) : sel[k].delete(v);
      pinned = null; refresh();
    };
  });
  host.querySelectorAll('.svc-open[data-svc]').forEach(el => {
    el.onclick = (e) => {
      e.preventDefault(); e.stopPropagation();   // don't toggle the checkbox
      showService(el.dataset.svc, '');
    };
  });
  host.querySelectorAll('a[data-clear]').forEach(a => {
    a.onclick = (e) => { e.preventDefault(); sel[a.dataset.clear]=new Set();
                         pinned = null; renderFacets(); refresh(); };
  });
}

// ---- findings ----
// Synthetic node labels that don't name a real node, so they can't scope a
// node filter (and on their own make a finding non-navigable).
const NONNODE = new Set(['?', '(multiple)', '(cluster)']);
function findingRelated(f) {
  try { return JSON.parse(f.related || '[]'); } catch(e) { return []; }
}
// A click only helps if it can narrow the view: pinned events, a real time to
// window on, or a real node to filter by. Otherwise the finding is inert
// (e.g. pressure-unavailable: node '(cluster)', no ts, no related).
function findingClickable(f) {
  return findingRelated(f).length > 0
      || !!f.ts_epoch
      || (f.node && !NONNODE.has(f.node));
}
// ---- inline strips ----
// Every band above the table (findings, activity, host pressure, cluster
// overview) collapses the same way, because they compete for the same vertical
// space and on a laptop viewport all of them open leaves the table with no rows.
// Which ones matter is per-person and per-investigation, so it is a choice
// rather than a layout we guess at -- and the choice persists, or it would have
// to be remade on every reload.
const STRIP_PREFS_KEY = 'cbtriage.strips';
// activity starts collapsed: its only unique function is the drag-to-zoom
// gesture, and it costs 110px to keep that visible at all times.
const STRIP_DEFAULTS = {findings: true, hist: false, pressure: true,
                        overview: true};
let stripOpen = {...STRIP_DEFAULTS};

function loadStripPrefs() {
  try {
    const saved = JSON.parse(localStorage.getItem(STRIP_PREFS_KEY) || '{}');
    stripOpen = {...STRIP_DEFAULTS, ...saved};
  } catch (e) {
    stripOpen = {...STRIP_DEFAULTS};   // unreadable pref: fall back, never throw
  }
}

function saveStripPrefs() {
  try { localStorage.setItem(STRIP_PREFS_KEY, JSON.stringify(stripOpen)); }
  catch (e) { /* private mode or full quota: the layout just won't persist */ }
}

function applyStrip(name) {
  const hdr = document.querySelector(`.striphdr[data-strip="${name}"]`);
  if (!hdr) return;
  const strip = hdr.closest('.strip');
  const open = stripOpen[name] !== false;
  if (strip) strip.classList.toggle('collapsed', !open);
  const caret = hdr.querySelector('.caret');
  if (caret) caret.textContent = open ? '▾' : '▸';
}

function setStripOpen(name, open) {
  stripOpen[name] = open;
  applyStrip(name);
  saveStripPrefs();
  // The canvas was sized against a zero-height box while collapsed, so it has
  // to be redrawn once it has real dimensions again.
  if (name === 'hist' && open) drawHist();
  // Deferred until the strip is first opened, so a collapsed overview costs
  // nothing on load.
  if (name === 'overview' && open) showOverview();
}

function initStrips() {
  loadStripPrefs();
  document.querySelectorAll('.striphdr[data-strip]').forEach(hdr => {
    const name = hdr.dataset.strip;
    applyStrip(name);
    hdr.onclick = (e) => {
      // The overview header also carries its own hide button.
      if (e.target.closest('button')) return;
      setStripOpen(name, stripOpen[name] === false);
    };
  });
}

async function renderFindings() {
  const fs = await getJSON('/api/findings');
  const sevClass = {critical:'crit', error:'error', warn:'warn', info:'info'};
  // Collapsible, with the count kept in the header so a collapsed block still
  // says how much is behind it. Findings is the tallest thing above the table
  // and is read once at the start of a session, so it should not go on costing
  // rows for the rest of it.
  const html = [`<div class="striphdr" data-strip="findings"
      title="click to collapse or expand"><span>findings${
      fs.length ? ` (${fs.length})` : ''}</span><span class="caret"></span></div>`,
    '<div class="stripbody">'];
  if (!fs.length) html.push('<div class="muted">no findings</div>');
  for (const f of fs) {
    const c = sevClass[f.severity]||'info';
    const nc = findingClickable(f) ? '' : ' noclick';
    html.push(`<div class="finding ${c}${nc}" data-ts="${f.ts_epoch||''}" data-node="${f.node}">
      <div class="ttl">${f.title}</div>
      <div class="ho">${f.handoff||f.detail||''}</div></div>`);
  }
  html.push('</div>');
  $('findings').innerHTML = html.join('');
  // The header is rebuilt with the list, so its collapse wiring is rebuilt too.
  initStrips();
  $('findings').querySelectorAll('.finding').forEach((el, i) => {
    if (!findingClickable(fs[i])) return;   // inert finding: no handler
    el.onclick = () => {
      const rel = findingRelated(fs[i]);
      sel = {}; range = {start:null, end:null}; pinned = null;
      if (rel.length) {
        // Show exactly the events this finding was built from.
        pinned = rel;
      } else {
        // No related events recorded — fall back to node + time window.
        const node = el.dataset.node, ts = parseFloat(el.dataset.ts);
        if (node && !NONNODE.has(node)) sel.nodes = new Set([node]);
        if (!isNaN(ts)) { range.start = ts-300; range.end = ts+300; }
      }
      $('q').value=''; syncRangeInputs(); renderFacets(); refresh();
    };
  });
}

// ---- histogram ----
let HIST = null;
function drawHist() {
  const cv = $('hist'), ctx = cv.getContext('2d');
  const W = cv.clientWidth, H = cv.clientHeight;
  cv.width = W*devicePixelRatio; cv.height = H*devicePixelRatio;
  ctx.scale(devicePixelRatio, devicePixelRatio);
  ctx.clearRect(0,0,W,H);
  if (!HIST || !HIST.bins.length || !HIST.lo) return;
  const nb = 240, bw = W/nb;
  const stacks = {};   // bucket -> [{cat,c}]
  let maxTot = 1;
  HIST.bins.forEach(b => { (stacks[b.b]=stacks[b.b]||[]).push(b); });
  for (const k in stacks) {
    const t = stacks[k].reduce((s,x)=>s+x.c,0); if (t>maxTot) maxTot=t;
  }
  for (const k in stacks) {
    let y = H;
    const x = (+k) * bw;
    for (const seg of stacks[k]) {
      const h = (seg.c/maxTot) * (H-2);
      ctx.fillStyle = CAT_COLORS[seg.category]||'#555';
      ctx.fillRect(x, y-h, Math.max(1,bw-0.5), h);
      y -= h;
    }
  }
  $('hlo').textContent = fmtAt(HIST.lo);
  $('hhi').textContent = fmtAt(HIST.hi);
}
function bindHistBrush() {
  const cv = $('hist'); let down=null;
  const toEpoch = (clientX) => {
    const rct = cv.getBoundingClientRect();
    const frac = Math.min(1,Math.max(0,(clientX-rct.left)/rct.width));
    return HIST.lo + frac*(HIST.hi-HIST.lo);
  };
  cv.onmousedown = (e) => { if(HIST&&HIST.lo) down = toEpoch(e.clientX); };
  cv.onmouseup = (e) => {
    if (down==null) return;
    const up = toEpoch(e.clientX);
    if (Math.abs(up-down) < (HIST.hi-HIST.lo)*0.01) { range.start=range.end=null; }
    else { range.start=Math.min(down,up); range.end=Math.max(down,up); }
    down=null; pinned=null; syncRangeInputs(); refresh();
  };
}

// ---- table ----
// HTTP column view kicks in when the results are scoped to http_access*, or
// when an HTTP-only control (latency/status) is in use. These logs have a fixed
// field set worth showing as real columns; everything else keeps the generic
// one-line summary view.
function isHttpMode() {
  if ($('minms').value.trim() || $('status').value.trim()
      || $('path').value.trim()) return true;
  const onlyVals = (key, allowed) => {
    const s = sel[key];
    if (!s || !s.size) return false;
    for (const v of s) if (!allowed.includes(v)) return false;
    return true;
  };
  return onlyVals('sources', ['http_access','http_access_internal'])
      || onlyVals('categories', ['http']);
}

function setHead(http) {
  const tl = tzLabel();
  // Time is the sort key unless resp_ms is active; ▲ = oldest first (default),
  // ▼ = newest first. Click toggles between them — newest-first puts the tail
  // of the window at the top.
  const tSorted = sortBy!=='resp_ms';
  const tArrow = tSorted ? (sortBy==='ts_desc' ? ' ▼' : ' ▲') : '';
  const timeTh = `<th id="th-time" class="sortable${tSorted?' sorted':''}" `
    + `title="click to toggle oldest/newest first">time (${tl})${tArrow}</th>`;
  const msArrow = sortBy==='resp_ms' ? ' ▼' : '';
  $('head').innerHTML = http
    ? `${timeTh}<th>node</th><th>status</th>`
      + `<th>method</th><th>path</th>`
      + `<th id="th-ms" class="sortable${sortBy==='resp_ms'?' sorted':''}" `
      + `title="click to sort slowest first">resp ms${msArrow}</th><th>user</th>`
    : `${timeTh}<th>node</th><th>source</th>`
      + `<th></th><th>subsystem</th><th>summary</th>`;
}

// Rebuild the header and (re)bind its sort toggles — innerHTML replacement drops
// the old handlers, so this must run after every setHead.
function renderHead() {
  setHead(pgHttp);
  const t = $('th-time');
  if (t) t.onclick = () => { sortBy = sortBy==='ts_desc' ? null : 'ts_desc';
                             renderTable(); };
  const ms = $('th-ms');
  if (ms) ms.onclick = () => { sortBy = sortBy==='resp_ms' ? null : 'resp_ms';
                               renderTable(); };
}

function genericRow(e) {
  const clk = e.clock==='inferred'?'clock-inf':e.clock==='unanchored'?'clock-un':'';
  return `<tr class="ev" data-id="${e.id}">
    <td class="mono ${clk}">${fmtTime(e.ts_epoch, e.tz_offset_min)}</td>
    <td>${e.node}</td><td>${e.source}</td>
    <td><span class="sev ${e.severity}" title="${e.severity}"></span></td>
    <td class="cat">${e.subsystem||''}</td>
    <td>${escapeHtml(e.summary||'')} <span class="cat">[${e.category}]</span>${
      e.service ? ` <span class="svc-open" data-svc="${escapeHtml(e.service)}"
        data-svcnode="${escapeHtml(e.node||'')}"
        title="lifecycle + rebalance calls for ${escapeHtml(e.service)}"
        >${escapeHtml(e.service)} ▸</span>` : ''}</td>
  </tr>`;
}

function httpRow(e) {
  let f = {};
  try { f = JSON.parse(e.fields||'{}'); } catch(_) {}
  const clk = e.clock==='inferred'?'clock-inf':e.clock==='unanchored'?'clock-un':'';
  const st = f.status!=null ? f.status : '';
  return `<tr class="ev" data-id="${e.id}">
    <td class="mono ${clk}">${fmtTime(e.ts_epoch, e.tz_offset_min)}</td>
    <td>${e.node}</td>
    <td><span class="sev ${e.severity}" title="${e.severity}"></span> ${st}</td>
    <td>${escapeHtml(f.method||'')}</td>
    <td class="mono"><span class="pathlink" data-path="${escapeHtml(f.path_base||'')}"
      title="filter to this exact path">${escapeHtml(f.path||'')}</span></td>
    <td class="mono" style="text-align:right">${f.resp_ms!=null?f.resp_ms:''}</td>
    <td>${escapeHtml(f.user||'')}</td>
  </tr>`;
}

// Reset the table for the current query: rebuild the head, jump to the first
// page. Each page replaces the body, so the DOM never grows past PAGE rows.
async function renderTable() {
  pgHttp = isHttpMode();
  pgNcol = pgHttp ? 7 : 6;
  // The latency/status/path inputs only apply to http_access* rows, so only
  // surface them when the view is HTTP-scoped (or one is already in use).
  $('httpfilters').style.display = pgHttp ? '' : 'none';
  renderHead();
  await loadPage(0);
}

// Fetch the page starting at `offset` and REPLACE the table body with it.
async function loadPage(offset) {
  if (pgLoading) return;
  pgLoading = true;
  updatePager('loading');
  const data = await getJSON(
    '/api/events?'+qstring({limit:PAGE, offset}));
  pgTotal = data.total;
  pgOffset = offset;
  pgShown = data.events.length;
  const html = data.events
    .map(e => pgHttp ? httpRow(e) : genericRow(e)).join('');
  $('rows').innerHTML = html ||
    `<tr class="sentinel"><td colspan="${pgNcol}">no matching events</td></tr>`;
  $('tablewrap').scrollTop = 0;
  wireRows();
  pgLoading = false;
  updatePager('idle');
}

// Bind click handlers to rows added since the last call (marked via data-wired
// so appended pages don't re-bind the whole table).
function wireRows() {
  $('rows').querySelectorAll('tr.ev:not([data-wired])').forEach(tr => {
    tr.dataset.wired = '1';
    tr.onclick = async () => {
      const ex = tr.nextElementSibling;
      if (ex && ex.classList.contains('rawrow')) { ex.remove(); return; }
      const ev = await getJSON('/api/event?id='+tr.dataset.id);
      const raw = ev.raw || '';
      const loc = ev.log_path ? ('— '+escapeHtml(ev.log_path)+(ev.line_no?(':'+ev.line_no):'')) : '';
      const td = document.createElement('tr');
      td.className = 'rawrow';
      td.innerHTML = `<td colspan="${pgNcol}"><pre class="raw">${escapeHtml(raw)}
${loc}
${ev.fields?escapeHtml(ev.fields):''}</pre></td>`;
      tr.after(td);
    };
  });
  $('rows').querySelectorAll('.svc-open[data-svc]:not([data-wired])').forEach(el => {
    el.dataset.wired = '1';
    el.onclick = (e) => {
      e.stopPropagation();           // don't toggle the row's raw view
      showService(el.dataset.svc, el.dataset.svcnode || '');
    };
  });
  $('rows').querySelectorAll('.pathlink:not([data-wired])').forEach(el => {
    el.dataset.wired = '1';
    el.onclick = (e) => {
      e.stopPropagation();           // don't toggle the row's raw view
      $('path').value = el.dataset.path;
      pinned = null; refresh();
    };
  });
}

// Footer pager: page indicator + row range, with Prev/Next/jump enablement.
// Also keeps the top-of-table count label in sync.
function updatePager(state) {
  const prev = $('pgprev'), next = $('pgnext'), info = $('pginfo'),
        jump = $('pgjump');
  if (state === 'loading') {
    info.textContent = 'loading…';
    prev.disabled = next.disabled = jump.disabled = true;
    return;
  }
  const pinNote = pinned
    // A pin comes from a finding's evidence or from an operation's log lines,
    // so the banner names neither.
    ? ' — pinned to selected lines (clear or click a facet to browse all)' : '';
  if (pgTotal === 0) {
    info.textContent = 'no matching events';
    prev.disabled = next.disabled = jump.disabled = true;
    jump.value = '';
    $('count').textContent = '0 rows' + pinNote;
    return;
  }
  const pages = Math.max(1, Math.ceil(pgTotal / PAGE));
  const page = Math.floor(pgOffset / PAGE);            // 0-based
  const from = pgOffset + 1, to = pgOffset + pgShown;
  info.textContent = `page ${page+1} of ${pages.toLocaleString()} · `
    + `rows ${from.toLocaleString()}–${to.toLocaleString()} `
    + `of ${pgTotal.toLocaleString()}`;
  prev.disabled = pgOffset <= 0;
  next.disabled = pgOffset + PAGE >= pgTotal;
  jump.disabled = pages <= 1;
  jump.max = pages;
  jump.value = page + 1;
  $('count').textContent = `${pgTotal.toLocaleString()} rows` + pinNote;
}

function pagePrev() { if (pgOffset > 0) loadPage(Math.max(0, pgOffset - PAGE)); }
function pageNext() { if (pgOffset + PAGE < pgTotal) loadPage(pgOffset + PAGE); }
// Jump to a 1-based page number, clamped to the valid range.
function pageJump() {
  const pages = Math.max(1, Math.ceil(pgTotal / PAGE));
  let p = parseInt($('pgjump').value, 10);
  if (!Number.isFinite(p)) return;
  p = Math.min(Math.max(p, 1), pages);
  loadPage((p - 1) * PAGE);
}
function escapeHtml(s){return (s+'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

// ---- per-service drawer ----
// One service's whole history, in two deliberately separate sections:
//   lifecycle      did it start / stop / exit, and with what status (babysitter)
//   service rebalance  did it answer ServiceAPI calls (json_rpc)
// A service can be answering rebalance calls while crash-looping, and can be
// running perfectly while not answering, so merging them would hide the very
// distinction that decides whether this is ns_server's problem.
//
// NOT bound to the time window: a service that died before the window opened is
// usually what explains the window, so the drawer always shows the full capture.
let svcOpen = null;      // {name, node} currently shown, or null
// Half-width of the window opened around an outstanding call. Wide enough to
// catch what the rest of the cluster was doing when the call went unanswered,
// narrow enough that the table is still readable on a busy node.
const AROUND_S = 120;

async function showService(name, node) {
  if (!name) return;
  svcOpen = {name, node: node || ''};
  const d = await getJSON('/api/service?name=' + qsv(name)
                          + (svcOpen.node ? '&node=' + qsv(svcOpen.node) : ''));
  $('svcpanel').style.display = 'flex';
  $('svcname').textContent = name;
  // Header states the two verdicts up front, so the drawer answers before it
  // is read: is anything unanswered, and did the service stay up.
  const exits = d.exit_count || 0;
  const stalled = (d.outstanding || []).filter(r => !r.fields.at_capture_boundary).length;
  const bits = [];
  if (stalled) bits.push(`${stalled} unanswered`);
  if (exits) bits.push(`${exits} abnormal exit${exits > 1 ? 's' : ''}`);
  $('svccount').textContent = bits.length ? bits.join(' · ')
    : `${d.topology.length} ServiceAPI · ${d.lifecycle.length} lifecycle`;
  $('svccount').style.color = bits.length ? '#ff4d4f' : '';
  $('svccount').style.fontWeight = bits.length ? '600' : '';

  // Node picker only earns its space on a multi-node DB.
  const nodes = d.nodes || [];
  const wrap = $('svcnodewrap');
  wrap.style.display = nodes.length > 1 ? '' : 'none';
  if (nodes.length > 1) {
    $('svcnode').innerHTML = ['<option value="">all nodes</option>']
      .concat(nodes.map(n => `<option value="${escapeHtml(n)}"${
        n === svcOpen.node ? ' selected' : ''}>${escapeHtml(n)}</option>`)).join('');
  }

  const multi = nodes.length > 1 && !svcOpen.node;
  const life = d.lifecycle.map(t => {
    const st = t.exit_status == null ? '' :
      ` <span class="svc-note">status ${t.exit_status}</span>`;
    const nd = multi ? ` <span class="svc-note">${escapeHtml(t.node||'')}</span>` : '';
    // The dying service's own stderr (the panic) lives in the raw of this
    // entry; the row expands to show it rather than sending the reader away.
    const more = t.death_output
      ? ` <span class="svc-open" data-out="${t.id}">output ▾</span>` : '';
    return `<div class="svc-ev" data-id="${t.id}">
      <span class="t">${fmtTime(t.ts_epoch, t.tz_offset_min)}</span>
      <span class="w"><span class="svc-st ${t.lifecycle}">${t.lifecycle}</span>${st}${nd}${more}
        <div class="svc-note">${escapeHtml(t.summary || '')}</div></span></div>`;
  }).join('') || '<div class="muted" style="font-size:11px">no start/stop/exit lines for this service — it is not a babysitter-managed port, or its babysitter log is outside the capture</div>';

  // The stall question: is there a ServiceAPI call this service never answered?
  // That call, its request id and how long it sat unanswered is what gets
  // handed to the service team, so it leads and carries the detail.
  const out = (d.outstanding || []).map(r => {
    const f = r.fields || {};
    const secs = f.outstanding_s;
    const dur = secs == null ? '' : ` <b>${fmtDur(secs)}</b> with no response`;
    // In-flight at capture is ambiguous: the response may simply have landed
    // after the snapshot. Say so rather than calling it a stall.
    const amb = f.at_capture_boundary
      ? `<div class="svc-note">still in flight when the capture was taken — ambiguous, the response may have arrived after</div>` : '';
    const bits = [
      f.request_id != null ? `id=${escapeHtml(String(f.request_id))}` : '',
      f.channel ? escapeHtml(f.channel) : '',
      f.tc_type ? escapeHtml(f.tc_type) : '',
      f.tc_id ? `change=${escapeHtml(f.tc_id)}` : '',
      (f.keep_n != null ? `keep=${f.keep_n}` : ''),
      (f.eject_n != null ? `eject=${f.eject_n}` : ''),
    ].filter(Boolean).join(' · ');
    return `<div class="svc-ev" data-id="${r.id}" data-around="${r.ts_epoch||''}">
      <span class="t">${fmtTime(r.ts_epoch, r.tz_offset_min)}</span>
      <span class="w"><span class="svc-st ${f.at_capture_boundary ? 'restarting' : 'exited'}">${
        escapeHtml(f.method || 'call')}</span>${dur}
        <div class="svc-note">${bits}</div>${amb}
        <div class="svc-note">click to show the events around this call</div>
      </span></div>`;
  }).join('') || '<div class="muted" style="font-size:11px">nothing outstanding — every ServiceAPI call in this capture got a response</div>';

  const topo = (d.topology || []).map(r => {
    const f = r.fields || {};
    const rt = f.rt_ms != null ? ` <span class="svc-note">rt=${f.rt_ms}ms</span>` : '';
    // Flags that say whether the service still considers itself mid-rebalance.
    const flags = [
      f.has_task_rebalance === true ? 'rebalance task running' : '',
      f.is_balanced === false ? 'not balanced' : '',
      f.tasks_count ? `${f.tasks_count} task${f.tasks_count > 1 ? 's' : ''}` : '',
      f.tc_type ? escapeHtml(f.tc_type) : '',
    ].filter(Boolean).join(' · ');
    return `<div class="svc-ev" data-id="${r.id}">
      <span class="t">${fmtTime(r.ts_epoch, r.tz_offset_min)}</span>
      <span class="w"><span class="svc-st stopped">${
        escapeHtml(f.method || 'call')}</span>${rt}
        ${flags ? `<div class="svc-note">${flags}</div>` : ''}</span></div>`;
  }).join('') || '<div class="muted" style="font-size:11px">no ServiceAPI traffic — this service was not asked to do a topology change</div>';

  const otherN = d.other_rpc_count || 0;
  const otherNote = otherN
    ? `<div class="muted" style="font-size:11px;margin-top:10px">+ ${otherN} json_rpc
       message${otherN > 1 ? 's' : ''} on this service's other channels (cbauth and
       similar) — not rebalance traffic, not listed</div>` : '';

  $('svcbody').innerHTML =
    `<div class="svc-sec"><h4>outstanding calls</h4>${out}</div>
     <div class="svc-sec"><h4>ServiceAPI — topology / rebalance</h4>${topo}</div>
     <div class="svc-sec"><h4>lifecycle — babysitter</h4>${life}</div>
     ${otherNote}`;
  wireServiceRows();
}

function wireServiceRows() {
  $('svcbody').querySelectorAll('.svc-open').forEach(el => {
    el.onclick = async (e) => {
      e.stopPropagation();
      const row = el.closest('.svc-ev');
      const ex = row.querySelector('.svc-out');
      if (ex) { ex.remove(); el.textContent = 'output ▾'; return; }
      const ev = await getJSON('/api/event?id=' + el.dataset.out);
      const pre = document.createElement('pre');
      pre.className = 'svc-out';
      // Drop the header line; the row above already says what happened.
      pre.textContent = (ev.raw || '').split('\n').slice(1).join('\n').trim()
                        || '(no output captured)';
      row.appendChild(pre);
      el.textContent = 'output ▴';
    };
  });
  // Clicking a row moves the timeline to that moment. For an outstanding call
  // that means the events AROUND it, not the call alone -- the hand-off to the
  // service team is "here is the call you never answered, and here is what
  // everyone else was doing at the time", which a single pinned row can't show.
  $('svcbody').querySelectorAll('.svc-ev').forEach(el => {
    el.onclick = () => {
      const at = parseFloat(el.dataset.around || '');
      if (Number.isFinite(at)) {
        pinned = null;
        range.start = at - AROUND_S;
        range.end = at + AROUND_S;
        syncRangeInputs();
      } else {
        pinned = [parseInt(el.dataset.id, 10)];
      }
      refresh();
    };
  });
}

function hideService() { svcOpen = null; $('svcpanel').style.display = 'none'; }

// ---- operation drawer ----
// Clicking a block in the ops band opens the rebalance report for that
// operation, joined by operation_id (ns_orchestrator stamps it on the span,
// the report carries it as rebalanceId -- an exact key, not a time match).
//
// The report is the ONLY place two things are recorded: where an operation
// stopped (per-vbucket, per-phase), and how long each service took. Everything
// shown is a stored field. Nothing here says why it failed -- the reader draws
// that from the facts, so e.g. "docs left == docs total" is displayed and left
// to speak for itself rather than being labelled a wedge.
//
// Deliberately NOT a 1024-bar gantt: that is what makes the upstream plot
// unusable, and the phase table answers the same questions in text.
//
// The last section is the route into the logs: not the two event_log entries
// that bracket the span (they say only that it started and how it ended) but the
// lines the operation's own modules wrote, and the auto-failover down-state
// episodes behind a failover. See opProvSec.
let opOpen = null;       // drawer key currently shown, or null

function opNodes(list) {
  return (list || []).map(n => ldrShort(n)).join(', ');
}

// How a clicked block finds its span. operation_id when the events carried one
// (it is also the report's key); otherwise a synthetic key off the span's own
// dated event, which is unique per span and needs nothing from ns_server. Older
// builds, and failover events predating the id, land in the second case -- they
// used to jump straight to the two event_log lines and skip the drawer, which
// meant skipping the nodes, the reasons and the log lines with it.
function opKey(s) {
  const oid = (s.attrs || {}).operation_id || '';
  if (oid) return oid;
  return `span:${s.kind}:${s.start_event_id != null ? s.start_event_id
    : `end${s.end_event_id}`}`;
}

// ---- failover detail, shared by the ops band and the operation drawer ----
// Which nodes a failover acted on, and the reason event_log recorded per node.
// Both are span fields (see orchestration._failover_detail), so the band and the
// drawer read the same values rather than each digging through attributes.
function foNodes(span) {
  return (span && span.failover_nodes) || [];
}

// One line per failed-over node: the node and its own recorded reason. A node
// with no reason recorded says so -- only the initiated event carries
// failover_reason, so a span whose start fell off the event_log ring has the
// nodes but not the reasons, and that is stated rather than left blank.
function foLines(span) {
  const nodes = foNodes(span);
  if (!nodes.length) return [];
  const reasons = (span && span.failover_reasons) || {};
  const out = nodes.map(n => `failed over ${ldrShort(n)}: ${
    reasons[n] || 'no reason recorded on this event'}`);
  if (span.allow_unsafe) {
    out.push('allowUnsafe was set: ran without a healthy quorum');
  }
  return out;
}

// The failover's own facts, straight off the event_log span: which nodes it
// acted on and the reason recorded for EACH of them. Rendered above the report,
// because on a failover this is the question and the report answers a different
// one (where the vbucket moves got to).
function opFailoverSec(span) {
  const nodes = foNodes(span);
  if (!nodes.length) return '';
  const reasons = (span.failover_reasons) || {};
  const rows = nodes.map(n => `<tr>
      <td>${escapeHtml(ldrShort(n))}</td>
      <td>${reasons[n] ? escapeHtml(reasons[n])
        : '<span class="muted">not recorded on this event</span>'}</td>
    </tr>`).join('');
  // allowUnsafe is a modifier on a hard failover, not a type of its own, and it
  // is the one that means quorum was not there -- so it is stated, not folded in.
  const unsafe = span.allow_unsafe ? `<div class="op-msg">allowUnsafe was set:
    this ran without a healthy quorum</div>` : '';
  // Only the initiated event carries failover_reason. Say so once, here, rather
  // than leaving a table of blanks to be read as "no reason existed" -- but only
  // blame the missing initiated event when that is what happened. A span that
  // HAS its initiated event and still carries no reason is the ordinary
  // operator-driven failover: ns_server records a per-node reason for the
  // failovers it decides on itself, not for the ones it was told to run.
  const why = Object.keys(reasons).length ? '' : `<div class="muted"
    style="font-size:11px">${span.start_unknown
      ? `The per-node reason is recorded only on the failover_initiated event.
         This span was dated from its terminator, so the nodes survived in
         nodes_info and the reasons did not.`
      : `No per-node reason was recorded on the failover_initiated event.
         auto_failover fills that field in when it is the one deciding; a
         failover requested through the API carries the request, not a reason.`}
    </div>`;
  return `<div class="svc-sec"><h4>Nodes failed over</h4>
    <table class="op-tbl"><tr><th>node</th><th>reason recorded</th></tr>
    ${rows}</table>${unsafe}${why}</div>`;
}

// Provenance: one click from the drawer to the LOG LINES behind the span.
//
// The event_log entries alone are two lines -- "initiated" and how it ended --
// which is what the span already says on its face, so they are not the way in.
// The lines that say what the operation did are the ones its own modules wrote
// (see orchestration._OP_MODULES), and for a failover the down-state ladder that
// triggered it, both attached to the span server-side. This is the same route
// the auto-failover finding gives: one click pins every related line in the
// timeline, where they can be read next to everything else happening then.
//
// The event_log row stays as a last, muted entry -- it is the only evidence a
// span dated from a rotated-away log still has.
function opProvSec(span) {
  const ev = (span && span.evidence) || {};
  const eids = span ? [span.start_event_id, span.end_event_id]
    .filter(x => x != null) : [];
  const rows = [];

  // The auto-failover episodes first: on a failover this IS the answer, and it
  // is the one part of the evidence that predates the operation.
  (ev.episodes || []).forEach(e => {
    if (!(e.ids || []).length) return;
    rows.push(`<div class="ldr-row" data-ids="${e.ids.join(',')}">
      <span><b>${escapeHtml(e.title || '')}</b>
        <div class="muted" style="font-size:11px">${
          escapeHtml(e.detail || '')}</div>
        <div class="svc-note">click to pin these ${e.ids.length} lines</div>
      </span></div>`);
  });

  if ((ev.ids || []).length) {
    // A cap that is not stated reads as "that was all of them".
    const cap = ev.truncated
      ? ` <span class="muted">(first ${ev.ids.length} of ${ev.total})</span>`
      : '';
    rows.push(`<div class="ldr-row" data-ids="${ev.ids.join(',')}">
      <span>all ${ev.total} log line${ev.total > 1 ? 's' : ''} written by the
        modules that ran this operation${cap}</span></div>`);
    (ev.modules || []).forEach(m => {
      rows.push(`<div class="ldr-row" data-ids="${m.ids.join(',')}">
        <span>${escapeHtml(m.module)} — ${m.count} line${
          m.count > 1 ? 's' : ''}${m.count > m.ids.length
          ? ` <span class="muted">(first ${m.ids.length})</span>` : ''}
        </span></div>`);
    });
  }

  if (eids.length) {
    rows.push(`<div class="ldr-row" data-ids="${eids.join(',')}">
      <span class="muted">${eids.length > 1
        ? 'the 2 event log entries that bracket this operation'
        : 'the single event log entry this operation is dated from'}</span>
      </div>`);
  }
  if (!rows.length) return '';
  return `<div class="svc-sec"><h4>Log lines behind this operation</h4>${
    rows.join('')}</div>`;
}

function bindOpEventLinks() {
  $('opbody').querySelectorAll('[data-ids]').forEach(el => {
    el.onclick = () => {
      const ids = (el.dataset.ids || '').split(',').filter(Boolean)
        .map(x => parseInt(x, 10));
      if (!ids.length) return;
      range = {start: null, end: null};
      syncRangeInputs();
      pinned = ids;
      hideOperation();
      refresh();
    };
  });
}

// The drawer key is the operation_id when the events carried one, and a
// synthetic per-span key when they did not (see opKey). Only a real
// operation_id can join to a report; a span without one still has its nodes,
// its reasons and its log lines, which is most of what the drawer is for.
async function showOperation(key, span) {
  if (!key) return;
  opOpen = key;
  const oid = (span && (span.attrs || {}).operation_id) || '';
  const d = oid ? await getJSON('/api/operation?id=' + qsv(oid))
    : {found: false};
  $('oppanel').style.display = 'flex';
  const kind = ((span && span.kind) || 'operation').replace(/_/g, ' ');
  $('opname').textContent = kind;
  const body = $('opbody');

  // Only 5 reports are retained, so a span with none is the expected case for
  // anything older -- say which, rather than rendering an empty drawer that
  // reads like "nothing happened".
  //
  // The failover section and the link to the event lines come from the SPAN, not
  // the report, so both are rendered here too. A retained report is the usual
  // casualty of an auto-failover being old, and the drawer used to dead-end on
  // it -- taking the nodes, the per-node reason and the route to the log lines
  // down with it, none of which ever needed the report.
  if (!d.found) {
    $('opsub').textContent = span ? (span.outcome || '') : '';
    // Two different absences, said differently: no operation_id on the events at
    // all (nothing to join a report BY), versus an id whose report is not in the
    // capture.
    const why = oid
      ? `No rebalance report for this operation.
      ns_server retains only the 5 most recent reports, and writes each one to
      the first node it keeps rather than to the orchestrator — so an older
      operation, or one whose holding node is not in this capture, has none.`
      : `These event log entries carry no operation_id, so there is no key to
      join a rebalance report by. The nodes, the reasons and the log lines above
      do not need one.`;
    body.innerHTML = opFailoverSec(span) + opProvSec(span)
      + `<div class="svc-sec"><div class="muted"
      style="font-size:11px">${why}</div></div>`;
    bindOpEventLinks();
    return;
  }

  const r = d.report, m = d.moves || {};
  const stuck = m.in_flight || 0;
  $('opsub').textContent = [r.outcome,
    stuck ? `${stuck} move${stuck > 1 ? 's' : ''} never completed` : ''
  ].filter(Boolean).join(' · ');
  $('opsub').style.color = stuck ? '#ff4d4f' : '';
  $('opsub').style.fontWeight = stuck ? '600' : '';

  // 1. What this operation was. eject/delta/failed come straight from the
  // start_rebalance params and are real. active_nodes is deliberately absent:
  // ns_server builds it as keep ++ eject, a synthetic union, so showing it as
  // pre-operation membership would be wrong.
  const kv = [];
  const push = (k, v) => { if (v) kv.push(`<dt>${k}</dt><dd>${v}</dd>`); };
  push('started', fmtAt(r.start_ts));
  push('ended', r.completed_ts ? fmtAt(r.completed_ts)
    : '<span class="op-stuck">still running when the report was written</span>');
  push('took', r.time_taken_ms != null ? fmtDur2(r.time_taken_ms / 1000) : '');
  push('master', escapeHtml(ldrShort(r.master_node || '')));
  push('ejecting', escapeHtml(opNodes(r.eject_nodes)));
  push('delta recovery', escapeHtml(opNodes(r.delta_nodes)));
  push('failed nodes', escapeHtml(opNodes(r.failed_nodes)));
  push('failing over', escapeHtml(opNodes(r.failover_nodes)));
  // The real membership delta needs a before/after active_nodes() snapshot,
  // which ns_server only started recording on master (MB-70003). On a released
  // build the fields are absent and node ADDITIONS cannot be derived from
  // anything in the report, so those rows are simply omitted rather than
  // inferred -- an absent row is already "not recorded".
  if (r.has_delta_fields) {
    push('type', escapeHtml(r.rebalance_type || ''));
    push('nodes added', escapeHtml(opNodes(r.nodes_added)));
    push('nodes removed', escapeHtml(opNodes(r.nodes_removed)));
  }

  const msg = r.completion_message
    ? `<div class="svc-sec"><h4>Recorded outcome</h4>
       <div class="op-msg">${escapeHtml(r.completion_message)}</div></div>` : '';

  // 2. Where the time went, per service. stageInfo is per service, so this is
  // answerable before opening a single vbucket.
  const svc = Object.entries(r.services || {})
    .sort((a, b) => (b[1].time_taken_ms || 0) - (a[1].time_taken_ms || 0));
  const svcRows = svc.map(([name, s]) => `<tr>
      <td>${escapeHtml(name)}</td>
      <td class="n">${s.time_taken_ms != null
        ? fmtDur2(s.time_taken_ms / 1000) : '—'}</td>
      <td class="${s.state === 'in_flight' ? 'stuck' : ''}">${
        s.state === 'in_flight' ? 'never completed' : (s.state || '')}</td>
    </tr>`).join('');
  const svcSec = svcRows ? `<div class="svc-sec"><h4>Time per service</h4>
    <table class="op-tbl"><tr><th>service</th><th>took</th><th>state</th></tr>
    ${svcRows}</table></div>` : '';

  // 3. Where it stopped. The counts come from ns_server's own three-state
  // phase encoding: a phase with a start stamp and no completion was entered
  // and never left. Phase names are whatever the report carried, so one added
  // upstream shows up here on its own.
  const phaseRows = Object.entries(d.phases || {})
    .sort((a, b) => (b[1].in_flight || 0) - (a[1].in_flight || 0))
    .map(([name, c]) => `<tr>
      <td>${escapeHtml(name)}</td>
      <td class="n">${c.done || 0}</td>
      <td class="n ${c.in_flight ? 'stuck' : ''}">${c.in_flight || 0}</td>
      <td class="n">${c.not_started || 0}</td></tr>`).join('');
  const phaseSec = phaseRows ? `<div class="svc-sec">
    <h4>Move phases (${(m.done || 0) + stuck + (m.not_started || 0)} moves)</h4>
    <table class="op-tbl">
      <tr><th>phase</th><th>completed</th><th>entered, never
        completed</th><th>never entered</th></tr>${phaseRows}</table></div>`
    : `<div class="svc-sec"><div class="muted" style="font-size:11px">
       This report records no vbucket moves — the operation moved no data
       (a report can exist with an empty move set).</div></div>`;

  // The stalled moves themselves. vbucket, the phase(s) it sat in, when it
  // entered, where it was going, and how much replication was left: four
  // recorded fields per row, no verdict attached to any of them.
  const stalledRows = (d.stalled || []).map(s => {
    const docs = s.docs_total
      ? `${s.docs_left == null ? '?' : s.docs_left} / ${s.docs_total}` : '—';
    return `<tr>
      <td>${s.vbucket}</td>
      <td>${escapeHtml(s.bucket || '')}</td>
      <td class="stuck">${escapeHtml((s.stuck_phases || []).join('+'))}</td>
      <td>${s.stuck_since_ts ? fmtAt(s.stuck_since_ts) : '—'}</td>
      <td>${escapeHtml(opNodes(s.target_nodes))}</td>
      <td class="n">${docs}</td></tr>`;
  }).join('');
  // A cap that is not stated reads as "that was all of them".
  const capped = stuck > d.stalled_shown
    ? `<div class="muted" style="font-size:11px">showing ${d.stalled_shown}
       of ${stuck}</div>` : '';
  const stalledSec = stalledRows ? `<div class="svc-sec">
    <h4>Moves that never completed</h4><div class="op-scroll">
    <table class="op-tbl"><tr><th>vb</th><th>bucket</th><th>in phase</th>
      <th>since</th><th>to</th><th>docs left / total</th></tr>
    ${stalledRows}</table></div>${capped}</div>` : '';

  const neverSec = (m.not_started || 0) ? `<div class="svc-sec">
    <h4>Moves never started</h4><div class="muted" style="font-size:11px">${
      m.not_started} move(s): vb ${(d.not_started_sample || []).join(', ')}${
      m.not_started > (d.not_started_sample || []).length ? ' …' : ''}</div>
    </div>` : '';

  body.innerHTML = opFailoverSec(span)
    + `<div class="svc-sec"><dl class="op-kv">${kv.join('')}</dl>
    </div>${msg}${phaseSec}${stalledSec}${neverSec}${svcSec}${opProvSec(span)}
    <div class="svc-sec"><div class="muted" style="font-size:11px">
      from ${escapeHtml((r.log_path || '').split('/').pop())} (collected on ${
      escapeHtml(ldrShort(r.node || ''))})</div></div>`;

  bindOpEventLinks();
}

function hideOperation() { opOpen = null; $('oppanel').style.display = 'none'; }

// ---- cluster overview ----
// One lane per observer showing who THAT node believed held mastership. There is
// deliberately no single "the master" row: mb_master runs on every node and a
// candidate promotes itself after 10s of silence from higher-priority peers, so
// a partition legitimately produces two nodes in the master state at once. The
// view's job is to make the disagreement between lanes visible, not to resolve
// it. See cbtriage/leadership.py for where each belief line comes from.
let LDR = null;
// Holder colours are assigned by first appearance and reused across every lane,
// so the same colour always means the same node -- that is what makes two lanes
// disagreeing legible at a glance.
//
// Blues, purples, cyans, pinks and greys ONLY. Green, amber and red are reserved
// for outcomes and consensus states (completed / interrupted / failed, no master
// / split), and a shared hue there is not a near miss but a genuine ambiguity:
// the 4th identity colour used to be #ffc53d, the exact amber of "interrupted"
// and "no master", so on a 6-node cluster one node was drawn in the colour of a
// broken operation. Two greens (#73d13d against #52c41a) and orange next to red
// (#ff7a45 against #ff4d4f) had the same problem more softly.
const LDR_COLORS = ['#4ea1ff', '#b37feb', '#36cfc9', '#f759ab', '#597ef7',
                    '#bfbfbf', '#d3adf7', '#08979c'];
// Plain-language names for the consensus states. The panel is read at a glance,
// so the strip says "split" rather than making the reader decode two_masters.
const LDR_STATE = {
  agreed: 'agreed on one master',
  two_masters: 'split: nodes disagreed on who held it',
  no_master: 'no master: nobody believed anyone held it',
  partial: 'partial: some believed a master, others none',
  unknown: 'unknown: too few nodes had said anything yet',
};

function ldrColorMap(d) {
  const seen = [];
  for (const lane of d.lanes || []) {
    for (const s of lane.segments || []) {
      if (s.holder && !seen.includes(s.holder)) seen.push(s.holder);
    }
  }
  const map = {};
  seen.forEach((h, i) => { map[h] = LDR_COLORS[i % LDR_COLORS.length]; });
  return map;
}

// Short node label: the host half is what distinguishes nodes in a cluster, but
// ns_1@ is on every one of them, so it earns no pixels.
function ldrShort(n) { return (n || '').replace(/^ns_1@/, ''); }

// Fetch once, draw many times. The payload does not depend on the visible
// window -- the server derives the whole capture -- so zooming is a redraw, not
// another derivation.
async function showOverview() {
  if (!LDR) LDR = await getJSON('/api/overview');
  renderOverview();
}

function overviewOpen() { return stripOpen.overview !== false; }

// operation_id -> the span it came from, so the drawer can show the span's own
// facts (kind, outcome, event ids) next to the report's. Rebuilt each render.
let opSpans = {};

// Set by the "show all" tag: draw the whole extent of the evidence instead of
// the ingest window. Sticky until the strip is reset.
let ldrShowAll = false;

function renderOverview() {
  const all = LDR;
  if (!all) return;
  const d = all.leadership || {}, orch = all.orchestration || {};
  const body = $('ldrbody');
  opSpans = {};          // rebuilt below as the op blocks are drawn
  // One x-axis for both axes, from the server: each alone would misframe the
  // other, since an hour of elections and a rebalance on another day are both
  // real and neither should squash the other off the chart.
  const v = d.verdict || {};
  // The bands follow the timeline's window when one is set. Without this a
  // 1.4s rebalance on a 44-minute axis is a sliver no matter what, and the
  // span -- the whole point of drawing an operation as a rectangle -- cannot be
  // read.
  const zoomed = range.start != null && range.end != null
                 && range.end > range.start;
  // With no timeline window, the axis is the INGEST window rather than the raw
  // evidence extent, for the same reason the header pill is (db.query_meta):
  // event_log and diag.log are always-full sources, so their spans reach across
  // the whole collection and would frame the band on time the windowed sources
  // say nothing about. Anything overlapping an edge is still drawn, clipped at
  // the edge -- an operation running into the window is the window's business.
  const w = (META && META.info) || {};
  const wlo = ldrShowAll ? null : w.window_lo;
  const whi = ldrShowAll ? null : w.window_hi;
  let elo = all.span.lo, ehi = all.span.hi;
  if (elo != null && ehi != null) {
    const clo = wlo != null ? Math.max(elo, wlo) : elo;
    const chi = whi != null ? Math.min(ehi, whi) : ehi;
    // A window that excludes every piece of evidence would leave an empty axis;
    // the evidence extent is the honest fallback there.
    if (chi > clo) { elo = clo; ehi = chi; }
  }
  const windowed = !zoomed && (elo !== all.span.lo || ehi !== all.span.hi);
  const lo = zoomed ? range.start : elo;
  const hi = zoomed ? range.end : ehi;
  if (lo == null || hi == null
      || (!(d.lanes || []).length && !(orch.spans || []).length)) {
    body.innerHTML = '<div class="muted">Nothing to show: no mb_master or '
      + 'leader_registry announcements, and no rebalance or failover events. '
      + 'Neither can be reconstructed from a snapshot, only from these log '
      + 'records — the usual cause is a window no debug.log reaches back to.'
      + '</div>';
    return;
  }
  const span = Math.max(hi - lo, 0.001);
  const pct = (t) => ((Math.min(Math.max(t, lo), hi) - lo) / span) * 100;
  // Anything that overlaps the axis is drawn (clipped by pct); anything fully
  // outside it is dropped. Clamping those instead would pile them up as slivers
  // on the edges, which reads as activity right at the window boundary. An open
  // span (no end) is treated as running to the end of the axis, which is what
  // "no end recorded" means for the purpose of "is it on screen".
  const vis = (s, e) => (e == null ? hi : e) >= lo && (s == null ? hi : s) <= hi;
  const colors = ldrColorMap(d);
  // The operations on this axis. The header counts and the band are both built
  // from this one list, so a tag can never claim an operation the band does not
  // draw.
  const onAxis = (orch.spans || []).filter(s => vis(s.start, s.end));
  const offAxis = (orch.spans || []).length - onAxis.length;

  // Deliberately NOT summarised here: share of time in agreement, number of
  // splits, transitions, rival claims seen. Every one of those is a statistic
  // about churn that a live cluster produces constantly -- nodes joining and
  // leaving, brief partitions, rolling restarts -- so the number is never zero,
  // never means anything on its own, and reads as a score. The bands below show
  // the same thing in place, where it can be looked at rather than graded.
  const tags = [];
  // Operations lead the header, stated per kind and outcome: "7 rebalances: 7
  // completed" answers what ran, how it ended, and whether it kept re-running,
  // which is the whole question. Counts of recorded outcomes -- no grade. Kept
  // per kind even though the band collapses the failovers onto one row: "2 auto
  // failovers" and "2 graceful failovers" are different sentences.
  const byKind = {};
  for (const s of onAxis) {
    const o = byKind[s.kind] || (byKind[s.kind] = {});
    o[s.outcome] = (o[s.outcome] || 0) + 1;
  }
  for (const [kind, outcomes] of Object.entries(byKind)) {
    const n = Object.values(outcomes).reduce((a, b) => a + b, 0);
    const parts = Object.entries(outcomes)
      .map(([o, c]) => `${c} ${o === 'unfinished' ? 'no end recorded' : o}`);
    const bad = Object.keys(outcomes).some(o => o !== 'completed');
    tags.unshift(`<span class="ldr-tag ${bad ? 'bad' : ''}">${n} ${
      escapeHtml(kind.replace(/_/g, ' '))}${n > 1 ? 's' : ''}: ${
      escapeHtml(parts.join(', '))}</span>`);
  }
  // The axis is narrower than the evidence, and something was left off it. Say
  // how much, and offer the whole extent in one click -- a hidden operation the
  // reader is not told about is the one thing this band must not do.
  if (windowed && offAxis) {
    tags.push(`<span class="ldr-tag" id="ldrshowall" style="cursor:pointer"
      title="The bands cover the ingest window. event_log and diag.log are read
 in full regardless of the window, so they carry operations from outside it;
 those are not drawn here. Click to widen the axis to all the evidence.">${
      offAxis} operation${offAxis > 1 ? 's' : ''} outside the window — show all`
      + `</span>`);
  }
  if (ldrShowAll && (w.window_lo != null || w.window_hi != null)) {
    tags.push(`<span class="ldr-tag" id="ldrwindowback" style="cursor:pointer"
      title="Showing every operation the always-full sources carry, including
 ones from outside the ingest window. Click to go back to the window."
      >all evidence — back to the window</span>`);
  }
  if (zoomed) {
    tags.push(`<span class="ldr-tag" id="ldrunzoom" style="cursor:pointer"
      title="The bands are following the timeline window. Click to go back to
 the full extent of the evidence.">zoomed to ${fmtDur2(hi - lo)} — show all`
      + `</span>`);
  }
  const cs = all.capture_span || {};
  if (cs.lo != null && cs.hi != null && (cs.hi - cs.lo) > span * 1.5) {
    tags.push(`<span class="ldr-tag" title="Outside this range no node logged `
      + `anything about mastership, so nothing is known about it — the chart `
      + `covers the evidence, not the capture.">covering ${fmtDur2(span)} of a ${
      fmtDur2(cs.hi - cs.lo)} capture</span>`);
  }
  // A lane with no evidence is not a lane that agreed; say so, or the picture
  // reads as more unanimous than the logs support.
  if ((v.silent_observers || []).length) {
    tags.push(`<span class="ldr-tag warn">silent: ${
      v.silent_observers.map(ldrShort).join(', ')}</span>`);
  }

  // The date is stated once, on the left edge; the rest are clock times, which
  // is what a reader compares between lanes.
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f, i, a) => {
    const t = fmtAt(lo + f * span);
    const cls = i === 0 ? ' class="first"' : (i === a.length - 1 ? ' class="last"' : '');
    return `<span${cls} style="left:${f * 100}%">${
      i === 0 ? t : t.slice(11)}</span>`;
  }).join('');

  const lanes = (d.lanes || []).map(lane => {
    const shown = (lane.segments || []).filter(s => vis(s.start, s.end));
    const segs = shown.map(s => {
      const left = pct(s.start), w = Math.max(pct(s.end) - left, 0.15);
      const self = s.holder && s.holder === lane.observer ? ' self' : '';
      const cls = s.holder ? 'ldr-seg' + self : 'ldr-seg none';
      const bg = s.holder ? `background:${colors[s.holder]};` : '';
      const label = w > 6 ? escapeHtml(s.holder ? ldrShort(s.holder)
                                                : 'no master') : '';
      const exp = s.expected_holder
        ? `, expected ${ldrShort(s.expected_holder)} to take over` : '';
      const title = `${lane.observer} believed ${s.holder || 'there was no master'}`
        + `\n${fmtAt(s.start)} -> ${fmtAt(s.end)}`
        + `\nreason: ${s.reason}${exp}`
        + `\nattested by: ${(s.subsystems || []).join(', ')}`
        + `\n${s.summary || ''}`;
      return `<div class="${cls}" style="left:${left}%;width:${w}%;${bg}"
        data-ids="${(s.evidence || []).join(',')}" data-at="${s.start}"
        title="${escapeHtml(title)}">${label}</div>`;
    }).join('');
    const confs = (d.conflicts || [])
      .filter(c => c.observer === lane.observer && vis(c.ts_epoch, c.ts_epoch))
      .map(c => `<div class="ldr-conf" style="left:${pct(c.ts_epoch)}%"
        data-ids="${c.event_id}"
        title="${escapeHtml(`${c.kind}${c.peer ? ' (' + c.peer + ')' : ''}\n`
          + fmtAt(c.ts_epoch) + '\n' + (c.summary || ''))}"></div>`).join('');
    // First evidence ON THIS AXIS, not the span start: before it, this node's
    // belief is unknown and must not be painted as anything. Taken from the
    // visible segments, so a lane whose only evidence lies outside the window
    // reads as unknown here rather than as an empty (agreeing) row.
    const first = shown[0];
    const gap = !first
      // A node that announced nothing at all: the lane has to look unknown for
      // its whole length, or an empty row reads as a node that agreed.
      ? `<div class="ldr-seg unknown" style="left:0;width:100%"
          title="no mb_master or leader_registry line from ${
          escapeHtml(lane.observer)} in this window — unknown throughout, not
 agreement">unknown</div>`
      : (first.start > lo
        ? `<div class="ldr-seg unknown thin" style="left:0;width:${pct(first.start)}%"
            title="no belief line from ${escapeHtml(lane.observer)} before ${
            escapeHtml(fmtAt(first.start))} — unknown, not agreement"></div>`
        : '');
    const only = (lane.subsystems || []).length === 1
      ? ` <span class="muted" title="attested by ${lane.subsystems[0]
          } only">·${lane.subsystems[0] === 'mb_master' ? 'mb' : 'reg'}</span>`
      : '';
    return `<div class="ldr-lane"><div class="ldr-name">${
      escapeHtml(ldrShort(lane.observer))}${only}</div>
      <div class="ldr-track">${gap}${segs}${confs}</div></div>`;
  }).join('');

  // The cluster strip: one row answering "did they agree" at every instant,
  // above the per-node rows that answer "and if not, who thought what". Reading
  // it top-down is the whole point of the panel -- find the red, then look down
  // the column to see which nodes were on which side.
  const strip = (d.consensus || []).filter(c => vis(c.start, c.end)).map(c => {
    const left = pct(c.start), w = Math.max(pct(c.end) - left, 0.15);
    const label = w > 8 && c.kind === 'agreed' && c.holder
      ? escapeHtml(ldrShort(c.holder)) : '';
    const bg = c.kind === 'agreed' && c.holder
      ? `background:${colors[c.holder]};` : '';
    const views = Object.entries(c.views || {})
      .map(([o, h]) => `  ${ldrShort(o)} -> ${h ? ldrShort(h) : 'no master'}`)
      .join('\n');
    const title = `${LDR_STATE[c.kind] || c.kind}`
      + `\n${fmtAt(c.start)} -> ${fmtAt(c.end)} (${fmtDur2(c.duration_s)})`
      + (views ? `\n${views}` : '');
    return `<div class="ldr-cons ${c.kind}" style="left:${left}%;width:${w}%;${bg}"
      data-at="${c.start}" data-end="${c.end}"
      title="${escapeHtml(title)}">${label}</div>`;
  }).join('');

  // Operations band: one row per operation FAMILY present, so a rebalance and a
  // failover overlapping stay legible instead of stacking on one row. An
  // operation is a cluster-scoped span with an owner and an outcome, which is a
  // different shape of fact from a per-node belief -- hence its own band rather
  // than marks on the lanes.
  //
  // The three failover kinds share one row: which of graceful, hard or auto ran
  // is a property of the individual operation, not of a separate axis, and three
  // near-empty rows cost vertical space that the per-node lanes need. The kind
  // is on every block's hover, and the header tags still count them separately.
  const opRow = (kind) => (/failover$/.test(kind) ? 'failover' : kind);
  // Only operations on this axis get a row: an axis-wide row for an operation
  // that ran on another day is an empty track that reads as "none happened".
  const rowKinds = [];
  for (const s of onAxis) {
    const row = opRow(s.kind);
    if (!rowKinds.includes(row)) rowKinds.push(row);
  }
  const opRows = rowKinds.map(kind => {
    const spans = onAxis.filter(s => opRow(s.kind) === kind);
    const blocks = spans.map(s => {
      const endAt = s.end == null ? hi : s.end;
      const left = pct(s.start == null ? endAt : s.start);
      const trueW = pct(endAt) - left;
      const w = Math.max(trueW, 0.4);
      // The span is the information -- how long the operation took -- so it is
      // always drawn as one. Below the CSS floor the drawn width is the floor
      // rather than the duration; that block gets the dashed "not to scale"
      // outline and its real duration is in the hover as usual. Zooming the
      // window (a strip or episode click, or the from/to boxes) redraws to
      // scale.
      const floored = trueW < 0.8;
      const owner = ldrShort(s.owner || '');
      // On a failover the question is which node LEFT, not which node drove it,
      // so the block is labelled with the failed-over nodes and the driver moves
      // to the hover. A rebalance keeps the owner: it has no such node.
      // Past two nodes the names stop fitting a block, so the label counts the
      // rest rather than being clipped mid-name. The hover lists every one.
      const fo = foNodes(s);
      const labelText = !fo.length ? owner
        : (fo.length <= 2 ? fo.map(ldrShort).join(', ')
          : `${ldrShort(fo[0])} +${fo.length - 1}`);
      const label = w > 7 ? escapeHtml(labelText) : '';
      // s.kind, not the row's: on the shared failover row the hover is the only
      // place that says whether this one was graceful, hard or auto.
      const bits = [`${s.kind.replace(/_/g, ' ')} — ${s.outcome}`,
                    `${fmtAt(s.start == null ? endAt : s.start)} -> ${
                      s.end == null ? 'no end recorded' : fmtAt(s.end)}`];
      if (s.duration_s != null) bits.push(`took ${fmtDur2(s.duration_s)}`);
      // Which nodes, and the reason recorded for each one, on its own line. The
      // per-node reason used to be flattened into the attribute blob below and
      // clipped there -- it is the first thing a failover read needs.
      bits.push(...foLines(s));
      bits.push(`driven by ${owner || 'unknown node'}`);
      if (s.reason) bits.push(`reason: ${s.reason}`);
      if (s.start_unknown) {
        bits.push('start is not in the event_log ring, so only the end is dated');
      }
      if (s.start_text) bits.push(s.start_text);
      const cls = ['ldr-op', s.outcome, floored ? 'floored' : '',
                   s.start_unknown ? 'nostart' : ''].filter(Boolean).join(' ');
      // Every block opens the drawer, with or without an operation_id: the
      // drawer is where the operation's log lines are, and those never needed
      // the id (see opKey).
      //
      // Failovers get a report too: ns_orchestrator starts an
      // ns_rebalance_observer for the failover under the same operation id and
      // records its report the same way, which is why the parser handles
      // failover_nodes. ns_server files them all as "rebalance reports"; the
      // hover says "report" so a failover block does not offer a rebalance one.
      const key = opKey(s);
      opSpans[key] = s;
      const ev = s.evidence || {};
      bits.push((s.attrs || {}).operation_id
        ? "click for this operation's report and its log lines"
        : "click for this operation's log lines");
      if (ev.total) {
        bits.push(`${ev.total} log line${ev.total > 1 ? 's' : ''} from the `
          + `modules that ran it`);
      }
      return `<div class="${cls}" style="left:${left}%;width:${w}%"
        data-op="${escapeHtml(key)}"
        title="${escapeHtml(bits.join('\n'))}">${label}</div>`;
    }).join('');
    return `<div class="ldr-lane op"><div class="ldr-name">${
      escapeHtml(kind.replace(/_/g, ' '))}</div>
      <div class="ldr-track">${blocks}</div></div>`;
  }).join('');

  // Operations are coloured by outcome, nodes by identity, so the two halves of
  // the legend are kept apart -- one colour scheme per question.
  const opLegend = !onAxis.length ? '' :
    '<div class="ldr-legend"><span class="muted">operations:</span>'
    + '<span><i class="ldr-sw" style="background:var(--info)"></i>completed</span>'
    + '<span><i class="ldr-sw" style="background:var(--crit)"></i>failed</span>'
    + '<span><i class="ldr-sw" style="background:var(--warn)"></i>interrupted</span>'
    + '<span><i class="ldr-sw" style="background:repeating-linear-gradient('
    + '45deg,#b37feb 0 3px,#6b3fa0 3px 6px)"></i>no end recorded</span>'
    + '<span title="Too short to draw to scale at this zoom: the block is at its '
    + 'minimum width, and the hover states the real duration. Zoom in and it is '
    + 'drawn to scale."><i class="ldr-sw" style="border:1px dashed #ffffffaa;'
    + 'background:#3a4252"></i>not to scale</span>'
    + '<span class="muted" title="a failover is labelled with the nodes it '
    + 'failed over, since that is what the operation did; the node that drove '
    + 'it, and the reason recorded per failed-over node, are in the hover">'
    + 'failovers labelled with the nodes failed over, rebalances with the node '
    + 'that drove it</span>'
    + '<span class="muted" title="the drawer carries what the event log cannot: '
    + 'the report where one is retained, and the lines the operation\'s own '
    + 'modules wrote">click an operation for its detail and its log lines'
    + '</span></div>';

  const uncoll = new Set(d.uncollected_holders || []);
  // A pre-rename name is a node initialising, not a missing capture. Saying so
  // keeps the early flurry of transitions through it from reading as an
  // election, and stops anyone hunting for a cbcollect that cannot exist.
  const boot = new Set(d.bootstrap_holders || []);
  const legend = Object.keys(colors).map(h => {
    const note = boot.has(h) ? ' (node initialising)'
      : (uncoll.has(h) ? ' (not collected)' : '');
    const why = boot.has(h)
      ? ' title="the name every node carries before it is renamed to its real '
        + 'one, so this is a node still bootstrapping rather than a separate '
        + 'node"'
      : (uncoll.has(h) ? ' title="named as the master by other nodes, but its '
        + 'own cbcollect is not in this bundle, so it has no lane"' : '');
    return `<span${why}><i class="ldr-sw" style="background:${colors[h]}"></i>${
      escapeHtml(ldrShort(h))}${note}</span>`;
  }).join('')
    + '<span><i class="ldr-sw" style="background:repeating-linear-gradient('
    + '45deg,#2a2f3a 0 3px,#1a1e26 3px 6px)"></i>no master believed</span>'
    + '<span><i class="ldr-sw" style="background:repeating-linear-gradient('
    + '90deg,#20242d 0 2px,transparent 2px 6px)"></i>unknown (no line)</span>'
    + '<span style="border:2px solid #fff8;padding:0 4px;border-radius:2px">'
    + 'believed itself master</span>'
    + `<span><i class="ldr-sw" style="background:var(--crit)"></i>split: nodes `
    + `disagreed</span>`
    + `<span class="muted">hover anything for detail; click to take the timeline `
    + `there</span>`;

  // Operations that did not end cleanly, and nothing else. Each row is what
  // ns_server recorded: the outcome and its reason. An operation that completed
  // is not listed, and neither is one that merely overlapped a divergence
  // window -- selecting on that would be a judgement that a clean rebalance
  // needs attention because the cluster briefly disagreed, which is the
  // inevitable made to look like an incident. The overlap is still marked on the
  // block and counted in the header, where it is a count rather than a verdict.
  const rough = onAxis.filter(s => s.outcome !== 'completed');
  const opList = !onAxis.length ? '' : (rough.length
    ? `<div class="svc-sec"><h4>Operations that did not complete</h4>`
      + rough.map(s => {
          const owner = ldrShort(s.owner || '') || 'unknown node';
          const rkey = opKey(s);
          opSpans[rkey] = s;
          return `<div class="ldr-row" data-op="${escapeHtml(rkey)}">
            <span class="t">${fmtAt(s.start == null ? s.end : s.start)}</span>
            <span><b class="ldr-bad">${escapeHtml(s.kind.replace(/_/g, ' '))} ${
              escapeHtml(s.outcome)}</b>${
              s.duration_s != null ? ` after ${fmtDur2(s.duration_s)}` : ''
              } — driven by ${escapeHtml(owner)}${
              s.reason ? `<div class="muted" style="font-size:11px">${
                escapeHtml(s.reason)}</div>` : ''}</span></div>`;
        }).join('') + '</div>'
    : `<div class="svc-sec"><div class="muted" style="font-size:11px">all ${
        onAxis.length} operation${onAxis.length > 1 ? 's' : ''} `
      + `completed</div></div>`);


  body.innerHTML = `<div class="ldr-verdict">${tags.join('')}</div>
    <div class="ldr-chart">
      <div class="ldr-axis">${ticks}</div>
      ${opRows}
      <div class="ldr-lane cluster"><div class="ldr-name">believed master</div>
        <div class="ldr-track">${strip}</div></div>
      ${lanes}
    </div>
    ${opLegend}
    <div class="ldr-legend">${legend}</div>
    ${opList}`;

  // The rival-claim lines are no longer listed here (they are log text, and the
  // lanes are the point of the panel), so the count itself is the way to reach
  // them: it pins every one of them in the timeline.
  if ($('ldrunzoom')) {
    $('ldrunzoom').onclick = () => {
      range = {start: null, end: null};
      syncRangeInputs();
      refresh();
    };
  }
  if ($('ldrshowall')) {
    $('ldrshowall').onclick = () => { ldrShowAll = true; renderOverview(); };
  }
  if ($('ldrwindowback')) {
    $('ldrwindowback').onclick = () => { ldrShowAll = false; renderOverview(); };
  }
  setOverviewHover('');
  wireOverviewHover();

  body.querySelectorAll('[data-ids],[data-at],[data-op]').forEach(el => {
    el.onclick = () => {
      // An operation with a report opens the report: it answers what the
      // operation was and where it stopped, which the event lines alone do not.
      // The drawer still links through to those lines.
      if (el.dataset.op) {
        return showOperation(el.dataset.op, opSpans[el.dataset.op]);
      }
      const ids = (el.dataset.ids || '').split(',').filter(Boolean)
        .map(x => parseInt(x, 10));
      const at = parseFloat(el.dataset.at || '');
      const end = parseFloat(el.dataset.end || '');
      // An episode opens as a window (what everyone was doing while the cluster
      // disagreed); a single line opens pinned (that exact line).
      if (Number.isFinite(at) && Number.isFinite(end)) {
        pinned = null;
        range.start = at - AROUND_S;
        range.end = end + AROUND_S;
        syncRangeInputs();
      } else if (ids.length) {
        range = {start: null, end: null};
        syncRangeInputs();
        pinned = ids;
      } else if (Number.isFinite(at)) {
        pinned = null;
        range.start = at - AROUND_S;
        range.end = at + AROUND_S;
        syncRangeInputs();
      }
      refresh();
    };
  });
}

// Seconds with sub-minute precision, which fmtDur (minutes-and-up) throws away:
// an election is decided in ten seconds, so a 4s window and a 40s window are
// different findings.
function fmtDur2(secs) {
  if (secs == null) return '—';
  if (secs < 90) return secs.toFixed(secs < 10 ? 2 : 1) + 's';
  return fmtDur(secs);
}

function hideSnapshots() {
  $('snappanel').style.display = 'none';
  $('snapbtn').classList.remove('primary');
}

// Live readout of whatever the pointer is over, in the subtitle row under the
// heading. The bands carry their detail in a title attribute, but an operation
// twelve pixels wide is not a realistic tooltip target, so the same text is
// surfaced here the moment the pointer crosses it. Delegated, so it survives
// every re-render.
//
// It takes over the row from the strip's description rather than being given a
// row of its own: the space is then reserved whether or not anything is
// hovered, so crossing a band cannot move the table underneath (see .ldr-sub).
function setOverviewHover(text) {
  const out = $('ldrhover'), desc = $('ldrdesc');
  if (!out) return;
  out.textContent = text;
  if (desc) desc.hidden = !!text;
}
function wireOverviewHover() {
  const body = $('ldrbody');
  if (!body || !$('ldrhover')) return;
  body.onmousemove = (e) => {
    const el = e.target.closest('[title]');
    if (!el || !body.contains(el)) { setOverviewHover(''); return; }
    setOverviewHover((el.getAttribute('title') || '')
      .split('\n').map(s => s.trim()).filter(Boolean).join('  ·  '));
  };
  body.onmouseleave = () => { setOverviewHover(''); };
}
// Coalesce keystrokes into one request; the trailing call always runs, so the
// final state of the box is what gets queried.
function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// ---- pressure strip ----
// Coarse (~1/min) resource-pressure verdict for the CURRENT window, from the
// ns_doctor heartbeat in stats.log. Scoped by the same node/time filters as the
// timeline (qstring), so brushing/zooming the histogram re-scopes it too.
// Thresholds mirror findings._PRESSURE_WARN. This is the yes/no — open promtimer
// for the full-resolution series.
const PWARN = {io:20, memory:10, cpu:50, cpu_stolen:5};
const PLABEL = {io:'io', memory:'mem', cpu:'cpu', cpu_stolen:'steal'};
async function renderPressure() {
  const el = $('pressure');
  let p;
  try { p = await getJSON('/api/pressure?'+qstring()); } catch(e) { el.innerHTML=''; return; }
  // The strip header carries the label and the explanation now, so the body is
  // just the numbers.
  const hdr = '';
  if (!p.available) {
    el.innerHTML = hdr + '<span class="muted">no PSI/allocstall in stats.log for '
      + 'this capture (pre-7.2.4 or non-Linux) — pressure can’t be ruled in or out</span>';
    return;
  }
  if (!p.in_window) {
    el.innerHTML = hdr + `<span class="muted">no samples in this window `
      + `(${p.total_samples} in capture)</span>`;
    return;
  }
  const chips = p.nodes.map(n => {
    const parts = [];
    for (const key of ['io','memory','cpu','cpu_stolen']) {
      const m = n.metrics[key];
      if (!m) continue;
      const hot = m.peak >= PWARN[key] ? ' hot' : '';
      parts.push(`<span class="pm${hot}">${PLABEL[key]} ${m.peak.toFixed(1)}%</span>`);
    }
    const a = n.metrics.allocstall;
    if (a && a.delta > 0) parts.push(`<span class="pm hot">allocstall +${Math.round(a.delta)}</span>`);
    return `<span class="pnode"><b>${n.node}</b>${parts.join(' ')}</span>`;
  }).join('');
  // PSI qualifies what the chips mean: with PSI captured a quiet strip is
  // measured-and-clean; without it, absent io/mem/cpu pressure just means never
  // measured (only steal/allocstall were available). Shown only here, where
  // chips render, so it accurately describes the visible window.
  const psi = p.psi_available
    ? '<span class="pm" title="Kernel PSI (io/mem/cpu) was captured this window, '
      + 'so absent io/mem/cpu pressure is measured-and-clean.">PSI: available</span>'
    : '<span class="pm hot" title="Kernel PSI (io/mem/cpu) was NOT captured this '
      + 'window (old kernel / non-Linux / not exported) — absent io/mem/cpu '
      + 'pressure means never measured, not healthy. Only CPU steal and allocstall '
      + 'were available.">PSI: not captured</span>';
  el.innerHTML = hdr + psi + chips;
}

// ---- refresh ----
// ---- process-dump explorer ----
// Per-process grab_process_info dumps from diag.log (collection snapshot) and
// timeout_diag_logger (incident-time). Same table for both; pick a dump, sort
// by mailbox/memory/reductions, or click a process name to pivot to that
// process across every dump (a mini time-series when timeout dumps exist).
let PROC_DUMPS = [];
function fmtBytes(n) {
  if (n == null) return '';
  const u = ['B','K','M','G','T']; let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i ? v.toFixed(1) : v) + u[i];
}
async function loadProcDumps() {
  PROC_DUMPS = await getJSON('/api/process_dumps');
  const sel = $('procdump');
  if (!PROC_DUMPS.length) {
    sel.innerHTML = '<option>(no process dumps in capture)</option>';
    $('procrows').innerHTML = ''; $('procinfo').textContent = '';
    return;
  }
  sel.innerHTML = PROC_DUMPS.map((d, i) => {
    const t = d.source === 'diag' ? 'collection snapshot'
                                  : fmtTime(d.capture_ts, d.tz_offset_min);
    return `<option value="${i}">${escapeHtml(d.node)} · ${d.source} · ${t}`
         + ` — ${d.n} procs</option>`;
  }).join('');
  $('procname').value = $('procloc').value = $('procmq').value = '';
  renderProcDump();
}
async function renderProcDump() {
  if (!PROC_DUMPS.length) return;
  // One dump at a time. name/location are substring filters and min queue a
  // threshold; all three narrow the selected dump and leave the sort applied.
  const d = PROC_DUMPS[+$('procdump').value || 0];
  const name = $('procname').value.trim();
  const loc = $('procloc').value.trim();
  const minmq = $('procmq').value.trim();
  const url = '/api/process_dump?node=' + encodeURIComponent(d.node)
      + '&source=' + encodeURIComponent(d.source)
      + (d.capture_ts != null ? '&capture_ts=' + d.capture_ts : '')
      + (name ? '&name=' + encodeURIComponent(name) : '')
      + (loc ? '&location=' + encodeURIComponent(loc) : '')
      + (minmq ? '&min_mq=' + encodeURIComponent(minmq) : '')
      + '&order=' + encodeURIComponent($('procsort').value);
  const rows = await getJSON(url);
  const filtered = name || loc || minmq;
  $('procinfo').textContent = `${rows.length} shown`
      + (filtered ? ` of ${d.n} processes` : ` — ${d.n} processes`);
  renderProcRows(rows);
}
function renderProcRows(rows) {
  const tb = $('procrows');
  tb.innerHTML = rows.map((r, i) => {
    return `<tr class="proc" data-i="${i}">
      <td>${escapeHtml(r.name||'')}</td>
      <td class="mono">${escapeHtml(r.pid||'')}</td>
      <td>${escapeHtml(r.status||'')}</td>
      <td class="num mq">${r.message_queue_len!=null?r.message_queue_len:''}</td>
      <td class="num">${fmtBytes(r.memory)}</td>
      <td class="num">${r.reductions!=null?r.reductions.toLocaleString():''}</td>
      <td class="mono">${escapeHtml(r.current_location||'')}</td>
    </tr>`;
  }).join('');
  tb.querySelectorAll('tr.proc').forEach(tr => {
    tr.onclick = (e) => {
      const ex = tr.nextElementSibling;
      if (ex && ex.classList.contains('pdraw')) { ex.remove(); return; }
      const r = rows[+tr.dataset.i];
      const td = document.createElement('tr');
      td.className = 'pdraw';
      td.innerHTML = `<td colspan="7"><pre class="raw">${escapeHtml(r.raw||'')}</pre></td>`;
      tr.after(td);
    };
  });
}

// ---- collection-time snapshot view ----
// couchbase.log one-shots: a single since-boot reading, window-independent.
// Two tabs share the panel: the System & cgroup fact cards (below) and the
// existing process-dump explorer.
let SNAP_BY_NODE = null;   // {node: {metric: row}}, cached across node switches
function snapTab(which) {
  const facts = which === 'facts';
  $('snapfacts').style.display = facts ? 'grid' : 'none';
  $('snapproc').style.display = facts ? 'none' : 'block';
  $('snapnodewrap').style.display = facts ? 'flex' : 'none';
  $('snaptab-facts').classList.toggle('active', facts);
  $('snaptab-proc').classList.toggle('active', !facts);
  if (facts) loadSnapshot(); else loadProcDumps();
}

// One card definition = a title + the metrics it pulls, with an optional
// formatter and a hotness test (warn/crit tint). Kept declarative so a new
// couchbase.log one-shot is a few lines, not new layout code.
const SNAP_BYTES = v => fmtBytes(v) + 'B';
const SNAP_PCT = v => (+v).toFixed(v < 10 ? 2 : 1) + '%';
const SNAP_INT = v => (+v).toLocaleString();
const SNAP_SEC = v => (v / 1e6).toFixed(1) + 's';   // usec -> human seconds
const SNAP_KB = v => fmtBytes(v * 1024) + 'B';      // a kbytes sysctl, shown human
// Cards with no single-scope source line worth footnoting (host-wide facts,
// or facts folded together from more than one one-shot command).
const SNAP_NO_FOOT = new Set(['reclaim', 'platform']);
// Mirrors cbsections.NO_OUTPUT_NOTE. cbcollect_info writes a section's header
// before running the command and sends the command's errors to the collection
// log rather than into couchbase.log, so a source it could not read leaves a
// header and an empty body -- which is why these are listed, not guessed at.
const SNAP_NO_OUTPUT_NOTE = 'couchbase.log has the section header but no '
  + 'output: the command needed privileges the collection did not have, or the '
  + 'tool/file is not on this host. Nothing in the capture says which — the '
  + 'error went to the collection log, not here';
// Kernel defaults for the vm.* knobs, so a tuned host is visible at a glance.
// Every knob is still rendered whether or not it matches, because a missing row
// would be ambiguous between "stock" and "not recorded". min_free_kbytes has no
// fixed default (the kernel sizes it from RAM), so it is absent here.
const SNAP_DEFAULT = {
  'vm.swappiness': 60,
  'vm.watermark_scale_factor': 10,
  'vm.zone_reclaim_mode': 0,
  'vm.extfrag_threshold': 500,
  'vm.overcommit_memory': 0,
  'vm.overcommit_ratio': 50,
  'vm.panic_on_oom': 0,
  'vm.oom_kill_allocating_task': 0,
};
// Sectioned so the panel reads as Platform / CPU / Memory / IO rather than
// one undifferentiated card list. A card that mixes resources (the old PSI
// card) is split so each half lands under its own resource's section.
const SNAP_SECTIONS = [
  { title:'Host', cards:[
    { key:'platform', title:'Host uptime',
      help:'from /proc/uptime, host-wide even in a pod — how long the box had '
         + 'been up at collection. Shorter than the capture means it rebooted, '
         + 'which explains a gap in every other signal',
      rows:[
        ['uptime_secs','up at collection', fmtDur],
      ] },
  ] },
  { title:'CPU', cards:[
    { key:'cbcpu', title:'Couchbase slice CPU throttling (CFS)',
      help:'PSI-independent — throttling against the pod’s OWN cpu limit',
      rows:[
        ['cpu.stat.nr_periods','CFS periods', SNAP_INT],
        ['cpu.stat.nr_throttled','periods throttled', SNAP_INT, v=>v>0],
        ['cpu.stat.throttled_period_pct','% periods throttled', SNAP_PCT, v=>v>=25, 'crit'],
        ['cpu.stat.throttled_usec','time throttled', SNAP_SEC, v=>v>0],
        ['cpu.stat.throttled_vs_usage_pct','throttled vs used', SNAP_PCT, v=>v>=10],
      ] },
    { key:'enclcpu', title:'Enclosing group CPU throttling (system-wide)',
      help:'a parent slice (e.g. kubepods = whole-node pod budget) hitting ITS cpu limit',
      rows:[
        ['encl.nr_throttled','periods throttled', SNAP_INT, v=>v>0],
        ['encl.throttled_period_pct','% periods throttled', SNAP_PCT, v=>v>=5],
        ['encl.throttled_usec','time throttled', SNAP_SEC, v=>v>0],
      ] },
    { key:'cbpsi_cpu', title:'Couchbase slice pressure (PSI) — CPU',
      help:'is couchbase itself stalling on cpu (needs PSI enabled)',
      rows:[
        ['cpu.some.avg60','cpu some avg60', SNAP_PCT, v=>v>=50],
      ] },
  ] },
  { title:'Memory', cards:[
    { key:'memswap', title:'Host memory and swap (at collection)',
      help:'swap total is the fact no series carries: a swap-usage series reads '
         + '0 both when swap is not configured and when it is configured but '
         + 'untouched, and those are different incidents',
      rows:[
        ['mem_total_bytes','total', SNAP_BYTES],
        ['mem_free_bytes','free', SNAP_BYTES],
        ['mem_available_bytes','available', SNAP_BYTES],
        ['swap_total_bytes','swap configured', v => v ? SNAP_BYTES(v) : 'none', v=>v===0],
        ['swap_free_bytes','swap free', SNAP_BYTES],
        ['swap_used_pct','swap used', SNAP_PCT, v=>v>=10],
      ] },
    { key:'wmark', title:'Reclaim thresholds (where each path starts)',
      help:'free below the low watermark wakes kswapd; below min an allocating '
         + 'task reclaims inline and stalls doing it; kswapd stops above high. '
         + 'Summed over populated zones to compare against a host-wide '
         + 'free-memory series — reclaim is decided per zone, so one zone can '
         + 'cross its own watermark while the total still looks comfortable',
      rows:[
        ['wmark_low_bytes','kswapd wakes below free', SNAP_BYTES],
        ['wmark_min_bytes','direct reclaim below free', SNAP_BYTES],
        ['wmark_high_bytes','kswapd stops above free', SNAP_BYTES],
        ['zone_free_bytes','zone free at collection', SNAP_BYTES],
        ['free_above_low_bytes','headroom above kswapd threshold', SNAP_BYTES, v=>v<=0, 'crit'],
        ['wmark_largest_zone','largest zone', v=>v],
        ['largest_zone_wmark_low_bytes','its kswapd threshold', SNAP_BYTES],
        ['largest_zone_free_bytes','its free at collection', SNAP_BYTES],
        ['wmark_zones','zones summed', v=>v],
        ['page_size_bytes','page size used to scale', SNAP_BYTES],
      ] },
    { key:'reclaimcfg', title:'Reclaim tuning (sysctl vm.*)',
      help:'the knobs that set the watermarks above and decide what happens '
         + 'when reclaim cannot keep up. Values differing from the kernel '
         + 'default are marked — a deliberately tuned host reads differently '
         + 'from a stock one',
      rows:[
        ['vm.swappiness','swappiness', SNAP_INT],
        ['vm.min_free_kbytes','min_free_kbytes', SNAP_KB],
        ['vm.watermark_scale_factor','watermark_scale_factor', SNAP_INT],
        ['vm.zone_reclaim_mode','zone_reclaim_mode', SNAP_INT],
        ['vm.extfrag_threshold','extfrag_threshold', SNAP_INT],
        ['vm.overcommit_memory','overcommit_memory', SNAP_INT],
        ['vm.overcommit_ratio','overcommit_ratio', SNAP_INT],
        ['vm.panic_on_oom','panic_on_oom', SNAP_INT, v=>v>0, 'crit'],
        ['vm.oom_kill_allocating_task','oom_kill_allocating_task', SNAP_INT, v=>v>0],
      ] },
    { key:'reclaim', title:'Host reclaim (root, /proc/vmstat)',
      help:'whole-node since-boot counters — available even in a pod',
      rows:[
        ['allocstall_total','direct-reclaim invocations', SNAP_INT, v=>v>0],
        ['pgscan_total','pages scanned', SNAP_INT],
        ['pgsteal_total','pages reclaimed', SNAP_INT],
        ['scan_efficiency_pct','scan efficiency', SNAP_PCT, v=>v<50],
      ] },
    { key:'reclaimpath', title:'Host reclaim by path (kswapd vs direct)',
      help:'kswapd scans in the background; direct reclaim scans inline in an allocating task — those pages were scanned while something stalled waiting for memory',
      rows:[
        ['pgscan_kswapd','kswapd pages scanned', SNAP_INT],
        ['pgsteal_kswapd','kswapd pages reclaimed', SNAP_INT],
        ['scan_efficiency_kswapd_pct','kswapd scan efficiency', SNAP_PCT, v=>v<50],
        ['pgscan_direct','direct pages scanned', SNAP_INT, v=>v>0],
        ['pgsteal_direct','direct pages reclaimed', SNAP_INT, v=>v>0],
        ['scan_efficiency_direct_pct','direct scan efficiency', SNAP_PCT, v=>v<50],
        ['pgscan_direct_share_pct','% of scanning that was direct', SNAP_PCT, v=>v>=1],
      ] },
    { key:'census', title:'Dying (zombie) cgroups',
      help:'rmdir’d cgroups still pinned by unreclaimed page cache',
      rows:[
        ['cgroup.stat.nr_dying_descendants','dying', SNAP_INT, v=>v>=1000],
        ['cgroup.stat.nr_descendants','live descendants', SNAP_INT],
      ] },
    { key:'cbmem', title:'Couchbase slice memory',
      help:'the couchbase cgroup’s own accounting',
      rows:[
        ['memory.current','current', SNAP_BYTES],
        ['memory.max','limit', SNAP_BYTES],
        ['memory.swap.current','swap', SNAP_BYTES],
        ['memory.events.high','high (throttle) events', SNAP_INT, v=>v>0],
        ['memory.events.oom','oom events', SNAP_INT, v=>v>0, 'crit'],
        ['memory.events.oom_kill','oom_kill events', SNAP_INT, v=>v>0, 'crit'],
      ] },
    { key:'cbmemthrash', title:'Couchbase slice memory reclaim / thrash',
      help:'PSI-independent — throttle events + refaults (pages evicted under the limit, then faulted back)',
      rows:[
        ['memory.events.high','throttled at memory.high', SNAP_INT, v=>v>0, 'crit'],
        ['memory.events.max','hit hard memory.max', SNAP_INT, v=>v>0, 'crit'],
        ['memory.stat.pgmajfault','major faults', SNAP_INT, v=>v>0],
        ['memory.stat.workingset_refault_file','file refaults (thrash)', SNAP_INT, v=>v>0],
        ['memory.stat.workingset_refault_anon','anon refaults (thrash)', SNAP_INT, v=>v>0],
        ['memory.swap.events.fail','swap alloc failures', SNAP_INT, v=>v>0],
      ] },
    { key:'cbpsi_mem', title:'Couchbase slice pressure (PSI) — Memory',
      help:'is couchbase itself stalling on memory (needs PSI enabled)',
      rows:[
        ['memory.some.avg60','memory some avg60', SNAP_PCT, v=>v>=10],
        ['memory.full.avg60','memory full avg60', SNAP_PCT, v=>v>=10],
      ] },
  ] },
  { title:'IO', cards:[
    { key:'cbio', title:'Couchbase slice block IO',
      help:'IO limits (if any) + volume. No throttle-time without PSI — presence of a limit = can be throttled',
      rows:[
        ['io.max.limited_devices','IO-limited devices', v=>v, v=>true, 'crit'],
        ['io.stat.rbytes','read', SNAP_BYTES],
        ['io.stat.wbytes','written', SNAP_BYTES],
        ['io.stat.rios','read ops', SNAP_INT],
        ['io.stat.wios','write ops', SNAP_INT],
      ] },
    { key:'cbpsi_io', title:'Couchbase slice pressure (PSI) — IO',
      help:'is couchbase itself stalling on io (needs PSI enabled)',
      rows:[
        ['io.full.avg60','io full avg60', SNAP_PCT, v=>v>=20],
      ] },
  ] },
];

async function loadSnapshot() {
  if (!SNAP_BY_NODE) {
    const rows = await getJSON('/api/snapshot');
    SNAP_BY_NODE = {};
    // node -> {metric: row}. Metric names are unique within a node.
    for (const r of rows)
      (SNAP_BY_NODE[r.node] = SNAP_BY_NODE[r.node] || {})[r.metric] = r;
    const nodes = Object.keys(SNAP_BY_NODE).sort();
    const sel = $('snapnode');
    sel.innerHTML = nodes.map(n => `<option>${escapeHtml(n)}</option>`).join('');
    sel.disabled = nodes.length <= 1;
  }
  renderSnapshotCards();
}

// The sources a card above would have come from whose couchbase.log command
// produced no output. Rendered as its own card because an absent card is
// otherwise indistinguishable from a healthy capture with nothing to report --
// and in the field the usual cause is cbcollect_info run without the privileges
// the command needed. Metric names are dynamic ("no_output:<section>"), so this
// scans by prefix rather than being declared in SNAP_SECTIONS.
function snapNotCollected(m) {
  const rows = Object.keys(m).filter(k => k.startsWith('no_output:')).sort()
    .map(k => `<div class="srow"><span class="sk">${
      escapeHtml(k.slice('no_output:'.length))}</span>`
      + `<span class="sv"><span class="snote">${
        escapeHtml(m[k].text_value || '')}</span></span></div>`);
  if (!rows.length) return '';
  return `<div class="scard"><h4>Sources that returned nothing</h4>`
    + `<div class="snode" title="${escapeHtml(SNAP_NO_OUTPUT_NOTE)}">${
      escapeHtml(SNAP_NO_OUTPUT_NOTE)}</div>${rows.join('')}</div>`;
}

function renderSnapshotCards() {
  const host = $('snapfacts');
  const nodes = Object.keys(SNAP_BY_NODE);
  if (!nodes.length) {
    host.innerHTML = '<div class="muted">no collection-time snapshot facts '
      + '(couchbase.log had no vmstat / cgroup sections)</div>';
    return;
  }
  const node = $('snapnode').value || nodes.sort()[0];
  const m = SNAP_BY_NODE[node] || {};
  const cards = [];
  for (const section of SNAP_SECTIONS) {
    const sectionCards = [];
    for (const c of section.cards) {
      const present = c.rows.filter(([metric]) => m[metric] !== undefined);
      if (!present.length) continue;
      const lines = present.map(([metric, label, fmt, hot, tint]) => {
        const r = m[metric];
        const raw = r.value !== null ? r.value : r.text_value;
        const shown = (fmt && r.value !== null) ? fmt(r.value) : raw;
        const cls = hot && hot(r.value) ? (tint === 'crit' ? 'crit' : 'hot') : '';
        // A knob off its kernel default is not a warning, so it gets a note
        // rather than a tint -- "tuned" is context, not a verdict.
        const dflt = SNAP_DEFAULT[metric];
        const note = (dflt !== undefined && r.value !== null && +r.value !== dflt)
          ? ` tuned, default ${dflt}` : '';
        return `<div class="srow"><span class="sk">${label}</span>`
             + `<span class="sv ${cls}">${escapeHtml(String(shown))}`
             + (note ? `<span class="snote">${escapeHtml(note)}</span>` : '')
             + `</span></div>`;
      }).join('');
      // Source footnote: the exact slice/file these facts came from (honesty
      // about host-rooted vs container-scoped cgroup views).
      const any = m[present[0][0]];
      const idBy = m['identified_by'];
      const foot = SNAP_NO_FOOT.has(c.key) ? ''
        : `<div class="srcpath">${escapeHtml(any.scope)}: ${escapeHtml(any.scope_path||'')}`
          + (any.scope === 'couchbase' && idBy ? ` (${escapeHtml(idBy.text_value)})` : '')
          + `</div>`;
      sectionCards.push(`<div class="scard"><h4>${c.title}</h4>`
        + `<div class="snode" title="${escapeHtml(c.help)}">${escapeHtml(c.help)}</div>`
        + lines + foot + `</div>`);
    }
    if (!sectionCards.length) continue;
    cards.push(`<div class="ssechead">${escapeHtml(section.title)}</div>`);
    cards.push(...sectionCards);
  }
  const missing = snapNotCollected(m);
  if (missing) {
    cards.push('<div class="ssechead">Not collected</div>');
    cards.push(missing);
  }
  host.innerHTML = cards.join('');
}

async function refresh() {
  HIST = await getJSON('/api/histogram?'+qstring());
  drawHist();
  renderPressure();
  // The overview bands follow the window, so they are part of a refresh. Redraw
  // only (the payload is already in hand), and only when the panel is open.
  if (LDR && overviewOpen()) renderOverview();
  await renderTable();
}

async function init() {
  META = await getJSON('/api/meta');
  OFFSET_TL = META.offset_timeline || [];
  // Default to collection-local when we have any offset data, else UTC.
  displayMode = OFFSET_TL.length ? 'local' : 'utc';
  $('colltz').checked = (displayMode === 'local');
  for (const [k,_] of FACETS) sel[k] = new Set();
  renderPills(); renderFacets(); bindHistBrush();
  // Apply reads the start/end inputs (a manual range overrides any brush).
  const applyRange = () => {
    range.start = parseTs($('tstart').value);
    range.end = parseTs($('tend').value, true);   // upper bound: inclusive of its unit
    pinned = null; syncRangeInputs(); refresh();
  };
  $('apply').onclick = applyRange;
  ['q','minms','status','path','tstart','tend'].forEach(id =>
    $(id).onkeydown = (e) => { if (e.key==='Enter') applyRange(); });
  $('reset').onclick = () => { sel={}; for(const[k,_]of FACETS)sel[k]=new Set();
    range={start:null,end:null}; pinned=null; sortBy=null; $('q').value='';
    $('minms').value=''; $('status').value=''; $('path').value='';
    $('anchored').checked=false;
    syncRangeInputs(); renderFacets(); refresh(); };
  $('anchored').onchange = refresh;
  $('colltz').onchange = () => {
    displayMode = $('colltz').checked ? 'local' : 'utc';
    // Range epochs are canonical; just reformat the inputs in the new zone.
    syncTZLabels(); syncRangeInputs(); renderPills(); drawHist(); renderTable();
  };
  window.onresize = drawHist;
  $('pgprev').onclick = pagePrev;
  $('pgnext').onclick = pageNext;
  $('pgjump').onkeydown = (e) => { if (e.key === 'Enter') pageJump(); };
  $('pgjump').onchange = pageJump;
  $('snapbtn').onclick = () => {
    if ($('snappanel').style.display !== 'none') return hideSnapshots();
    $('snappanel').style.display = 'flex';
    $('snapbtn').classList.add('primary');
    snapTab('facts');
  };
  $('snapclose').onclick = hideSnapshots;
  $('svcclose').onclick = hideService;
  $('opclose').onclick = hideOperation;
  $('svcnode').onchange = () => {
    if (svcOpen) showService(svcOpen.name, $('svcnode').value);
  };
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    // Innermost first: a modal is on top of the drawer, which is on top of the
    // inline overview, so Escape peels them off in the order they were stacked.
    if ($('snappanel').style.display !== 'none') hideSnapshots();
    else if (opOpen) hideOperation();
    else if (svcOpen) hideService();
  });
  $('snaptab-facts').onclick = () => snapTab('facts');
  $('snaptab-proc').onclick = () => snapTab('proc');
  $('snapnode').onchange = renderSnapshotCards;
  $('procdump').onchange = renderProcDump;
  $('procsort').onchange = renderProcDump;
  // Filters apply as you type; a dump is already in memory server-side, so the
  // round trip is cheap and waiting for Enter just adds a step.
  for (const id of ['procname', 'procloc', 'procmq']) {
    $(id).oninput = debounce(renderProcDump, 200);
  }
  initStrips();
  if (overviewOpen()) await showOverview();
  await renderFindings();
  syncTZLabels();
  await refresh();
}
init();
