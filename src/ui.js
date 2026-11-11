// BlueShift — application UI (vanilla JS, no framework). The platform shell plus
// the SIEM analyst console. State lives in memory and the view is re-rendered on
// change; everything is driven by the deterministic model, so the UI stays a thin
// presentation layer over tested logic.
const Model = require('./model');

const $ = sel => document.querySelector(sel);
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
const DISPOSITIONS = [
  { key: 'true-positive', label: 'True positive · escalate', hint: 'A real threat — escalate to an incident.' },
  { key: 'false-positive', label: 'False positive', hint: 'The detection fired but there is no real threat.' },
  { key: 'benign', label: 'Benign / expected', hint: 'Real activity, but authorized and expected.' }
];
const VERDICT_LABEL = { 'true-positive': 'a true positive', 'false-positive': 'a false positive', 'benign': 'benign / expected activity' };

const STATE = { env: null, seed: 1, selected: null, filters: { severity: 'all', status: 'open', query: '' }, feedback: null };

function newShift(seed) {
  STATE.seed = seed == null ? (Date.now() % 100000) : seed;
  STATE.env = Model.generateEnvironment(STATE.seed);
  STATE.selected = STATE.env.alerts[0] ? STATE.env.alerts[0].id : null;
  STATE.feedback = null;
  render();
}

const MODULES = [
  { key: 'siem', glyph: '◈', name: 'SIEM', sub: 'Alert triage', active: true },
  { key: 'vuln', glyph: '◎', name: 'Vulnerability Mgmt', sub: 'Findings & remediation', soon: true },
  { key: 'soar', glyph: '⚙', name: 'SOAR', sub: 'Response playbooks', soon: true },
  { key: 'ai', glyph: '✦', name: 'AI Triage', sub: 'Assisted analysis', soon: true }
];

function render() {
  const env = STATE.env, s = Model.summarize(env);
  const shown = Model.filterAlerts(env, STATE.filters);
  const sel = env.alerts.find(a => a.id === STATE.selected) || shown[0] || null;
  if (sel) STATE.selected = sel.id;
  $('#app').innerHTML = `
    <div class="bs-shell">
      <aside class="bs-rail">
        <div class="bs-brand"><span class="bs-logo">◂▸</span><div><strong>BlueShift</strong><small>SOC analyst range</small></div></div>
        <div class="bs-rail-label">Modules</div>
        ${MODULES.map(m => `<button class="bs-mod${m.active ? ' active' : ''}${m.soon ? ' soon' : ''}" ${m.soon ? 'disabled' : ''} title="${m.soon ? 'Coming soon' : m.name}"><span class="bs-mod-glyph">${m.glyph}</span><span class="bs-mod-text"><b>${m.name}</b><small>${m.sub}</small></span>${m.soon ? '<span class="bs-soon">soon</span>' : ''}</button>`).join('')}
        <div class="bs-rail-foot">Fully simulated range<br>Seed #${env.seed}</div>
      </aside>
      <main class="bs-main">
        <header class="bs-top">
          <div><div class="bs-eyebrow">Security operations · SIEM</div><h1>Alert triage console</h1></div>
          <div class="bs-top-actions">
            <div class="bs-score" title="Your triage accuracy this shift"><span>Accuracy</span><strong>${s.accuracy == null ? '—' : s.accuracy + '%'}</strong><small>${s.correct}/${s.closed} graded</small></div>
            <button class="bs-btn" id="bsNewShift">↻ New shift</button>
          </div>
        </header>
        <section class="bs-kpis">
          <article class="bs-kpi"><span>Open alerts</span><strong>${s.open}</strong><em>${s.total} this shift</em></article>
          <article class="bs-kpi k-critical"><span>Critical</span><strong>${s.bySev.critical}</strong></article>
          <article class="bs-kpi k-high"><span>High</span><strong>${s.bySev.high}</strong></article>
          <article class="bs-kpi k-medium"><span>Medium</span><strong>${s.bySev.medium}</strong></article>
          <article class="bs-kpi"><span>Closed</span><strong>${s.closed}</strong><em>${s.accuracy == null ? 'triage to score' : s.accuracy + '% correct'}</em></article>
        </section>
        <div class="bs-toolbar">
          <label>Severity <select id="bsSev">${['all', ...SEV_ORDER].map(v => `<option value="${v}"${STATE.filters.severity === v ? ' selected' : ''}>${v === 'all' ? 'All' : v[0].toUpperCase() + v.slice(1)}</option>`).join('')}</select></label>
          <label>Status <select id="bsStatus">${['open', 'all', 'new', 'investigating', 'closed'].map(v => `<option value="${v}"${STATE.filters.status === v ? ' selected' : ''}>${v[0].toUpperCase() + v.slice(1)}</option>`).join('')}</select></label>
          <input id="bsSearch" type="search" value="${esc(STATE.filters.query)}" placeholder="Search alerts, assets, log lines, techniques…"/>
          <span class="bs-count">${shown.length} shown</span>
        </div>
        <div class="bs-split">
          <section class="bs-queue" aria-label="Alert queue">${shown.map(a => queueRow(a, sel)).join('') || '<div class="bs-empty">No alerts match the current filters.</div>'}</section>
          <section class="bs-detail" aria-label="Alert detail">${sel ? detail(sel) : '<div class="bs-empty">Select an alert to investigate.</div>'}</section>
        </div>
      </main>
    </div>`;
  wire();
}

function queueRow(a, sel) {
  const stateDot = a.status === 'closed' ? (a.analystVerdict === a.truth ? 'ok' : 'bad') : a.status === 'investigating' ? 'wip' : '';
  return `<button class="bs-row sev-${a.severity}${sel && a.id === sel.id ? ' selected' : ''}${a.status === 'closed' ? ' closed' : ''}" data-alert="${a.id}">
    <span class="bs-sev sev-${a.severity}">${a.severity[0].toUpperCase()}</span>
    <span class="bs-row-main"><b>${esc(a.title)}</b><small>${esc(a.asset.hostname)} · ${esc(a.category)} · ${esc(a.techniqueId)} · ${a.minutesAgo}m ago</small></span>
    ${stateDot ? `<span class="bs-row-state ${stateDot}" title="${a.status}">${stateDot === 'ok' ? '✓' : stateDot === 'bad' ? '✗' : '●'}</span>` : ''}
  </button>`;
}

function detail(a) {
  const closed = a.status === 'closed';
  const fb = STATE.feedback && STATE.feedback.id === a.id ? STATE.feedback : null;
  return `
    <div class="bs-detail-head">
      <span class="bs-sev-badge sev-${a.severity}">${a.severity.toUpperCase()}</span>
      <div><h2>${esc(a.title)}</h2><div class="bs-detail-meta"><span class="bs-chip">${esc(a.category)}</span><span class="bs-chip ghost">ATT&CK · ${esc(a.techniqueId)} ${esc(a.technique)}</span><span class="bs-mono">${esc(a.id)}</span></div></div>
    </div>
    <div class="bs-asset-card">
      <div><span>Asset</span><b>${esc(a.asset.hostname)}</b></div>
      <div><span>Address</span><b class="bs-mono">${esc(a.asset.ip)}</b></div>
      <div><span>Role</span><b>${esc(a.asset.role)}</b></div>
      <div><span>Criticality</span><b class="crit-${a.asset.criticality}">${esc(a.asset.criticality)}</b></div>
      <div><span>Owner</span><b>${esc(a.asset.owner)}</b></div>
      <div><span>Detection</span><b>${esc(a.rule)}</b></div>
    </div>
    <div class="bs-section-label">Raw events</div>
    <pre class="bs-log">${a.events.map(e => esc(e)).join('\n')}</pre>
    <div class="bs-reco"><b>Recommended response</b><p>${esc(a.recommendation)}</p></div>
    ${fb ? `<div class="bs-feedback ${fb.correct ? 'good' : 'bad'}">${fb.correct ? '✓ Correct' : '✗ Not quite'} — this alert was <b>${esc(VERDICT_LABEL[fb.truth])}</b>. You called it <b>${esc(VERDICT_LABEL[fb.verdict])}</b>.</div>` : ''}
    <div class="bs-section-label">Disposition</div>
    ${closed
      ? `<div class="bs-closed-note">Closed as <b>${esc(VERDICT_LABEL[a.analystVerdict])}</b>. <button class="bs-link" data-reopen="${a.id}">Reopen</button></div>`
      : `<div class="bs-dispo">${DISPOSITIONS.map(d => `<button class="bs-btn dispo" data-dispo="${d.key}" data-alert="${a.id}" title="${esc(d.hint)}">${esc(d.label)}</button>`).join('')}${a.status !== 'investigating' ? `<button class="bs-btn ghost" data-ack="${a.id}">Start investigating</button>` : '<span class="bs-inv">● investigating</span>'}</div>`}
  `;
}

function wire() {
  $('#bsNewShift').addEventListener('click', () => newShift());
  $('#bsSev').addEventListener('change', e => { STATE.filters.severity = e.target.value; render(); });
  $('#bsStatus').addEventListener('change', e => { STATE.filters.status = e.target.value; render(); });
  const search = $('#bsSearch');
  search.addEventListener('input', e => { STATE.filters.query = e.target.value; render(); const n = $('#bsSearch'); if (n) { n.focus(); n.setSelectionRange(n.value.length, n.value.length); } });
  document.querySelectorAll('[data-alert]').forEach(b => b.addEventListener('click', e => {
    if (e.target.closest('[data-dispo],[data-ack],[data-reopen]')) return;
    STATE.selected = b.dataset.alert; STATE.feedback = null; render();
  }));
  document.querySelectorAll('[data-ack]').forEach(b => b.addEventListener('click', () => { Model.acknowledgeAlert(STATE.env, b.dataset.ack); render(); }));
  document.querySelectorAll('[data-reopen]').forEach(b => b.addEventListener('click', () => { Model.reopenAlert(STATE.env, b.dataset.reopen); STATE.feedback = null; render(); }));
  document.querySelectorAll('[data-dispo]').forEach(b => b.addEventListener('click', () => {
    const r = Model.triageAlert(STATE.env, b.dataset.alert, b.dataset.dispo);
    if (r.ok) STATE.feedback = { id: b.dataset.alert, correct: r.correct, truth: r.truth, verdict: b.dataset.dispo };
    render();
  }));
}

function boot() { newShift(1); }
if (typeof document !== 'undefined') document.addEventListener('DOMContentLoaded', boot);
module.exports = { boot, STATE, newShift };
