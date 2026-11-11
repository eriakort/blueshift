// BlueShift — the SOC environment model.
// Pure and deterministic: generateEnvironment(seed) builds a reproducible set of
// assets and correlated SIEM alerts (each with a hidden ground-truth verdict),
// plus query, triage and scoring helpers. No DOM, no randomness outside the seed.
const { makeRng } = require('./rng');
const C = require('./catalog');

const DEPT_ABBR = { Finance: 'FIN', Engineering: 'ENG', Sales: 'SAL', HR: 'HR', 'IT Operations': 'ITO', Legal: 'LEG', Marketing: 'MKT', Executive: 'EXE' };
const ROLE_ABBR = { workstation: 'WS', laptop: 'LT', 'file-server': 'FS', 'web-server': 'WEB', 'domain-controller': 'DC', database: 'DB', firewall: 'FW', 'vpn-gateway': 'VPN' };
const BUMP = { low: 'medium', medium: 'high', high: 'critical', critical: 'critical' };

function buildAssets(rng, n) {
  const assets = [];
  const used = new Set();
  for (let i = 0; i < n; i++) {
    const r = rng.weighted(C.ROLES.map(x => [x, x.weight]));
    const dept = rng.pick(C.DEPTS);
    let num = rng.int(1, 60), hostname;
    do { hostname = `${DEPT_ABBR[dept]}-${ROLE_ABBR[r.role]}-${String(num).padStart(2, '0')}`; num = rng.int(1, 99); } while (used.has(hostname));
    used.add(hostname);
    const owner = `${rng.pick(C.FIRST)}.${rng.pick(C.LAST)}`;
    assets.push({
      id: 'AST-' + String(1000 + i),
      hostname, dept, role: r.role, os: rng.pick(r.os), criticality: r.crit, owner,
      ip: `10.${C.DEPTS.indexOf(dept)}.${C.ROLES.indexOf(r) + 1}.${rng.int(10, 240)}`
    });
  }
  return assets;
}

const extIp = rng => `${rng.int(23, 198)}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`;
const b64 = rng => Array.from({ length: 10 }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789'[rng.int(0, 41)]).join('');

function makeContext(rng, asset) {
  const user = `${rng.pick(C.FIRST)}.${rng.pick(C.LAST)}`;
  return {
    asset, user,
    srcIp: extIp(rng), extIp: extIp(rng),
    subnet: asset.ip.split('.').slice(0, 3).join('.') + '.0/24',
    hostCount: rng.int(18, 120), failCount: rng.int(12, 240),
    beaconPath: rng.pick(['api/v2/ping', 'cdn/assets', 'gate.php', 'img/1.gif', 'rpc']),
    proc: rng.pick(['svchost32.exe', 'updater.exe', 'rundll32.exe', 'msbuild.exe', 'wscript.exe']),
    extUser: `${rng.pick(C.FIRST)}@${rng.pick(['mail-secure', 'invoices-dept', 'docs-share', 'it-helpdesk'])}.com`,
    phishDomain: rng.pick(['secure-login-portal', 'account-verify', 'o365-reauth', 'vpn-access']) + '.com',
    b64: b64(rng), cr: rng.int(1000, 9999),
    mb: rng.int(220, 4800), docCount: rng.int(40, 1200), proto: rng.pick(['HTTPS', 'FTP', 'DNS']),
    geoA: rng.pick(['London, UK', 'Berlin, DE', 'Austin, US', 'Toronto, CA']),
    geoB: rng.pick(['Lagos, NG', 'Manila, PH', 'São Paulo, BR', 'Kyiv, UA']),
    pushCount: rng.int(8, 60),
    malware: rng.pick(['Trojan.GenericKD', 'Win32/Emotet', 'EICAR-Test', 'Ransom.Conti', 'PUA.CoinMiner']),
    file: rng.pick(['invoice_2024.doc.exe', 'setup.scr', 'payroll.xlsm', 'update.bin']),
    newAcct: rng.pick(['svc_backup', 'admin2', 'helpdesk_tmp', 'ops_adm'])
  };
}

function buildAlerts(rng, assets, n) {
  const alerts = [];
  let minutesAgo = rng.int(2, 9);
  for (let i = 0; i < n; i++) {
    const arch = rng.pick(C.ARCHETYPES);
    const asset = rng.pick(assets);
    const truth = rng.weighted(arch.verdicts);
    const ctx = makeContext(rng, asset); ctx.truth = truth;
    let severity = arch.severity;
    if (asset.criticality === 'critical' && severity !== 'critical' && rng.chance(0.6)) severity = BUMP[severity];
    alerts.push({
      id: 'AL-' + String(4100 + i),
      archetype: arch.key, title: arch.title(ctx), severity,
      category: arch.category, tactic: arch.tactic, techniqueId: arch.techniqueId, technique: arch.technique,
      rule: arch.rule, asset: { id: asset.id, hostname: asset.hostname, ip: asset.ip, role: asset.role, criticality: asset.criticality, owner: asset.owner },
      user: ctx.user, minutesAgo, events: arch.ev(ctx), recommendation: arch.reco(ctx),
      truth,                                   // hidden ground truth (not shown until triaged)
      status: 'new', analystVerdict: null
    });
    minutesAgo += rng.int(3, 55);
  }
  return alerts.sort((a, b) => C.SEV_RANK[b.severity] - C.SEV_RANK[a.severity] || a.minutesAgo - b.minutesAgo);
}

function generateEnvironment(seed = 1, opts = {}) {
  const rng = makeRng(seed);
  const assets = buildAssets(rng, opts.assets || 26);
  const alerts = buildAlerts(rng, assets, opts.alerts || 16);
  return { seed, assets, alerts, meta: { version: 1 } };
}

// ---- queries ----
function filterAlerts(env, f = {}) {
  const q = (f.query || '').toLowerCase();
  return env.alerts.filter(a =>
    (f.severity == null || f.severity === 'all' || a.severity === f.severity) &&
    (f.status == null || f.status === 'all' || (f.status === 'open' ? a.status !== 'closed' : a.status === f.status)) &&
    (!q || (a.title + ' ' + a.asset.hostname + ' ' + a.category + ' ' + a.tactic + ' ' + a.technique + ' ' + a.rule + ' ' + a.events.join(' ')).toLowerCase().includes(q))
  );
}

function summarize(env) {
  const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
  let open = 0, closed = 0, correct = 0;
  for (const a of env.alerts) {
    if (a.status === 'closed') { closed++; if (a.analystVerdict === a.truth) correct++; }
    else { open++; bySev[a.severity]++; }
  }
  return { total: env.alerts.length, open, closed, correct,
    accuracy: closed ? Math.round((correct / closed) * 100) : null,
    bySev, assets: env.assets.length };
}

// ---- triage ----
// Disposition one of VERDICTS. Returns { ok, correct } where correct compares the
// analyst's call to the alert's hidden ground truth (the learning signal).
function triageAlert(env, alertId, disposition, note) {
  if (!C.VERDICTS.includes(disposition)) return { ok: false, reason: 'unknown disposition' };
  const a = env.alerts.find(x => x.id === alertId);
  if (!a) return { ok: false, reason: 'no such alert' };
  a.status = 'closed'; a.analystVerdict = disposition; a.note = note || a.note || '';
  return { ok: true, correct: disposition === a.truth, truth: a.truth };
}
function reopenAlert(env, alertId) {
  const a = env.alerts.find(x => x.id === alertId);
  if (!a) return { ok: false };
  a.status = 'new'; a.analystVerdict = null; return { ok: true };
}
function acknowledgeAlert(env, alertId) {
  const a = env.alerts.find(x => x.id === alertId);
  if (!a || a.status === 'closed') return { ok: false };
  a.status = 'investigating'; return { ok: true };
}

module.exports = { generateEnvironment, filterAlerts, summarize, triageAlert, reopenAlert, acknowledgeAlert, SEV_RANK: C.SEV_RANK, VERDICTS: C.VERDICTS };
