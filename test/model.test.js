#!/usr/bin/env node
// BlueShift — model unit tests. The synthetic SOC environment must be fully
// deterministic (same seed -> identical world), well-formed, and the triage
// scoring must grade against the hidden ground truth.
const path = require('path');
const { generateEnvironment, filterAlerts, summarize, triageAlert, reopenAlert, acknowledgeAlert, VERDICTS } = require(path.join('..', 'src', 'model'));

let passed = 0, failed = 0;
const assert = (c, m) => { if (!c) throw new Error(m); };
function test(name, fn) { try { fn(); passed++; console.log('  ✓ ' + name); } catch (e) { failed++; console.error('  ✗ ' + name + '\n      ' + e.message); } }

test('environment generation is deterministic for a seed', () => {
  const a = generateEnvironment(42), b = generateEnvironment(42);
  assert(JSON.stringify(a) === JSON.stringify(b), 'same seed must produce an identical environment');
  const c = generateEnvironment(43);
  assert(JSON.stringify(a) !== JSON.stringify(c), 'different seeds should differ');
});

test('environment is well-formed', () => {
  const env = generateEnvironment(7, { assets: 26, alerts: 16 });
  assert(env.assets.length === 26 && env.alerts.length === 16, 'expected the requested counts');
  const ids = new Set(env.alerts.map(a => a.id));
  assert(ids.size === env.alerts.length, 'alert ids must be unique');
  for (const a of env.alerts) {
    assert(a.title && a.severity && a.category && a.techniqueId && a.rule, 'alert missing core fields: ' + a.id);
    assert(['critical', 'high', 'medium', 'low'].includes(a.severity), 'bad severity ' + a.severity);
    assert(Array.isArray(a.events) && a.events.length > 0, 'alert needs raw events');
    assert(a.recommendation && a.recommendation.length > 10, 'alert needs a recommendation');
    assert(VERDICTS.includes(a.truth), 'alert needs a ground-truth verdict');
    assert(a.asset && a.asset.hostname && a.asset.ip, 'alert must reference an asset');
    assert(a.status === 'new' && a.analystVerdict === null, 'alerts start untriaged');
  }
});

test('alerts are sorted by severity (highest first)', () => {
  const rank = { critical: 4, high: 3, medium: 2, low: 1 };
  const env = generateEnvironment(11);
  for (let i = 1; i < env.alerts.length; i++)
    assert(rank[env.alerts[i - 1].severity] >= rank[env.alerts[i].severity], 'alerts must be severity-sorted');
});

test('the generator exercises many detection archetypes (not just one)', () => {
  const kinds = new Set(generateEnvironment(5, { alerts: 24 }).alerts.map(a => a.archetype));
  assert(kinds.size >= 5, 'expected varied detections, got ' + kinds.size);
});

test('triage grades the analyst against the hidden truth', () => {
  const env = generateEnvironment(3);
  const a = env.alerts[0];
  const right = triageAlert(env, a.id, a.truth, 'matches truth');
  assert(right.ok && right.correct === true, 'correct disposition should score correct');
  assert(a.status === 'closed' && a.analystVerdict === a.truth, 'alert should be closed with the verdict recorded');
  const b = env.alerts[1];
  const wrongPick = VERDICTS.find(v => v !== b.truth);
  const wrong = triageAlert(env, b.id, wrongPick);
  assert(wrong.ok && wrong.correct === false, 'wrong disposition should score incorrect');
  assert(triageAlert(env, a.id, 'nonsense').ok === false, 'unknown dispositions are rejected');
});

test('acknowledge and reopen move alert status correctly', () => {
  const env = generateEnvironment(9);
  const a = env.alerts[2];
  assert(acknowledgeAlert(env, a.id).ok && a.status === 'investigating', 'acknowledge -> investigating');
  triageAlert(env, a.id, a.truth);
  assert(acknowledgeAlert(env, a.id).ok === false, 'cannot acknowledge a closed alert');
  assert(reopenAlert(env, a.id).ok && a.status === 'new' && a.analystVerdict === null, 'reopen resets the alert');
});

test('summary rolls up open/closed, severity and analyst accuracy', () => {
  const env = generateEnvironment(21);
  const before = summarize(env);
  assert(before.open === env.alerts.length && before.closed === 0 && before.accuracy === null, 'fresh env: all open, no accuracy yet');
  assert(before.bySev.critical + before.bySev.high + before.bySev.medium + before.bySev.low === env.alerts.length, 'severity rollup covers all open alerts');
  // close two correctly and one incorrectly -> 2/3 = 67%
  triageAlert(env, env.alerts[0].id, env.alerts[0].truth);
  triageAlert(env, env.alerts[1].id, env.alerts[1].truth);
  const wrong = VERDICTS.find(v => v !== env.alerts[2].truth);
  triageAlert(env, env.alerts[2].id, wrong);
  const after = summarize(env);
  assert(after.closed === 3 && after.correct === 2 && after.accuracy === 67, 'accuracy should be 2/3 = 67%, got ' + after.accuracy);
});

test('filterAlerts respects severity, status and free-text search', () => {
  const env = generateEnvironment(13);
  const crit = filterAlerts(env, { severity: 'critical' });
  assert(crit.every(a => a.severity === 'critical'), 'severity filter');
  const term = env.alerts[0].asset.hostname.toLowerCase();
  assert(filterAlerts(env, { query: term }).some(a => a.asset.hostname.toLowerCase() === term), 'search matches hostname');
  triageAlert(env, env.alerts[0].id, env.alerts[0].truth);
  assert(filterAlerts(env, { status: 'open' }).every(a => a.status !== 'closed'), 'open filter excludes closed');
});

console.log(`\n${passed} passed, ${failed} failed, ${passed + failed} total.`);
if (failed) process.exit(1);
