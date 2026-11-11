#!/usr/bin/env node
// BlueShift — SPL engine tests against a fixed event set, so every command and
// function is asserted on exact results.
const path = require('path');
const { runSpl } = require(path.join('..', 'src', 'spl'));

let passed = 0, failed = 0;
const assert = (c, m) => { if (!c) throw new Error(m); };
function test(name, fn) { try { fn(); passed++; console.log('  ✓ ' + name); } catch (e) { failed++; console.error('  ✗ ' + name + '\n      ' + e.message); } }

const EV = [
  { _time: 1, _raw: 'ssh failed password for ava from 9.9.9.9', index: 'auth', host: 'FS-01', user: 'ava', src_ip: '9.9.9.9', action: 'failure', signature: 'ssh_fail', bytes: 100, dest_port: 22 },
  { _time: 2, _raw: 'ssh failed password for ava from 9.9.9.9', index: 'auth', host: 'FS-01', user: 'ava', src_ip: '9.9.9.9', action: 'failure', signature: 'ssh_fail', bytes: 120, dest_port: 22 },
  { _time: 3, _raw: 'ssh accepted for ava', index: 'auth', host: 'FS-01', user: 'ava', src_ip: '9.9.9.9', action: 'success', signature: 'ssh_ok', bytes: 300, dest_port: 22 },
  { _time: 4, _raw: 'rdp failure for liam', index: 'auth', host: 'DC-01', user: 'liam', src_ip: '8.8.8.8', action: 'failure', signature: 'rdp_fail', bytes: 90, dest_port: 3389 },
  { _time: 5, _raw: 'big upload', index: 'dlp', host: 'DB-01', user: 'omar', src_ip: '10.0.0.5', action: 'allowed', signature: 'exfil', bytes: 5000000, dest_port: 443 },
  { _time: 6, _raw: 'web browse', index: 'proxy', host: 'WS-02', user: 'mia', src_ip: '10.0.0.9', action: 'allowed', signature: 'browse', bytes: 2048, dest_port: 443 }
];
const run = q => { const r = runSpl(EV, q); assert(r.ok, 'query failed: ' + q + ' :: ' + r.error); return r; };

test('implicit search: field equality and AND', () => {
  const r = run('index=auth action=failure');
  assert(r.rows.length === 3 && r.rows.every(e => e.index === 'auth' && e.action === 'failure'), 'expected 3 auth failures');
});
test('search: OR, NOT and parentheses', () => {
  assert(run('action=failure OR action=success').rows.length === 4, 'OR');
  assert(run('index=auth NOT action=failure').rows.length === 1, 'NOT');
  assert(run('(index=auth AND action=success) OR index=dlp').rows.length === 2, 'grouping');
});
test('search: wildcards and numeric comparison', () => {
  assert(run('host=FS-*').rows.length === 3, 'wildcard host');
  assert(run('bytes>1000').rows.length === 2, 'bytes>1000');
  assert(run('dest_port>=3389').rows.length === 1, 'port>=');
});
test('search: bare term and quoted phrase match _raw', () => {
  assert(run('failed').rows.length === 2, 'bare term');
  assert(run('"failed password"').rows.length === 2, 'phrase');
});
test('stats count with by, and count of all', () => {
  const r = run('index=auth | stats count by action');
  assert(r.type === 'table', 'stats yields a table');
  const byAction = Object.fromEntries(r.rows.map(x => [x.action, x.count]));
  assert(byAction.failure === 3 && byAction.success === 1, 'counts by action: ' + JSON.stringify(byAction));
  assert(run('| stats count').rows[0].count === 6, 'total count');
});
test('stats: dc, sum, avg, min, max, values with as-names', () => {
  const r = run('| stats dc(user) as users sum(bytes) as total avg(bytes) as mean max(bytes) as biggest by index');
  const auth = r.rows.find(x => x.index === 'auth');
  assert(auth.users === 2, 'dc(user) in auth = 2 (ava, liam)');
  assert(auth.total === 100 + 120 + 300 + 90, 'sum(bytes) in auth');
  assert(auth.biggest === 300, 'max(bytes) in auth');
  const dlp = r.rows.find(x => x.index === 'dlp');
  assert(dlp.mean === 5000000, 'avg over single dlp row');
});
test('where filters on computed/aggregate fields', () => {
  const r = run('| stats count by user | where count >= 2');
  assert(r.rows.length === 1 && r.rows[0].user === 'ava' && r.rows[0].count === 3, 'only ava has >=2');
});
test('eval creates fields with functions and arithmetic', () => {
  const r = run('index=dlp | eval mb = round(bytes/1048576, 1) | table host mb');
  assert(r.rows[0].mb === 4.8, 'bytes->MB rounded, got ' + r.rows[0].mb);
  const r2 = run('index=auth | eval label = upper(user) . "@" . host | table label | head 1');
  assert(r2.rows[0].label === 'AVA@FS-01', 'string concat + upper, got ' + r2.rows[0].label);
  const r3 = run('| eval risky = if(bytes>1000, "high", "low") | stats count by risky');
  assert(Object.fromEntries(r3.rows.map(x => [x.risky, x.count])).high === 2, 'if() classification');
});
test('table / fields select and remove columns', () => {
  assert(JSON.stringify(run('| table host user').columns) === JSON.stringify(['host', 'user']), 'table columns');
  assert(!run('| fields - _raw bytes').columns.includes('_raw'), 'fields - removes');
});
test('rename changes a field name', () => {
  const r = run('| rename host as asset | table asset | head 1');
  assert(r.columns[0] === 'asset' && r.rows[0].asset === 'FS-01', 'renamed host->asset');
});
test('sort (asc/desc) with optional limit', () => {
  assert(run('| sort -bytes | head 1').rows[0].bytes === 5000000, 'desc by bytes');
  assert(run('| sort 2 bytes').rows.length === 2 && run('| sort bytes').rows[0].bytes === 90, 'asc + limit');
});
test('head and tail', () => {
  assert(run('| head 2').rows.length === 2, 'head');
  assert(run('| tail 1').rows[0]._time === 6, 'tail takes the last');
});
test('top and rare produce counts and percent', () => {
  const t = run('index=auth | top 1 user');
  assert(t.rows[0].user === 'ava' && t.rows[0].count === 3 && t.columns.includes('percent'), 'top user ava');
  const r = run('index=auth | rare 1 user');
  assert(r.rows[0].user === 'liam' && r.rows[0].count === 1, 'rarest user liam');
});
test('dedup keeps the first row per key', () => {
  assert(run('index=auth | dedup user').rows.length === 2, 'two distinct users in auth');
});
test('a full realistic pipeline runs end to end', () => {
  const r = run('index=auth action=failure | stats count by user host | where count > 1 | sort -count | head 5');
  assert(r.ok && r.rows.length === 1 && r.rows[0].user === 'ava' && r.rows[0].count === 2, 'ava/FS-01 had 2 failures');
});
test('an unknown command is reported, not thrown', () => {
  const r = runSpl(EV, '| frobnicate x');
  assert(r.ok === false && /unknown command/i.test(r.error), 'unknown command error');
});

console.log(`\n${passed} passed, ${failed} failed, ${passed + failed} total.`);
if (failed) process.exit(1);
