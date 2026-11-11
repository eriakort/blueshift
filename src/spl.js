// BlueShift — SPL (Search Processing Language): a Splunk-like, pipe-based query
// engine over the event index. Pure and deterministic. Supports an implicit
// `search` first stage plus a pipeline of commands:
//   search  stats  where  eval  table/fields  rename  sort  head/tail
//   top  rare  dedup
// with the common functions (count, dc, sum, avg, min, max, values, list,
// round, lower, upper, len, if, coalesce, like, match, isnull, isnotnull, ...).

/* ----------------------------- shared helpers ----------------------------- */
const isNumeric = v => v !== '' && v != null && !isNaN(Number(v));
const num = v => Number(v);
const str = v => v == null ? '' : String(v);
const wildcardToRe = (p, flags = 'i') => new RegExp('^' + str(p).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', flags);
function splitTopLevel(s, sep) {               // split on sep outside quotes/parens
  const out = []; let depth = 0, q = null, cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { cur += c; if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { q = c; cur += c; continue; }
    if (c === '(') depth++; if (c === ')') depth--;
    if (c === sep && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim() !== '' || out.length) out.push(cur);
  return out;
}

/* ----------------------------- search parser ------------------------------ */
// Tokenize a search expression into words, quoted strings, operators and parens.
function lexSearch(s) {
  const toks = []; let i = 0;
  const two = ['!=', '<=', '>=', '=~'];
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '(' || c === ')') { toks.push({ t: c }); i++; continue; }
    if (c === '"' || c === "'") { let j = i + 1, v = ''; while (j < s.length && s[j] !== c) v += s[j++]; i = j + 1; toks.push({ t: 'phrase', v }); continue; }
    const t2 = s.slice(i, i + 2);
    if (two.includes(t2)) { toks.push({ t: 'op', v: t2 }); i += 2; continue; }
    if (c === '=' || c === '<' || c === '>') { toks.push({ t: 'op', v: c }); i++; continue; }
    let j = i, w = '';
    while (j < s.length && !/[\s()"'=<>]/.test(s[j])) { w += s[j++]; }
    i = j;
    const up = w.toUpperCase();
    if (up === 'AND' || up === 'OR' || up === 'NOT') toks.push({ t: up });
    else toks.push({ t: 'word', v: w });
  }
  return toks;
}
function parseSearch(expr) {
  const toks = lexSearch(expr); let p = 0;
  const peek = () => toks[p], eat = () => toks[p++];
  function parseOr() { let l = parseAnd(); while (peek() && peek().t === 'OR') { eat(); const r = parseAnd(); const a = l, b = r; l = ev => a(ev) || b(ev); } return l; }
  function parseAnd() {
    let l = parseNot();
    while (peek() && peek().t !== 'OR' && peek().t !== ')') {
      if (peek().t === 'AND') eat();
      const r = parseNot(); const a = l, b = r; l = ev => a(ev) && b(ev);
    }
    return l;
  }
  function parseNot() { if (peek() && peek().t === 'NOT') { eat(); const a = parseAtom(); return ev => !a(ev); } return parseAtom(); }
  function parseAtom() {
    const tk = peek();
    if (!tk) return () => true;
    if (tk.t === '(') { eat(); const e = parseOr(); if (peek() && peek().t === ')') eat(); return e; }
    if (tk.t === 'word' && toks[p + 1] && toks[p + 1].t === 'op') {
      const field = eat().v, op = eat().v;
      const vt = peek() && (peek().t === 'word' || peek().t === 'phrase') ? eat() : { v: '' };
      return comparison(field, op, vt.v);
    }
    // bare term / phrase -> match against _raw (and any field value)
    const term = (tk.t === 'phrase' || tk.t === 'word') ? eat().v : (eat(), '');
    const re = /\*/.test(term) ? wildcardToRe('*' + term + '*') : null;
    const low = term.toLowerCase();
    return ev => { const hay = str(ev._raw || '').toLowerCase() + ' ' + Object.values(ev).map(str).join(' ').toLowerCase(); return re ? re.test(ev._raw || '') || Object.values(ev).some(v => re.test(str(v))) : hay.includes(low); };
  }
  function comparison(field, op, value) {
    const wild = /\*|\?/.test(value);
    const re = wild ? wildcardToRe(value) : null;
    return ev => {
      const has = Object.prototype.hasOwnProperty.call(ev, field);
      if (!has) return op === '!=' ? false : false;
      const fv = ev[field];
      if (op === '=' || op === '=~') return re ? re.test(str(fv)) : (isNumeric(fv) && isNumeric(value) ? num(fv) === num(value) : str(fv).toLowerCase() === str(value).toLowerCase());
      if (op === '!=') return !(re ? re.test(str(fv)) : (isNumeric(fv) && isNumeric(value) ? num(fv) === num(value) : str(fv).toLowerCase() === str(value).toLowerCase()));
      if (op === '<') return num(fv) < num(value);
      if (op === '>') return num(fv) > num(value);
      if (op === '<=') return num(fv) <= num(value);
      if (op === '>=') return num(fv) >= num(value);
      return false;
    };
  }
  const pred = parseOr();
  return typeof pred === 'function' ? pred : (() => true);
}

/* ------------------------- eval / where expressions ----------------------- */
function lexExpr(s) {
  const toks = []; let i = 0;
  const two = ['==', '!=', '<=', '>='];
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '"' || c === "'") { let j = i + 1, v = ''; while (j < s.length && s[j] !== c) v += s[j++]; i = j + 1; toks.push({ t: 'str', v }); continue; }
    if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(s[i + 1]))) { let j = i, v = ''; while (j < s.length && /[0-9.]/.test(s[j])) v += s[j++]; i = j; toks.push({ t: 'num', v: Number(v) }); continue; }
    const t2 = s.slice(i, i + 2);
    if (two.includes(t2)) { toks.push({ t: 'op', v: t2 }); i += 2; continue; }
    if ('+-*/.()<>=,'.includes(c)) { toks.push({ t: 'op', v: c }); i++; continue; }
    let j = i, w = '';
    while (j < s.length && /[A-Za-z0-9_]/.test(s[j])) w += s[j++];
    if (j === i) { i++; continue; }
    i = j;
    const up = w.toUpperCase();
    if (up === 'AND' || up === 'OR' || up === 'NOT') toks.push({ t: 'op', v: up === 'AND' ? '&&' : up === 'OR' ? '||' : '!' });
    else toks.push({ t: 'id', v: w });
  }
  return toks;
}
function parseExpr(s) {
  const toks = lexExpr(s); let p = 0;
  const peek = () => toks[p], eat = () => toks[p++];
  const isOp = v => peek() && peek().t === 'op' && peek().v === v;
  function or() { let l = and(); while (isOp('||')) { eat(); const r = and(); l = { op: '||', l, r }; } return l; }
  function and() { let l = not(); while (isOp('&&')) { eat(); const r = not(); l = { op: '&&', l, r }; } return l; }
  function not() { if (isOp('!')) { eat(); return { op: '!', r: not() }; } return cmp(); }
  function cmp() { let l = add(); while (peek() && peek().t === 'op' && ['==', '!=', '<', '>', '<=', '>=', '='].includes(peek().v)) { const op = eat().v; const r = add(); l = { op: op === '=' ? '==' : op, l, r }; } return l; }
  function add() { let l = mul(); while (peek() && peek().t === 'op' && ['+', '-', '.'].includes(peek().v)) { const op = eat().v; const r = mul(); l = { op, l, r }; } return l; }
  function mul() { let l = unary(); while (peek() && peek().t === 'op' && ['*', '/'].includes(peek().v)) { const op = eat().v; const r = unary(); l = { op, l, r }; } return l; }
  function unary() { if (isOp('-')) { eat(); return { op: 'neg', r: unary() }; } return primary(); }
  function primary() {
    const tk = peek();
    if (!tk) return { lit: null };
    if (tk.t === 'num') { eat(); return { lit: tk.v }; }
    if (tk.t === 'str') { eat(); return { lit: tk.v }; }
    if (isOp('(')) { eat(); const e = or(); if (isOp(')')) eat(); return e; }
    if (tk.t === 'id') {
      const name = eat().v;
      if (isOp('(')) { eat(); const args = []; if (!isOp(')')) { args.push(or()); while (isOp(',')) { eat(); args.push(or()); } } if (isOp(')')) eat(); return { fn: name.toLowerCase(), args }; }
      return { field: name };
    }
    eat(); return { lit: null };
  }
  return or();
}
function evalExpr(ast, row) {
  if (ast == null) return null;
  if ('lit' in ast) return ast.lit;
  if ('field' in ast) return Object.prototype.hasOwnProperty.call(row, ast.field) ? row[ast.field] : null;
  if ('fn' in ast) return callFn(ast.fn, ast.args.map(a => evalExpr(a, row)), row);
  const L = () => evalExpr(ast.l, row), R = () => evalExpr(ast.r, row);
  switch (ast.op) {
    case '||': return truthy(L()) || truthy(R());
    case '&&': return truthy(L()) && truthy(R());
    case '!': return !truthy(R());
    case 'neg': return -num(R());
    case '+': { const a = L(), b = R(); return (isNumeric(a) && isNumeric(b)) ? num(a) + num(b) : str(a) + str(b); }
    case '-': return num(L()) - num(R());
    case '*': return num(L()) * num(R());
    case '/': return num(L()) / num(R());
    case '.': return str(L()) + str(R());
    case '==': { const a = L(), b = R(); return (isNumeric(a) && isNumeric(b)) ? num(a) === num(b) : str(a).toLowerCase() === str(b).toLowerCase(); }
    case '!=': { const a = L(), b = R(); return (isNumeric(a) && isNumeric(b)) ? num(a) !== num(b) : str(a).toLowerCase() !== str(b).toLowerCase(); }
    case '<': return num(L()) < num(R());
    case '>': return num(L()) > num(R());
    case '<=': return num(L()) <= num(R());
    case '>=': return num(L()) >= num(R());
  }
  return null;
}
const truthy = v => v === true || (typeof v === 'number' && v !== 0) || (typeof v === 'string' && v !== '' && v !== '0' && v.toLowerCase() !== 'false');
function callFn(name, a, row) {
  switch (name) {
    case 'lower': return str(a[0]).toLowerCase();
    case 'upper': return str(a[0]).toUpperCase();
    case 'len': return str(a[0]).length;
    case 'round': return a[1] != null ? Number(num(a[0]).toFixed(num(a[1]))) : Math.round(num(a[0]));
    case 'abs': return Math.abs(num(a[0]));
    case 'floor': return Math.floor(num(a[0]));
    case 'ceil': case 'ceiling': return Math.ceil(num(a[0]));
    case 'if': return truthy(a[0]) ? a[1] : a[2];
    case 'coalesce': return a.find(x => x != null && x !== '') ?? null;
    case 'tostring': return str(a[0]);
    case 'tonumber': return isNumeric(a[0]) ? num(a[0]) : null;
    case 'substr': return str(a[0]).substr(num(a[1]) - 1, a[2] != null ? num(a[2]) : undefined);
    case 'isnull': return a[0] == null || a[0] === '';
    case 'isnotnull': return !(a[0] == null || a[0] === '');
    case 'like': return wildcardToRe(str(a[1]).replace(/%/g, '*').replace(/_/g, '?')).test(str(a[0]));
    case 'match': { try { return new RegExp(str(a[1])).test(str(a[0])); } catch (e) { return false; } }
    case 'max': return Math.max(...a.map(num));
    case 'min': return Math.min(...a.map(num));
    default: return null;
  }
}

/* --------------------------- pipeline commands ---------------------------- */
const AGG = {
  count: g => g.length,
  dc: (g, f) => new Set(g.map(r => str(r[f])).filter(x => x !== '')).size,
  distinct_count: (g, f) => AGG.dc(g, f),
  sum: (g, f) => g.reduce((s, r) => s + (isNumeric(r[f]) ? num(r[f]) : 0), 0),
  avg: (g, f) => { const n = g.filter(r => isNumeric(r[f])); return n.length ? Math.round((n.reduce((s, r) => s + num(r[f]), 0) / n.length) * 100) / 100 : 0; },
  min: (g, f) => Math.min(...g.filter(r => isNumeric(r[f])).map(r => num(r[f]))),
  max: (g, f) => Math.max(...g.filter(r => isNumeric(r[f])).map(r => num(r[f]))),
  values: (g, f) => [...new Set(g.map(r => str(r[f])).filter(x => x !== ''))].sort().join(', '),
  list: (g, f) => g.map(r => str(r[f])).filter(x => x !== '').join(', '),
  first: (g, f) => g.length ? g[0][f] : null,
  last: (g, f) => g.length ? g[g.length - 1][f] : null
};
function cmd_stats(state, arg) {
  // arg: "<func[(field)] [as name]> ... [by f1,f2]"  (specs are space- or comma-separated)
  let by = [];
  const byM = arg.match(/\bby\b\s+(.+)$/i);
  if (byM) { by = byM[1].split(/[\s,]+/).map(s => s.trim()).filter(Boolean); arg = arg.slice(0, byM.index); }
  const tokens = (arg.replace(/,/g, ' ').match(/\w+\s*\([^)]*\)|\bas\b|[\w()]+/gi) || []).map(t => t.trim());
  const specs = [];
  for (let i = 0; i < tokens.length;) {
    const s = tokens[i++]; let name = null;
    if (tokens[i] && tokens[i].toLowerCase() === 'as' && tokens[i + 1]) { name = tokens[i + 1]; i += 2; }
    const m = s.match(/^(\w+)\s*(?:\(\s*([^)]*)\s*\))?$/);
    if (!m) continue;
    const fn = m[1].toLowerCase(), field = m[2] ? m[2].trim() : null;
    specs.push({ fn, field, name: name || (field ? fn + '(' + field + ')' : fn) });
  }
  const groups = new Map();
  for (const r of state.rows) { const key = by.map(f => str(r[f])).join('\u0001'); if (!groups.has(key)) groups.set(key, []); groups.get(key).push(r); }
  const rows = [];
  for (const [key, g] of groups) {
    const row = {}; const parts = key.split('\u0001'); by.forEach((f, i) => row[f] = parts[i]);
    for (const sp of specs) { const fn = AGG[sp.fn]; row[sp.name] = fn ? fn(g, sp.field) : null; }
    rows.push(row);
  }
  return { rows, columns: [...by, ...specs.map(s => s.name)] };
}
function cmd_where(state, arg) { const ast = parseExpr(arg); return { rows: state.rows.filter(r => truthy(evalExpr(ast, r))), columns: state.columns }; }
function cmd_eval(state, arg) {
  const eq = firstTopLevelEq(arg); if (eq < 0) return state;
  const name = arg.slice(0, eq).trim(), ast = parseExpr(arg.slice(eq + 1));
  const rows = state.rows.map(r => ({ ...r, [name]: evalExpr(ast, r) }));
  const columns = state.columns.includes(name) ? state.columns : [...state.columns, name];
  return { rows, columns };
}
function firstTopLevelEq(s) { for (let i = 0; i < s.length; i++) { const c = s[i]; if (c === '=' && s[i - 1] !== '!' && s[i - 1] !== '<' && s[i - 1] !== '>' && s[i + 1] !== '=') return i; } return -1; }
function cmd_fields(state, arg, keep) {
  let remove = false; arg = arg.trim();
  if (arg[0] === '-') { remove = true; arg = arg.slice(1); } else if (arg[0] === '+') arg = arg.slice(1);
  const list = arg.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
  if (remove) return { rows: state.rows, columns: state.columns.filter(c => !list.includes(c)) };
  return { rows: state.rows, columns: list };
}
function cmd_rename(state, arg) {
  const m = arg.match(/^(\w+)\s+as\s+(\w+)$/i); if (!m) return state;
  const [, from, to] = m;
  const rows = state.rows.map(r => { const n = { ...r }; if (from in n) { n[to] = n[from]; delete n[from]; } return n; });
  return { rows, columns: state.columns.map(c => c === from ? to : c) };
}
function cmd_sort(state, arg) {
  let limit = 0; arg = arg.trim();
  const lm = arg.match(/^(\d+)\s+(.+)/); if (lm) { limit = Number(lm[1]); arg = lm[2]; }
  const keys = arg.split(',').map(s => s.trim()).filter(Boolean).map(s => { let dir = 1; if (s[0] === '-') { dir = -1; s = s.slice(1); } else if (s[0] === '+') s = s.slice(1); return { f: s.trim(), dir }; });
  const rows = state.rows.slice().sort((a, b) => {
    for (const k of keys) { const av = a[k.f], bv = b[k.f]; let c; if (isNumeric(av) && isNumeric(bv)) c = num(av) - num(bv); else c = str(av).localeCompare(str(bv)); if (c) return c * k.dir; }
    return 0;
  });
  return { rows: limit ? rows.slice(0, limit) : rows, columns: state.columns };
}
function cmd_topRare(state, arg, rare) {
  let n = 10; arg = arg.trim();
  const nm = arg.match(/^(\d+)\s+(.+)/); if (nm) { n = Number(nm[1]); arg = nm[2]; }
  let by = []; const byM = arg.match(/\bby\b\s+(.+)$/i); if (byM) { by = byM[1].split(',').map(s => s.trim()); arg = arg.slice(0, byM.index).trim(); }
  const field = arg.trim();
  const groups = new Map();
  for (const r of state.rows) { const key = [str(r[field]), ...by.map(f => str(r[f]))].join('\u0001'); groups.set(key, (groups.get(key) || 0) + 1); }
  const total = state.rows.length || 1;
  let rows = [...groups].map(([key, count]) => { const parts = key.split('\u0001'); const row = { [field]: parts[0] }; by.forEach((f, i) => row[f] = parts[i + 1]); row.count = count; row.percent = Math.round((count / total) * 1000) / 10; return row; });
  rows.sort((a, b) => rare ? a.count - b.count : b.count - a.count);
  return { rows: rows.slice(0, n), columns: [field, ...by, 'count', 'percent'] };
}
function cmd_dedup(state, arg) {
  const fields = arg.split(/[\s,]+/).map(s => s.trim()).filter(Boolean); const seen = new Set(); const rows = [];
  for (const r of state.rows) { const key = fields.map(f => str(r[f])).join('\u0001'); if (!seen.has(key)) { seen.add(key); rows.push(r); } }
  return { rows, columns: state.columns };
}

const COMMANDS = {
  stats: cmd_stats, where: cmd_where, eval: cmd_eval,
  table: (s, a) => cmd_fields(s, a, true), fields: (s, a) => cmd_fields(s, a, false),
  rename: cmd_rename, sort: cmd_sort,
  head: (s, a) => ({ rows: s.rows.slice(0, Number(a.trim()) || 10), columns: s.columns }),
  tail: (s, a) => ({ rows: s.rows.slice(-(Number(a.trim()) || 10)), columns: s.columns }),
  top: (s, a) => cmd_topRare(s, a, false), rare: (s, a) => cmd_topRare(s, a, true),
  dedup: cmd_dedup
};

const DEFAULT_COLUMNS = ['_time', 'index', 'host', 'user', 'src_ip', 'dest_ip', 'action', 'signature'];

// Run an SPL query over an array of event objects. Returns { ok, rows, columns,
// type: 'events'|'table', error? }. The first stage is an implicit `search`.
function runSpl(events, query) {
  try {
    const stages = splitTopLevel(String(query || ''), '|').map(s => s.trim());
    while (stages.length && stages[stages.length - 1] === '') stages.pop();   // tolerate a trailing pipe
    if (!stages.length) return { ok: true, rows: events.slice(), columns: DEFAULT_COLUMNS, type: 'events' };
    let first = stages[0];                                                    // may be '' when the query starts with '|'
    if (/^search\s/i.test(first)) first = first.replace(/^search\s/i, '').trim();
    const pred = first ? parseSearch(first) : () => true;
    let state = { rows: events.filter(pred), columns: DEFAULT_COLUMNS, type: 'events' };
    for (let k = 1; k < stages.length; k++) {
      const st = stages[k]; if (!st) continue; const sp = st.indexOf(' ');
      const name = (sp < 0 ? st : st.slice(0, sp)).toLowerCase();
      const arg = sp < 0 ? '' : st.slice(sp + 1).trim();
      const fn = COMMANDS[name];
      if (!fn) return { ok: false, error: 'Unknown command: ' + name, rows: [], columns: [] };
      const next = fn(state, arg);
      state = { rows: next.rows, columns: next.columns, type: ['stats', 'top', 'rare', 'table', 'rename'].includes(name) ? 'table' : (name === 'fields' ? 'table' : state.type) };
    }
    return { ok: true, rows: state.rows, columns: state.columns, type: state.type };
  } catch (e) {
    return { ok: false, error: e.message, rows: [], columns: [] };
  }
}

module.exports = { runSpl, parseSearch, parseExpr, evalExpr, DEFAULT_COLUMNS };
