#!/usr/bin/env node
// BlueShift — build. Inlines the TESTED source modules + the UI + styles into a
// single self-contained dist/index.html via a tiny CommonJS require() shim, so
// the shipped page is byte-for-byte a function of the source (no drift) and runs
// offline with no dependencies, build step or network.
const fs = require('fs');
const path = require('path');
const read = f => fs.readFileSync(path.join(__dirname, f), 'utf8');

// Order matters: a module must be defined before anything that requires it runs.
const MODULES = ['src/rng.js', 'src/catalog.js', 'src/model.js', 'src/ui.js'];
const wrap = f => `__def(${JSON.stringify('./' + path.basename(f, '.js'))}, function(module, exports, require){\n${read(f)}\n});`;

const bundle = `
var __mods = {};
function __def(id, fn){ var m = { exports: {} }; fn(m, m.exports, require); __mods[id] = m; }
function require(id){ if(!__mods[id]) throw new Error('module not found: '+id); return __mods[id].exports; }
${MODULES.map(wrap).join('\n')}
require('./ui');
`;

const styles = read('src/styles.css');
const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>BlueShift — SOC Analyst Range</title>
<meta name="description" content="BlueShift: a fully simulated SOC analyst training range. Triage SIEM alerts, map them to MITRE ATT&CK, and grade your dispositions against ground truth. Offline, deterministic, no backend."/>
<style>${styles}</style>
</head>
<body><div id="app"></div><script>${bundle}</script></body>
</html>`;

const out = path.join(__dirname, 'dist', 'index.html');
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, html);
console.log('Built ' + path.relative(__dirname, out) + ' (' + html.length + ' bytes).');
