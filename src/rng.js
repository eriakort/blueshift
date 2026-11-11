// BlueShift — deterministic seeded PRNG.
// Everything in the synthetic SOC environment is generated from a seed so the
// world is fully reproducible (same seed -> same alerts), which keeps scenarios
// fair and the test suite stable. No Math.random anywhere in the model.

// mulberry32: a tiny, fast, well-distributed 32-bit PRNG.
function makeRng(seed) {
  let a = (seed >>> 0) || 1;
  const next = () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const api = {
    float: next,
    int: (lo, hi) => lo + Math.floor(next() * (hi - lo + 1)),      // inclusive
    chance: p => next() < p,
    pick: arr => arr[Math.floor(next() * arr.length)],
    weighted: pairs => {                                           // [[value, weight], ...]
      const total = pairs.reduce((s, [, w]) => s + w, 0);
      let r = next() * total;
      for (const [v, w] of pairs) { if ((r -= w) < 0) return v; }
      return pairs[pairs.length - 1][0];
    },
    shuffle: arr => { const a2 = arr.slice(); for (let i = a2.length - 1; i > 0; i--) { const j = Math.floor(next() * (i + 1)); [a2[i], a2[j]] = [a2[j], a2[i]]; } return a2; },
    sample: (arr, n) => api.shuffle(arr).slice(0, n)
  };
  return api;
}

module.exports = { makeRng };
