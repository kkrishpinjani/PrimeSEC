/**
 * Shared helpers for the rich demo dataset. Everything here is deterministic (seeded), so the demo looks the same on every
 * start and screenshots / videos can be repeated. Nothing in the demo dataset is real telemetry.
 */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function makeRandom(seed) {
  const r = rng(seed);
  const int = (a, b) => a + Math.floor(r() * (b - a + 1));
  const pick = (arr) => arr[Math.floor(r() * arr.length)];
  const chance = (p) => r() < p;
  const weighted = (items) => {
    const sum = items.reduce((s, [, w]) => s + w, 0);
    let x = r() * sum;
    for (const [v, w] of items) { x -= w; if (x <= 0) return v; }
    return items[items.length - 1][0];
  };
  const hex = (n) => Array.from({ length: n }, () => "0123456789abcdef"[Math.floor(r() * 16)]).join("");
  const shuffle = (arr) => { const a = arr.slice(); for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };
  return { r, int, pick, chance, weighted, hex, shuffle };
}

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const iso = (ms) => new Date(ms).toISOString();
const agoIso = (minutes) => iso(Date.now() - minutes * MIN);

/** Stable short id from a string (used for entity ids so they never change between runs). */
function stableId(prefix, key) {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < key.length; i++) {
    const ch = key.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const n = (h2 >>> 0).toString(16).padStart(8, "0") + (h1 >>> 0).toString(16).padStart(8, "0");
  return `${prefix}-${n.slice(0, 8)}-${n.slice(8, 12)}-${n.slice(12, 16)}`;
}

module.exports = { rng, makeRandom, MIN, HOUR, DAY, iso, agoIso, stableId };
