/** Tiny in-memory sliding-window limiter (per server process). Enough to stop an accidental or abusive loop. */
const hits = new Map<string, number[]>();
let lastSweep = 0;

export function allowRequest(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  // Evict idle keys now and then so the map cannot grow without bound.
  if (now - lastSweep > 60_000) {
    lastSweep = now;
    for (const [k, times] of hits) if (times.every((t) => now - t >= windowMs)) hits.delete(k);
  }
  const recent = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (recent.length >= max) {
    hits.set(key, recent);
    return false;
  }
  recent.push(now);
  hits.set(key, recent);
  return true;
}
