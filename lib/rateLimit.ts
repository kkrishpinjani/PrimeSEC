/** Tiny in-memory sliding-window limiter (per server process). Enough to stop an accidental or abusive loop. */
const hits = new Map<string, number[]>();

export function allowRequest(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const recent = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (recent.length >= max) {
    hits.set(key, recent);
    return false;
  }
  recent.push(now);
  hits.set(key, recent);
  return true;
}
