/**
 * Next.js instrumentation hook. The Node-only code lives in instrumentation-node.ts and is imported inside a plain
 * `NEXT_RUNTIME === "nodejs"` check, which is the form webpack can prove is dead code for the Edge bundle.
 */
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./instrumentation-node");
  }
}
