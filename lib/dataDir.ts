import path from "path";

/**
 * Where PrimeSEC keeps its own JSON stores and the audit log. Defaults to ./data. Setting PRIMESEC_DATA_DIR (for example to
 * "data-demo" for the rich demo, see scripts/dev-demo.ps1) points every store at a separate folder, so demo records never mix
 * with real ones.
 */
export function dataPath(...parts: string[]): string {
  const base = process.env.PRIMESEC_DATA_DIR?.trim() || "data";
  return path.join(path.isAbsolute(base) ? base : path.join(process.cwd(), base), ...parts);
}
