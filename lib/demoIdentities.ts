/** Demo identities (local demos only). Safe to import from the browser: no server code, no secrets. */
export const DEMO_IDENTITIES: Record<string, { name: string; email: string; label: string }> = {
  SOC_Admin: { name: "Demo Admin", email: "demo-admin@primesec.local", label: "Admin" },
  SOC_Analyst: { name: "Demo Analyst", email: "demo-analyst@primesec.local", label: "Analyst" },
  SOC_ReadOnly: { name: "Demo Viewer", email: "demo-readonly@primesec.local", label: "Read-only" }
};
