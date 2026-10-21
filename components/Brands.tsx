const ICON = { width: 22, height: 22, viewBox: "0 0 24 24", "aria-hidden": true } as const;

export default function Brands() {
  return (
    <div className="brands">
      <div className="brand-item">
        <svg {...ICON}><path fill="currentColor" d="M3 4h12a6 6 0 0 1 0 12H9l-6 4V4Z" /><circle cx="9" cy="10" r="1.6" fill="var(--bg)" /></svg>
        Wazuh
      </div>
      <div className="brand-item">
        <svg {...ICON} fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="3.5" /><path d="M12 3v3M12 18v3M3 12h3M18 12h3" /></svg>
        OpenCTI
      </div>
      <div className="brand-item">
        <svg {...ICON} fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3 4 7v5c0 5 3.5 8 8 9 4.5-1 8-4 8-9V7l-8-4Z" /><path d="m9 12 2 2 4-4" /></svg>
        Greenbone
      </div>
      <div className="brand-item">
        <svg {...ICON} fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></svg>
        Keycloak
      </div>
      <div className="brand-item">
        <svg {...ICON} fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a4 4 0 0 0-4 4 4 4 0 0 0-3 6.5A4 4 0 0 0 9 20h6a4 4 0 0 0 4-6.5A4 4 0 0 0 16 7a4 4 0 0 0-4-4Z" /><path d="M12 8v8M9 12h6" /></svg>
        CyberReasoner
      </div>
    </div>
  );
}
