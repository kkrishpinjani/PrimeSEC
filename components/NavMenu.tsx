import Link from "next/link";
import { useEffect, useRef, useState } from "react";

export type NavItem = { label: string; href: string; hint?: string; external?: boolean; disabled?: boolean };
export type NavGroup = { title: string; items: NavItem[] };

/** A small accessible dropdown: opens on click, closes on outside click, Escape, or choosing an item. */
export default function NavMenu({ label, groups }: { label: string; groups: NavGroup[] }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { if (root.current && !root.current.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey); };
  }, [open]);

  return (
    <div className="pv-menu" ref={root}>
      <button type="button" className={`pv-btn pv-menu-btn ${open ? "on" : ""}`} aria-haspopup="true" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        {label} <span aria-hidden="true">▾</span>
      </button>
      {open && (
        <div className="pv-menu-panel" role="menu">
          {groups.map((g) => (
            <div className="pv-menu-group" key={g.title}>
              <small>{g.title}</small>
              {g.items.map((i) => i.disabled
                ? <span key={i.label} className="pv-menu-item off" role="menuitem" aria-disabled="true" title={i.hint}>{i.label}<em>{i.hint}</em></span>
                : i.external
                  ? <a key={i.label} className="pv-menu-item" role="menuitem" href={i.href} target="_blank" rel="noreferrer" onClick={() => setOpen(false)}>{i.label} ↗<em>{i.hint}</em></a>
                  : <Link key={i.label} className="pv-menu-item" role="menuitem" href={i.href} onClick={() => setOpen(false)}>{i.label}<em>{i.hint}</em></Link>)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
