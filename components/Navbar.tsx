import Link from "next/link";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { Wordmark } from "./Logo";

export default function Navbar() {
  const [open, setOpen] = useState(false);
  const { status } = useSession();
  const signedIn = status === "authenticated";

  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [open]);

  const close = () => setOpen(false);

  return (
    <nav className="nav">
      <Link href="/" aria-label="PrimeSEC home"><Wordmark /></Link>

      <div className={`nav-menu${open ? " active" : ""}`}>
        <ul className="nav-links">
          <li><a href="#platform" onClick={close}>Platform</a></li>
          <li><a href="#intelligence" onClick={close}>Intelligence</a></li>
          <li><a href="#pricing" onClick={close}>Pricing</a></li>
          <li><a href="#docs" onClick={close}>Docs</a></li>
        </ul>
        <div className="nav-actions">
          {signedIn ? (
            <Link href="/dashboard" className="btn-signup" onClick={close}>Dashboard</Link>
          ) : (
            <>
              <Link href="/login" className="btn-login" onClick={close}>Sign in</Link>
              <Link href="/login" className="btn-signup" onClick={close}>Get started</Link>
            </>
          )}
        </div>
      </div>

      <button
        className={`menu-toggle${open ? " active" : ""}`}
        aria-label={open ? "Close menu" : "Open menu"}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <span /><span />
      </button>
    </nav>
  );
}
