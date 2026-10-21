/** PrimeSEC mark: shield outline with a "P" cut-out. */
export function LogoMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" aria-hidden="true">
      <path d="M20 3 33 8v10c0 8.5-5.6 15.2-13 19-7.4-3.8-13-10.5-13-19V8L20 3Z" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round" />
      <path d="M15 28V13h6.2a4.6 4.6 0 0 1 0 9.2H15" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="nav-logo">
      <span className="logo-glyph"><LogoMark size={22} /></span>
      PrimeSEC
    </span>
  );
}
