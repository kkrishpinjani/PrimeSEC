import { useEffect, useRef } from "react";
import { LogoMark } from "./Logo";

type Phase = "p1" | "splash" | "p2" | "idle";
const DURATION: Record<Phase, number> = { p1: 800, splash: 800, p2: 800, idle: 1000 };

/** Icon pipeline: layers -> PrimeSEC -> shield, with a beam driven by a rAF state machine. */
export default function HeroPipeline() {
  const pipelineRef = useRef<HTMLDivElement>(null);
  const stackRef = useRef<HTMLDivElement>(null);
  const xRef = useRef<HTMLDivElement>(null);
  const shieldRef = useRef<HTMLDivElement>(null);
  const glowPathRef = useRef<SVGPathElement>(null);
  const corePathRef = useRef<SVGPathElement>(null);
  const gradientRef = useRef<SVGLinearGradientElement>(null);
  const splashRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const pipeline = pipelineRef.current, nodeStack = stackRef.current, nodeX = xRef.current;
    const nodeShield = shieldRef.current, glowPath = glowPathRef.current, corePath = corePathRef.current;
    const gradient = gradientRef.current, splash = splashRef.current;
    if (!pipeline || !nodeStack || !nodeX || !nodeShield || !glowPath || !corePath || !gradient || !splash) return;

    const center = (el: HTMLElement, p: DOMRect) => {
      const r = el.getBoundingClientRect();
      return { x: r.left + r.width / 2 - p.left, y: r.top + r.height / 2 - p.top };
    };

    let startX = 0, endX = 0;
    const updatePath = () => {
      const p = pipeline.getBoundingClientRect();
      const s = center(nodeStack, p), m = center(nodeX, p), e = center(nodeShield, p);
      startX = s.x; endX = e.x;
      const d = `M ${s.x},${s.y} L ${m.x},${m.y} L ${e.x},${e.y}`;
      glowPath.setAttribute("d", d);
      corePath.setAttribute("d", d);
      gradient.setAttribute("y1", String(s.y));
      gradient.setAttribute("y2", String(s.y));
    };
    updatePath();
    window.addEventListener("resize", updatePath);

    const setBeam = (pct: number) => {
      // The bright window slides along the beam; positions in user space (px) so it tracks the path exactly.
      const x = startX + (endX - startX) * pct;
      const half = (endX - startX) * 0.05 + 8;
      gradient.setAttribute("x1", String(x - half));
      gradient.setAttribute("x2", String(x + half));
    };
    const showBeam = (v: boolean) => {
      glowPath.style.opacity = v ? "0.6" : "0";
      corePath.style.opacity = v ? "1" : "0";
    };

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) { setBeam(0.5); showBeam(true); }

    let phase: Phase = "p1";
    let last = performance.now();
    let raf = 0;

    const tick = (now: number) => {
      raf = requestAnimationFrame(tick);
      if (reduced) return;
      const elapsed = now - last;
      const t = Math.min(elapsed / DURATION[phase], 1);

      if (phase === "p1") {
        const pct = t * 0.5;
        setBeam(pct);
        nodeStack.classList.toggle("active", pct < 0.4);
        if (elapsed >= DURATION.p1) {
          nodeStack.classList.remove("active");
          phase = "splash"; last = now;
          showBeam(false);
          splash.classList.add("animate");
        }
      } else if (phase === "splash") {
        if (elapsed >= DURATION.splash) {
          phase = "p2"; last = now;
          splash.classList.remove("animate");
          showBeam(true);
        }
      } else if (phase === "p2") {
        const pct = 0.5 + t * 0.5;
        setBeam(pct);
        nodeShield.classList.toggle("active", pct > 0.6);
        if (elapsed >= DURATION.p2) {
          nodeShield.classList.remove("active");
          phase = "idle"; last = now;
        }
      } else if (elapsed >= DURATION.idle) {
        phase = "p1"; last = now;
      }
    };
    setBeam(0);
    raf = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", updatePath);
    };
  }, []);

  return (
    <div className="icon-pipeline" ref={pipelineRef}>
      <svg className="beam-svg" aria-hidden="true">
        <defs>
          <filter id="glow" filterUnits="userSpaceOnUse" x="-10%" y="-300%" width="120%" height="700%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
          <linearGradient id="beam-gradient" gradientUnits="userSpaceOnUse" ref={gradientRef} x1="0" x2="0" y1="0" y2="0">
            <stop offset="0%" stopColor="#0d9488" stopOpacity="0" />
            <stop offset="20%" stopColor="#14b8a6" stopOpacity="0.8" />
            <stop offset="50%" stopColor="#ffffff" stopOpacity="1" />
            <stop offset="80%" stopColor="#99f6e4" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#99f6e4" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path ref={glowPathRef} fill="none" stroke="url(#beam-gradient)" strokeWidth="2" filter="url(#glow)" style={{ opacity: 0.6 }} />
        <path ref={corePathRef} fill="none" stroke="url(#beam-gradient)" strokeWidth="0.8" />
      </svg>

      <div className="icon-node node-light-right" id="node-stack" ref={stackRef} title="Ingest">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <polygon points="12 2 2 7 12 12 22 7 12 2" />
          <polyline points="2 17 12 22 22 17" />
          <polyline points="2 12 12 17 22 12" />
        </svg>
      </div>

      <div className="pipeline-line" />

      <div style={{ position: "relative" }}>
        <div className="splash" ref={splashRef} />
        <div className="icon-node-center" id="node-x" ref={xRef} title="PrimeSEC">
          <LogoMark size={30} />
        </div>
      </div>

      <div className="pipeline-line right" />

      <div className="icon-node node-light-left" id="node-shield" ref={shieldRef} title="Protect">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <polyline points="9 12 11 14 15 10" />
        </svg>
      </div>
    </div>
  );
}
