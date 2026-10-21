import Head from "next/head";
import dynamic from "next/dynamic";
import Link from "next/link";
import { motion } from "framer-motion";
import Navbar from "../components/Navbar";
import HeroPipeline from "../components/HeroPipeline";
import Brands from "../components/Brands";

const Globe = dynamic(() => import("../components/Globe"), { ssr: false });

const fade = (i: number) => ({
  initial: { opacity: 0, y: 24 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.7, delay: 0.1 + i * 0.12, ease: [0.22, 1, 0.36, 1] as const }
});

export default function Landing() {
  return (
    <>
      <Head>
        <title>PrimeSEC | AI-powered security operations</title>
        <meta name="description" content="PrimeSEC unifies Wazuh, OpenCTI and Greenbone into one AI-assisted security operations workspace with single sign-on." />
      </Head>
      <main className="page">
        <Navbar />

        <section className="hero-card" id="platform">
          <div className="hero-arc" />
          <div className="hero-grid" />
          <div className="hero-beams" aria-hidden="true"><i /><i /><i /></div>

          <motion.div {...fade(0)} style={{ zIndex: 1 }}><HeroPipeline /></motion.div>

          <div className="hero-content">
            <motion.span {...fade(1)} className="hero-pill">AI-powered security operations platform</motion.span>
            <motion.h1 {...fade(2)} className="hero-heading">
              Detect, investigate and
              <strong>stop threats fast</strong>
            </motion.h1>
            <motion.p {...fade(3)} className="hero-sub">
              PrimeSEC brings endpoint alerts, threat intelligence and vulnerability<br />
              assessment into one workspace, behind a single sign-on.
            </motion.p>
            <motion.div {...fade(4)} className="hero-ctas">
              <Link href="/login" className="btn-cta">Start monitoring</Link>
              <a href="#intelligence" className="btn-ghost">Book a demo</a>
            </motion.div>
          </div>

          <motion.div {...fade(5)} className="hero-globe" aria-hidden="true">
            <div className="pv-globe-glow" />
            <Globe className="pv-canvas" />
          </motion.div>
        </section>

        <div id="intelligence">
          <p className="brands-title">Integrates with the tools your SOC already runs</p>
          <Brands />
        </div>
      </main>
    </>
  );
}
