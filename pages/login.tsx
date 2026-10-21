import Head from "next/head";
import Link from "next/link";
import type { GetServerSideProps } from "next";
import { getServerSession } from "next-auth/next";
import { signIn } from "next-auth/react";
import { motion } from "framer-motion";
import { authOptions, demoLoginEnabled } from "../lib/auth";
import { DEMO_IDENTITIES } from "../lib/demoIdentities";
import { LogoMark } from "../components/Logo";
import HeroPipeline from "../components/HeroPipeline";

export default function Login({ demo }: { demo: boolean }) {
  return (
    <>
      <Head><title>Sign in | PrimeSEC</title></Head>
      <main className="login-page">
        <div className="login-arc" />
        <motion.div
          className="login-panel"
          initial={{ opacity: 0, y: 30, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
        >
          <Link href="/" className="login-brand"><LogoMark size={26} /> PrimeSEC</Link>
          <HeroPipeline />
          <p className="eyebrow">Secure access</p>
          <h1>Security starts with a trusted identity.</h1>
          <p className="muted">Sign in through your organization&apos;s identity provider.</p>
          <button className="btn-cta btn-full" onClick={() => signIn("keycloak", { callbackUrl: "/dashboard" })}>
            Continue with Keycloak <span aria-hidden="true">→</span>
          </button>
          {demo && (
            <div className="login-demo-group">
              <p className="login-demo-title">Demo sign-in (local only, no Keycloak)</p>
              <div className="login-demo-buttons">
                {Object.entries(DEMO_IDENTITIES).map(([role, who]) => (
                  <button key={role} className="btn-ghost login-demo" title={`Sign in as ${who.name} (${role})`} onClick={() => signIn("demo", { role, callbackUrl: "/dashboard" })}>
                    {who.label}
                    <small>{role}</small>
                  </button>
                ))}
              </div>
            </div>
          )}
          <p className="login-footnote">Protected by centralized authentication (OIDC)</p>
        </motion.div>
      </main>
    </>
  );
}

export const getServerSideProps: GetServerSideProps = async (context) => {
  const session = await getServerSession(context.req, context.res, authOptions);
  if (session) return { redirect: { destination: "/dashboard", permanent: false } };
  return { props: { demo: demoLoginEnabled() } };
};
