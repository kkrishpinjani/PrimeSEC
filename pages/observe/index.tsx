import Head from "next/head";
import type { GetServerSideProps } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, PRIMESEC_ROLES } from "../../lib/auth";
import ObserveWorkspace from "../../components/ObserveWorkspace";

type Props = { user: { name?: string | null; email?: string | null }; roles: string[]; jaegerUrl: string; prometheusUrl: string };

export default function Observe(props: Props) {
  return (
    <>
      <Head>
        <title>Observe | PrimeSEC</title>
        <meta name="robots" content="noindex" />
      </Head>
      <main className="dash-page">
        <ObserveWorkspace {...props} />
      </main>
    </>
  );
}

export const getServerSideProps: GetServerSideProps<Props> = async (context) => {
  const session = await getServerSession(context.req, context.res, authOptions);
  if (!session) return { redirect: { destination: "/login", permanent: false } };
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) return { redirect: { destination: "/403", permanent: false } };
  // Browser-facing links are only ever the configured values or the local defaults, and must be http(s).
  const safe = (v: string | undefined, fallback: string) => (v && /^https?:\/\//i.test(v.trim()) ? v.trim() : fallback);
  return {
    props: {
      user: { name: session.user?.name ?? null, email: session.user?.email ?? null }, roles,
      jaegerUrl: safe(process.env.JAEGER_QUERY_URL_BROWSER, "http://localhost:16686"),
      prometheusUrl: safe(process.env.PROMETHEUS_URL_BROWSER, "http://localhost:9090")
    }
  };
};
