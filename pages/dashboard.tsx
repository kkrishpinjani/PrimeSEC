import Head from "next/head";
import type { GetServerSideProps } from "next";
import { getServerSession } from "next-auth/next";
import { fullSignOut } from "../lib/signOutClient";
import { authOptions, PRIMESEC_ROLES } from "../lib/auth";
import SocDashboard from "../components/SocDashboard";
import { getDashboardData, type DashboardData } from "../lib/dashboardData";

type Props = {
  user: { name?: string | null; email?: string | null };
  roles: string[];
  /** Links to the platforms' own interfaces. A link is greyed out, with the reason, when its platform is not running. */
  platforms: PlatformLink[];
  data: DashboardData;
};

export default function Dashboard({ user, roles, platforms, data }: Props) {
  return (
    <>
      <Head>
        <title>Dashboard | PrimeSEC</title>
        <meta name="robots" content="noindex" />
      </Head>
      <main className="dash-page">
        <SocDashboard
          data={data}
          user={user}
          roles={roles}
          platforms={platforms}
          onSignOut={() => void fullSignOut()}
        />
      </main>
    </>
  );
}

export type PlatformLink = { name: string; url: string; hint: string; /** null = not probed (assumed up) */ up: boolean | null; offHint: string };

/** A quick, quiet reachability probe. Never throws; a platform that does not answer in 1.5 s counts as down. */
async function reachable(url: string): Promise<boolean> {
  if (!url) return false;
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(1500) });
    return r.status < 500;
  } catch {
    return false;
  }
}
const base = (v: string | undefined) => String(v || "").trim().replace(/\/+$/, "");

async function platformLinks(): Promise<PlatformLink[]> {
  const [greenbone, opencti, neo4j] = await Promise.all([
    reachable(base(process.env.GREENBONE_BRIDGE_URL) && `${base(process.env.GREENBONE_BRIDGE_URL)}/health`),
    reachable(base(process.env.OPENCTI_URL)),
    reachable(base(process.env.NEO4J_HTTP_URL))
  ]);
  return [
    // Wazuh's dashboard uses its own certificate, which a server-side probe would reject; its stack is not one that gets swapped out.
    { name: "Wazuh", url: process.env.WAZUH_DASHBOARD_URL || "", hint: "Dashboard, agents, alerts", up: null, offHint: "Set WAZUH_DASHBOARD_URL in .env" },
    { name: "Greenbone", url: process.env.GREENBONE_DASHBOARD_URL || "", hint: "Scans and reports", up: greenbone, offHint: "Not running. Start it with: scripts\\stacks.ps1 use-greenbone" },
    { name: "OpenCTI", url: process.env.OPENCTI_DASHBOARD_URL || "", hint: "Threat intelligence platform", up: opencti, offHint: "Not running. Start it with: scripts\\stacks.ps1 use-opencti" },
    { name: "Neo4j", url: process.env.NEO4J_BROWSER_URL || "", hint: "Graph browser (login: neo4j)", up: neo4j, offHint: "Not running. Start it in infra\\neo4j: docker compose up -d" }
  ];
}

export const getServerSideProps: GetServerSideProps<Props> = async (context) => {
  const session = await getServerSession(context.req, context.res, authOptions);
  if (!session) return { redirect: { destination: "/login", permanent: false } };
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) {
    return { redirect: { destination: "/403", permanent: false } };
  }
  return {
    props: {
      user: { name: session.user?.name ?? null, email: session.user?.email ?? null },
      roles,
      platforms: await platformLinks(),
      data: await getDashboardData()
    }
  };
};
