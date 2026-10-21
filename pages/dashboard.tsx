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
  wazuhUrl: string;
  data: DashboardData;
};

export default function Dashboard({ user, roles, wazuhUrl, data }: Props) {
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
          wazuhUrl={wazuhUrl}
          onSignOut={() => void fullSignOut()}
        />
      </main>
    </>
  );
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
      wazuhUrl: process.env.WAZUH_DASHBOARD_URL || "",
      data: await getDashboardData()
    }
  };
};
