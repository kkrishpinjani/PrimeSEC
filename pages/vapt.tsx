import Head from "next/head";
import type { GetServerSideProps } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, PRIMESEC_ROLES } from "../lib/auth";
import VaptWorkspace from "../components/VaptWorkspace";

type Props = { user: { name?: string | null; email?: string | null }; roles: string[] };

export default function Vapt({ user, roles }: Props) {
  return (
    <>
      <Head>
        <title>VAPT | PrimeSEC</title>
        <meta name="robots" content="noindex" />
      </Head>
      <main className="dash-page">
        <VaptWorkspace user={user} roles={roles} />
      </main>
    </>
  );
}

export const getServerSideProps: GetServerSideProps<Props> = async (context) => {
  const session = await getServerSession(context.req, context.res, authOptions);
  if (!session) return { redirect: { destination: "/login", permanent: false } };
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) return { redirect: { destination: "/403", permanent: false } };
  return { props: { user: { name: session.user?.name ?? null, email: session.user?.email ?? null }, roles } };
};
