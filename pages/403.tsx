import Link from "next/link";
import { useSession } from "next-auth/react";
import { fullSignOut } from "../lib/signOutClient";

export default function Forbidden() {
  const { status } = useSession();
  return (
    <main className="simple-page">
      <h1>Access not permitted</h1>
      <p>Your identity does not have a PrimeSEC role. Ask an administrator to assign SOC_Admin, SOC_Analyst or SOC_ReadOnly.</p>
      {status === "authenticated" ? (
        <button className="btn-cta" onClick={() => void fullSignOut()}>Sign out</button>
      ) : (
        <Link href="/login" className="btn-cta">Back to sign in</Link>
      )}
    </main>
  );
}
