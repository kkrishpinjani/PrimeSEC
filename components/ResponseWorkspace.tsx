import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { LogoMark } from "./Logo";
import { fullSignOut } from "../lib/signOutClient";
import type { Execution, Proposal } from "../lib/response";

type Status = { executionEnabled: boolean; allowedActions: string[]; adapters: { name: string; actions: string[] }[]; dualControl: boolean; approvalMaxAgeMinutes: number };
const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
const cls = (s: string) => (["rejected", "execution_failed", "failed", "verification_failed", "rollback_failed"].includes(s) ? "sev-high" : ["approved", "proposed", "executing"].includes(s) ? "sev-medium" : "sev-low");

export default function ResponseWorkspace({ user, roles }: { user: { name?: string | null; email?: string | null }; roles: string[] }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [proposals, setProposals] = useState<Proposal[]>([]);
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [form, setForm] = useState({ actionType: "", target: "", rationale: "" });
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const isAdmin = roles.includes("SOC_Admin");
  const canPropose = isAdmin || roles.includes("SOC_Analyst");
  const displayName = user.name || user.email || "Analyst";

  const load = useCallback(async () => {
    const r = await fetch("/api/response", { cache: "no-store" });
    const b = await r.json();
    if (!r.ok) return setError(b.error || "Could not load the response workspace.");
    setStatus(b.status); setProposals(b.proposals); setExecutions(b.executions);
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function send(label: string, url: string, init: RequestInit, done: string) {
    setBusy(label); setError(""); setNotice("");
    try {
      const r = await fetch(url, init);
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "The request failed.");
      setNotice(done);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
      await load();
    }
  }
  const json = (method: string, body: unknown, extra: Record<string, string> = {}): RequestInit => ({ method, headers: { "Content-Type": "application/json", ...extra }, body: JSON.stringify(body) });
  const propose = () => send("propose", "/api/response/proposals", json("POST", form), "Proposal recorded. Another administrator must review it.").then(() => setForm({ actionType: "", target: "", rationale: "" }));
  const review = (id: string, decision: "approve" | "reject") => {
    const note = decision === "reject" ? window.prompt("Why are you rejecting this proposal?") ?? "" : "";
    if (decision === "reject" && !note.trim()) return;
    return send(id, `/api/response/proposals/${id}`, json("POST", { decision, note }), decision === "approve" ? "Approved." : "Rejected.");
  };
  const execute = (id: string) => send(id, "/api/response/executions", json("POST", { proposalId: id }, { "Idempotency-Key": `ui-${id}-${crypto.randomUUID()}` }), "Execution requested.");
  const act = (id: string, action: "verify" | "rollback") => send(id, `/api/response/executions/${id}`, json("POST", { action }), action === "verify" ? "Verification finished." : "Rollback finished.");

  return (
    <section className="preview soc-dash vapt-page" aria-label="Governed response">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/dashboard" className="pv-chip">← Dashboard</Link>
        <span className="pv-chip">Governed response</span>
        <div className="pv-actions">
          <span className="pv-user" title={roles.join(", ")}>
            <span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span>
            <span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span>
          </span>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
        </div>
      </div>

      <div className="vapt-body">
        {status && (
          <p className="vapt-warning">
            <b>Execution is {status.executionEnabled ? "ON" : "OFF"}.</b>{" "}
            {status.executionEnabled
              ? `Allowed actions: ${status.allowedActions.join(", ") || "none"}. Registered adapters: ${status.adapters.map((a) => a.name).join(", ") || "none"}.`
              : "As delivered, PrimeSEC records proposals and approvals but cannot act on any system: no adapter is installed and RESPONSE_EXECUTION_ENABLED is false."}{" "}
            {status.dualControl ? "Dual control is on: you cannot review or run your own proposal. " : ""}Approvals expire after {status.approvalMaxAgeMinutes} minutes.
          </p>
        )}
        {error && <div className="pv-list pv-error" role="alert">{error}</div>}
        {notice && <div className="pv-list vapt-ok" role="status">{notice}</div>}

        <div className="pv-list">
          <small>Propose an action {canPropose ? "" : "(SOC_Analyst or SOC_Admin only)"}. A proposal acts on nothing; it asks for review.</small>
          <div className="fd-edit sap-form">
            <label>Action type<input className="fd-input" value={form.actionType} maxLength={41} disabled={!canPropose} placeholder="e.g. watch_asset" onChange={(e) => setForm({ ...form, actionType: e.target.value })} /></label>
            <label>Target<input className="fd-input" value={form.target} maxLength={300} disabled={!canPropose} placeholder="e.g. an inventory asset id" onChange={(e) => setForm({ ...form, target: e.target.value })} /></label>
            <label>Why (the reviewer reads this)<textarea className="fd-input" rows={3} value={form.rationale} maxLength={1000} disabled={!canPropose} onChange={(e) => setForm({ ...form, rationale: e.target.value })} /></label>
            <div className="fd-actions"><button className="pv-btn pv-btn-primary" disabled={!canPropose || busy !== "" || !form.actionType || !form.target || form.rationale.trim().length < 10} onClick={() => void propose()}>{busy === "propose" ? "Saving…" : "Submit proposal"}</button></div>
          </div>
        </div>

        <div className="pv-list">
          <small>Proposals (newest first)</small>
          {proposals.length === 0 ? <p className="pv-empty">No proposals yet.</p> : proposals.map((p) => (
            <div className="fd-card" key={p.id}>
              <div className="fd-head"><span className={`pv-sev ${cls(p.status)}`}>{p.status.replace("_", " ")}</span><strong className="fd-name">{p.actionType} → {p.target}</strong><code>{p.id}</code></div>
              <p className="fd-meta">Proposed by {p.proposedBy} · {when(p.proposedAt)}{p.reviewedBy ? ` · reviewed by ${p.reviewedBy} ${when(p.reviewedAt)}` : ""}</p>
              <p>{p.rationale}</p>
              {p.reviewNote && <p className="fd-meta">Reviewer: {p.reviewNote}</p>}
              <div className="fd-actions">
                {p.status === "proposed" && <>
                  <button className="pv-btn pv-btn-primary" disabled={!isAdmin || busy !== ""} title={isAdmin ? "" : "SOC_Admin only"} onClick={() => void review(p.id, "approve")}>Approve</button>
                  <button className="pv-btn" disabled={!isAdmin || busy !== ""} onClick={() => void review(p.id, "reject")}>Reject</button>
                </>}
                {p.status === "approved" && <button className="pv-btn pv-btn-primary" disabled={!isAdmin || busy !== "" || !status?.executionEnabled} title={status?.executionEnabled ? "" : "Execution is switched off by policy"} onClick={() => void execute(p.id)}>{busy === p.id ? "Working…" : "Execute"}</button>}
              </div>
            </div>
          ))}
        </div>

        <div className="pv-list">
          <small>Executions</small>
          {executions.length === 0 ? <p className="pv-empty">Nothing has been executed.</p> : executions.map((x) => (
            <div className="fd-card" key={x.id}>
              <div className="fd-head"><span className={`pv-sev ${cls(x.status)}`}>{x.status.replace("_", " ")}</span><strong className="fd-name">{x.actionType} → {x.target}</strong><code>{x.id}</code></div>
              <p className="fd-meta">Adapter {x.adapter} · run by {x.requestedBy}, approved by {x.approvedBy || "—"} · {when(x.createdAt)}</p>
              <details><summary className="fd-meta">Result, verification, rollback</summary><pre style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify({ result: x.result, verification: x.verification, rollback: x.rollback }, null, 2)}</pre></details>
              <div className="fd-actions">
                {(x.status === "executed" || x.status === "verification_failed") && <button className="pv-btn" disabled={!isAdmin || busy !== ""} onClick={() => void act(x.id, "verify")}>Verify</button>}
                {["executed", "verified", "verification_failed"].includes(x.status) && <button className="pv-btn" disabled={!isAdmin || busy !== ""} onClick={() => void act(x.id, "rollback")}>Roll back</button>}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
