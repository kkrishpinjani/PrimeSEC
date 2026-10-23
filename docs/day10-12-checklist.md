# Days 10-12 acceptance checklist (Agent Security)

[x] = verified: 58 unit tests (including a 4,000-case random test of the fail-closed rules) and 61 end-to-end API checks against the running app, across all three roles. Not verified: any real agent runtime, because none is connected.

## What it is
A hand-kept registry of AI agents, a small set of policies, and a deterministic evaluator that answers "should this action be ALLOWED, REVIEWED, held for APPROVAL or DENIED?". Page: `/agents` (Overview, Agent inventory, Policies, Test lab). API: `/api/agents`, `/policies`, `/evaluate`, `/scenarios`, `/overview`.

**It decides; it does not enforce.** It never runs a tool, contacts an agent or blocks anything. A decision only protects something if the system that runs the agent asks first, obeys the answer and treats a failed check as DENY. The inventory is manual (the three seeded agents are labelled "Example"); nothing is discovered automatically.

## Fail-closed rules (cannot be weakened by any policy setting)
- [x] An agent that is not registered is never ALLOWED (at least REVIEW).
- [x] A suspended agent is always DENIED (a per-agent kill switch).
- [x] A tool not on the agent's registered allowlist is always DENIED.
- [x] Verified with all policies disabled, with no policies at all, with a tampered baseline policy, and over 4,000 random combinations: none produced an ALLOW that breaks these rules.
- [x] Policies can only make decisions **stricter**: there is no "allow" action, and when several policies match the strictest wins. *In the supplied code the first matching policy won, so a newly added "allow" policy could silently shadow a deny, and switching off the "unregistered tool" policy turned that case into ALLOW.*
- [x] Baseline policies (unregistered tools, unknown agents) cannot be switched off.
- [x] The caller can mark an action sensitive or external to make it stricter, never to make it looser (`sensitive:false` on a payment tool is ignored).

## Who may do what
- [x] Any PrimeSEC role: read. **SOC_Analyst/Admin: evaluate and run the test suite. SOC_Admin only: register agents, suspend/reactivate, add or toggle policies.** *The supplied package let any analyst register an agent with any tool list or switch off a policy, which lets them grant themselves trust.* Mutations are origin-checked; responses are `no-store`.
- [x] Evaluation is rate-limited (120/min per user, 429), the test suite 20/min.

## Records
- [x] Everything goes to the existing audit log (`agent_registered`, `agent_status_changed`, `agent_policy_changed`, `agent_policy_evaluated`, `agent_scenarios_run`): ids, tool names, decisions and policy ids only; no prompts, tool payloads or credentials. *The supplied package kept a second, separate log.*
- [x] A non-allow decision creates a finding; repeats of the same agent, tool and decision **update one finding with a count** instead of adding hundreds (capped at 500).
- [x] The scenario suite (6 checks) runs against the live policies and records nothing but one audit line. *The supplied suite wrote findings on every run.* It catches regressions: disabling the approval policy makes a check fail.
- [x] Input is validated: tool names may use letters, digits and `. _ : / -` only (a shell-looking name is rejected), control characters are stripped, lists and text are length-capped. Parallel registrations are serialised (20 at once, none lost).

## Not done / limits
- [ ] No live agent discovery or connectors (framework names are labels). No agent runtime is contacted or modified.
- [ ] Approval is only a decision outcome: there is no approval queue, signed approvals or resolve/acknowledge flow for findings.
- [ ] Sensitivity is judged by keywords in the tool and data-class names, plus caller flags. A cleverly named tool can slip past it; the allowlist is the stronger control.
- [ ] The scenarios are deterministic rule checks, not an adversarial red-team or an LLM alignment test.
- [ ] State is a local JSON file (`data/agentsec-state.json`), single-process, not tamper-proof.
