# Days 13-14 acceptance checklist (action gateway, approvals, evaluation report)

[x] = verified: 51 unit tests (`npm run test:agentgate`) and 54 end-to-end API checks against the running app across all three roles, including 20 simultaneous requests spending one permit. Not verified: any real agent runtime, because none is connected.

Page: `/agents` → **Gateway**, **Approvals** and **Evaluation** tabs. API: `POST /api/agents/gateway/action`, `POST /api/agents/gateway/consume`, `GET/POST /api/agents/approvals`, `POST /api/agents/scenarios` (the evaluation run).

**PrimeSEC still executes nothing.** The gateway answers "may this action go ahead?" and hands out a permit. It protects something only if the adapter that performs the action asks first, spends the permit with the same action details, and refuses to act otherwise (and treats an unreachable gateway as a refusal).

## Gateway and permits (Day 13)
- [x] ALLOW returns a one-time permit valid for 60 seconds. DENY and REVIEW return nothing, and no approval request is created for them.
- [x] **A permit is bound to one exact action** (agent, tool, destination, data class, sensitivity). Using it for a different tool, agent, destination or data class is refused (403) and does not spend it. *The supplied consume endpoint checked only the permit, so a permit for a harmless read could be used to authorise a delete.*
- [x] **Single use even under a race.** 20 simultaneous HTTP requests and 25 simultaneous in-process calls with one permit: exactly one succeeds, the rest get 409. *The supplied read-modify-write of a JSON file could let two requests both succeed.*
- [x] Expired permits are refused (410); malformed or invented permits are refused (400/403).
- [x] Only a SHA-256 hash of a permit is stored (checked in the state file); permits appear in no audit event and no overview response.
- [x] **Fail closed on audit:** if the decision cannot be written to the audit log, no permit is issued; if consumption cannot be recorded, the adapter is told not to act.
- [x] SOC_Analyst/SOC_Admin only; read-only is refused; origin-checked; rate-limited (120/min per user).

## Approvals (Day 13)
- [x] REQUIRE_APPROVAL creates one pending request (30 minutes). Asking again returns the same request instead of piling up new ones; at most 20 pending per requester.
- [x] **Four-eyes:** the person who made a request cannot approve or reject it (403). Another SOC_Analyst or SOC_Admin must.
- [x] **Approval completes the loop.** After approval, the same requester can re-submit the same action once, within 10 minutes, and receives a permit; the approval is then used up. *In the supplied design an approved action could never proceed, because re-submitting just asked for approval again.* Someone else cannot spend your approval; a rejected, expired or lapsed approval gives nothing.
- [x] **An approval never overrides a denial.** If policy later tightens to DENY, the earlier approval no longer helps.
- [x] Decided requests cannot be decided again (409); expired requests cannot be decided (410). Every decision is audited; the note stays on the request, not in the audit log.

## Evaluation report (Day 14)
- [x] Ten fixed cases (the supplied eight plus "caller cannot downgrade sensitivity" and "suspended agent"), each with a category, expected and actual decision and the reasons. All pass on the default policies; changing a policy makes the affected case fail (that is its purpose).
- [x] A report id, pass rate, who ran it and a list of limitations; **Download JSON report** in the browser.
- [x] One audit line per run (with the report id). *The supplied suite wrote ten events per run and created findings.* It records no findings and changes no state.

## Not done / limits
- [ ] Not a universal interceptor: nothing is wired into a real agent framework or MCP server. A reference adapter is the next step; tell me which framework to target.
- [ ] Permits and approvals are matched to the requesting *person's* identity. A real adapter would need its own service identity and signed requests; here the caller is an authenticated analyst or admin session.
- [ ] The approval note is free text and is not reviewed.
- [ ] State is a local JSON file, serialised within one process: correct for one server, not for several instances sharing it. Use a transactional store before that.
- [ ] The evaluation tests the rules, not model alignment, prompt-injection resistance or a live runtime.
