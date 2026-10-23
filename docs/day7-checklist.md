# Day 7 acceptance checklist (CyberReasoner: defensive local-model analysis)

[x] = verified: unit tests with an in-process fake Ollama, API end-to-end checks against the running app, and one real run against a local Ollama (`qwen2.5:7b`, about 20 s warm; the first call after a cold load can take over a minute).
Advisory text only. Nothing here scans, tests, exploits or changes a host or a finding.

## Access and input
- [x] `/cyberreasoner` needs a PrimeSEC login. `POST /api/cyberreasoner/analyze` and `/plan` need SOC_Analyst or SOC_Admin (read-only 403, unauthenticated 401), are POST-only and origin-checked.
- [x] The **only** input is the id of an already imported finding (`vuln_` + 16 hex). Junk, path-like or command-like ids are 400; a well-formed unknown id is 404. Extra fields such as `target` or `command` are ignored. No endpoint accepts a shell command, a URL or a target.
- [x] Analysis is rate-limited (10 per user per 10 minutes) and runs **one model call at a time** (a second concurrent call gets 429); the lock is released after success, failure and timeout.

## Model call
- [x] **Finding data stays on this machine.** `OLLAMA_BASE_URL` must be loopback; any other host (including a private LAN address or a look-alike such as `127.0.0.1.evil.com`) is refused unless `OLLAMA_ALLOW_REMOTE=true` is set deliberately. `file:`/credentials-in-URL are refused. Redirects are refused. *The original sent vulnerability data to whatever URL was configured.*
- [x] Scanner text (descriptions, banners can be attacker-controlled) is sent in the user message as data; the system prompt says to ignore instructions inside it. Notes, owners and secrets are never sent. Host criticality, exposure and exploit evidence from PrimeSEC's own stores are included (*the original read fields that did not exist*).
- [x] Timeout (default 180 s), model down, upstream error, redirect, empty, non-JSON and oversized replies each give a clear, bounded error; the upstream's own error text is not passed to the browser.

## Output handling
- [x] The reply must be a JSON **object**; every field is type-checked, length-capped (lists at 12 items), and unknown keys are dropped. A model that returns `null`, an array or a string is rejected. *The original crashed on `null`.*
- [x] A best-effort screen drops text mentioning offensive tooling (Metasploit/meterpreter, reverse shells, `/dev/tcp`, `curl | sh`, mimikatz, Cobalt Strike, shellcode...) and shows how many items were withheld. It is a safety net, **not** a guarantee: the model can still be wrong or unhelpful.
- [x] Always labelled "Advisory · unverified"; the model's confidence is shown as the model's own claim. Output is rendered as plain text.

## Workflow plan
- [x] `POST /api/cyberreasoner/plan` returns a fixed template (six task types from an allowlist, all `proposed`, active validation needs human approval, six prohibited actions listed) and `executed: false`. No free text from the finding or the model becomes a task.
- [ ] **Not connected to JEV.** The plan is not stored and not sent anywhere; the JEV API contract was not supplied. Because it is not stored, the audit log records the plan id and task types but there is nothing to look it up by.

## Audit
- [x] `cyberreasoner_analysis` (finding, model, number of items withheld) and `cyberreasoner_plan_created` (finding, plan id, task types). The model's text is never written to the audit log. Shown in the VAPT audit list.

## Known limitations
- The model is a 7B general model: it can be confidently wrong, and it only sees what the scanner reported. Use it to speed up triage, not as evidence.
- The content screen is keyword based and can both miss and over-match.
- An analysis is not saved: reload the page and it is gone (re-run costs about 20 seconds).
- `OLLAMA_ALLOW_REMOTE=true` sends vulnerability details to another machine. Do that only to a server you control.
