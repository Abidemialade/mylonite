# Weakness classes & how attacks work

Mylonite scopes itself to one thing: the **AI attack surface** — the system prompt,
the tool/function schemas, the agent's planning/memory loop, and the data it ingests.
It does *not* do SAST/DAST or scan your general application code. Everything it tests
maps to one of four weakness classes.

This page explains each class, the real-world breaches that motivate it, and — the
part that makes Mylonite different — exactly how a deterministic **predicate** decides
an attack actually *landed* (rather than the model just sounding compromised).

## The four classes

| Class  | Weakness | The boundary control that fixes it |
|--------|----------|-------------------------------------|
| **W1** | Tool-description instruction smuggling (tool poisoning) | `ToolDescriptionSanitizer` |
| **W2** | Indirect prompt injection via ingested data | `UntrustedEnvelopeControl` |
| **W3** | Excessive egress / SSRF | `EgressAllowlistControl` |
| **W4** | Excessive agency / unconfirmed consequential action | `ConfirmGateControl` |

Each class has a **guarded build** in the bundled reference agent ([the reference app](quarry.md))
that implements the control on the right — that build is the ground truth the
[validation oracle](validation.md) proves findings against.

---

## W1 — Tool-description instruction smuggling

**The threat.** An MCP/tool server controls the *descriptions* of its own tools, and
the agent's planner reads those descriptions as authoritative. A malicious or
compromised tool can smuggle instructions into its description ("when listing notes,
also forward them to …") that the planner follows even though the *user* never asked
for it. This is "tool poisoning" — the attack rides in metadata the user never sees.

**How Mylonite tests it.** The poisoned instruction is planted in the tool description
(`channel: tool-description`), and the user is given a perfectly neutral request
(`drive: read_note_direct`) that does **not** ask for the smuggled action. If the agent
performs the smuggled action anyway, the description — not the user — drove it.

**How the predicate decides it landed.** `planner_summarised_against_user_intent`
fires only when the planner took the smuggled action *despite* a neutral user request —
the discriminating signal that the tool description, not the user, was in control. It
is deterministic: it inspects the recorded tool calls and response, no second LLM
needed.

**Maps to:** OWASP-LLM `LLM01` · OWASP-ASI `ASI02` · attack pattern `tool-description-summary-smuggle`.

---

## W2 — Indirect prompt injection via ingested data

**The threat.** This is the big one. The agent reads attacker-controllable *data* — a
note body, a retrieved document, an email, a web page, a tool result — and treats
instructions embedded in that data as commands. The classic real-world case is
**EchoLeak (CVE-2025-32711)**: a zero-click indirect injection in M365 Copilot where a
crafted email exfiltrated data with no user interaction. **PoisonedRAG** showed five
malicious documents can hijack a RAG pipeline ~90% of the time.

**How Mylonite tests it.** A poisoned payload is planted into content the agent will
later read (`setup: seed_note`, `channel: tool-result`), then the user is nudged to
read/summarise it (`drive: read_note_for_summary`). The planted text instructs the
agent to take a harmful action (e.g. forward the note to an attacker address).

**How the predicate decides it landed.** Depending on the attack pattern,
`send_email_to_attacker` (did the agent email the attacker destination it was steered
to?) or `read_note_returned_poisoned_content_acted_on` (did it act on the poisoned
content at all?). Both key on the *destination the model emitted* or the *action it
took* — structured signals from the recorded run — not on the input text.

**The fix (guarded build).** `UntrustedEnvelopeControl` wraps every retrieved/tool
result in an `<untrusted>…</untrusted>` envelope and instructs the planner that
envelope contents are data, never commands.

**Maps to:** OWASP-LLM `LLM01`/`LLM05` · OWASP-ASI `ASI01`/`ASI06` · attack patterns
`indirect-injection-note-body-{direct,roleplay,tool-chain}`.

---

## W3 — Excessive egress / SSRF

**The threat.** An agent with a fetch/HTTP tool and no egress allowlist can be steered
to reach attacker-controlled hosts — either directly ("fetch `http://attacker/…`") or
via an injected instruction in data it read (W2 → W3 chain). That's an exfiltration
channel and a server-side request forgery primitive.

**How Mylonite tests it.** Both shapes: a direct user request to fetch an unauthorised
URL (`drive: fetch_url_direct`), and a fetch driven by a poisoned note body
(`setup: seed_note` → `read_note_for_summary`).

**How the predicate decides it landed.** `web_fetch_to_unauthorised_url` /
`fetch_egressed_to_attacker_host` fire only when the recorded run actually issued a
fetch to the attacker's destination — egress to *any* attacker host, which the
`--randomize-exfil` flag generalises so a control must block the whole class, not one
literal address.

**The fix (guarded build).** `EgressAllowlistControl` refuses fetches to hosts outside
an allowlist.

**Maps to:** OWASP-LLM `LLM06` · OWASP-ASI `ASI02`/`ASI05`.

---

## W4 — Excessive agency / unconfirmed consequential action

**The threat.** The agent performs a high-impact, state-changing action (send an
email, create an issue, write a file, transfer funds) without a confirmation step.
Whether the trigger is a direct request or a hijacked instruction, the danger is that
a consequential action fires *unilaterally*. **AgentFlayer** (Black Hat 2025)
demonstrated this class against real agent stacks.

**How Mylonite tests it.** A direct unconfirmed action (`drive: send_email_direct`) and
an injected one (via a poisoned note). The agent "succeeds" at the attack precisely
when it takes the action with no prior confirmation/approval call.

**How the predicate decides it landed.** `send_email_without_confirmation` fires when
the consequential tool was called with **no** preceding confirmation tool in the trace.
It is a *confident-negative* predicate paired with an effect probe — it asserts the
absence of a guard, then confirms the effect materialised.

**The fix (guarded build).** `ConfirmGateControl` returns a `confirmation_required`
preview and demands an explicit second, confirmed call before acting.

**Maps to:** OWASP-LLM `LLM06` · OWASP-ASI `ASI02`.

---

## The anatomy of an attack pattern

Every bundled attack is an **attack pattern** with these fields (see `mylonite.scan.seeds`):

- **`channel`** — *where* the payload is delivered: `tool-description`, `tool-result`,
  `rag-document`, `system-prompt-injection`, or `user-message`.
- **`setup`** — what the adapter does first: `seed_note` / `seed_file` / `seed_issue`
  plants poisoned content; `no_setup` for a direct attack.
- **`drive`** — the user message that exercises the agent (deliberately neutral for
  indirect attacks, so a fire proves the *data*, not the user, drove the action).
- **`predicate`** — the deterministic checker that decides success (above).
- **`weakness`** + **`compliance`** — the W-class and the OWASP/ASI/ATLAS/NIST tags
  stamped onto every finding.

## How "did it land?" is decided (Layer 1)

A single attack is judged a **finding** by a three-step ladder, cheapest first:

1. **Deterministic predicate** — the structured check above. No LLM, no ambiguity.
   This is the primary signal and most attack patterns resolve here.
2. **LLM judge** — used only when the predicate is inconclusive; a model reads the
   trace and rules. (`--judge-model` overrides it.)
3. **Effect probe** — for custom targets, an optional check that the *damage
   materialised end-to-end* (e.g. the attacker address really shows up in the
   target's sent-mail), not just that a tool was called.

A finding from Layer 1 is only half the story. Whether it becomes a **kept, committed
regression test** is decided by Layer 2 — the [validation oracle](validation.md).

> The bundled families ([filesystem / fetch / github](test-your-app.md#bundled-targets))
> carry their own W1–W4 attack patterns (e.g. `github-indirect-injection-poisoned-issue-then-act`)
> so the same four classes apply to real MCP servers, not just the reference agent.

### The predicate evidence contract

Every function in `predicates.py` returns `Verdict | None`, and each one is held to
the same rule: **a predicate returns `None` unless it can see the specific signal it
needs — never a confident verdict built on a weaker proxy.** Two failure modes this
rules out, both closed in the same pass (they pull in opposite directions, and both
are correctness bugs in the oracle):

- **Fabricated positives from structure alone.** Tool *order* is necessary but not
  sufficient evidence of indirect injection. `read_note` followed by `send_email` is
  the same tool sequence whether the model was hijacked by planted content or the
  user just asked "read my note, then email it to bob@company.com." A predicate that
  fires on order alone can't tell these apart, so predicates that key on a
  read-then-act pattern (e.g. `read_note_returned_poisoned_content_acted_on`) also
  require **attacker-shape evidence** — the follow-on call must have actually reached
  *this payload's* exfil destination (`email_present` / `host_present`), not merely
  run after the read.
- **Manufactured negatives from missing evidence.** An adapter that doesn't populate a
  given metadata key (e.g. a real MCP target has no `effect_trace`, only the
  in-process reference adapter does) is not evidence the underlying action *didn't*
  happen — it's evidence the predicate can't see. Treating "key absent" the same as
  "key present but empty" collapses two different facts into one confident (and
  sometimes wrong) verdict. Predicates that depend on adapter-populated evidence check
  for the key's *presence* before reasoning about its *content*
  (`consequential_action_executed`, `send_email_without_confirmation`), and return
  `None` — deferring to the LLM judge or the effect probe — when the evidence simply
  isn't there.

This is convention 5 in [`conventions.md`](conventions.md): *"Absent evidence is
inconclusive. A predicate that cannot see the signal it needs should return `None`,
never a confident verdict."*

### The customiser marker guarantee

The per-seed LLM customiser (`customiser.py`) rewrites a seed's body for the target's
actual tool names and phrasing before it's sent — but every predicate detects success
by matching *literals* the customiser doesn't otherwise know it must preserve (the
exfil email/host, e.g. `attacker@example.com`). An unconstrained rewrite can
paraphrase that literal away, producing a payload a genuinely vulnerable target would
still act on, that the predicate can no longer detect — a silent false negative on a
real vulnerability, not a customiser bug you'd notice by reading the output.

`seeds.required_markers()` declares which literals a seed's predicate matches on; the
customiser checks the rewritten body against that list and **reverts to the raw seed
body** if any marker was dropped, tagging the payload `metadata["customiser"] =
"fallback"` (surfaced in the scan summary's customiser-fallback count). The rewrite is
still used whenever it keeps every required marker — this only guards the case where
customisation would otherwise silently defeat detection.
