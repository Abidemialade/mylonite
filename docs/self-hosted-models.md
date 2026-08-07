# Self-hosted models (Ollama / vLLM)

Mylonite routes every LLM call through [LiteLLM](https://docs.litellm.ai/),
so a self-hosted model — [Ollama](https://ollama.com/) running locally, or a
[vLLM](https://docs.vllm.ai/) OpenAI-compatible server on your own
infrastructure — works the same way a hosted provider does: a model string
with a provider prefix, plus an `api_base` telling LiteLLM where to send the
request. No code change, no plugin.

This page is for **operators running Mylonite against their own self-hosted
models** — most commonly to avoid sending prompts to a third-party API at
all, or because you've already standardised on local inference. It is **not**
the recommended CI default; see [Why this isn't the CI default](#why-this-isnt-the-ci-default)
below before wiring it into a gating workflow.

## Configuring a self-hosted model

Set `model` (with the right LiteLLM provider prefix) and `api_base` — either
in `mylonite.yaml`:

```yaml
model: ollama/llama3.3
api_base: http://localhost:11434
```

or via the flat `MYLONITE_*` env vars (same precedence rules as every other
`mylonite.yaml` field — see [Concepts](concepts.md)):

```bash
export MYLONITE_MODEL=ollama/llama3.3
export MYLONITE_API_BASE=http://localhost:11434
mylonite scan reference:vulnerable
```

**Ollama.** LiteLLM's provider prefix is `ollama/<model>` (or
`ollama_chat/<model>` for Ollama's chat-completions endpoint — prefer this
one; it's what Ollama's own tool-calling support targets). `api_base`
defaults to `http://localhost:11434` if you're running Ollama's own default
port.

**vLLM.** LiteLLM's provider prefix for vLLM's OpenAI-compatible server is
`hosted_vllm/<model>` (this is the generic prefix for *any* self-hosted
OpenAI-compatible server, not vLLM-specific tooling). `api_base` points at
your server's `/v1`-style endpoint, e.g. `http://your-vllm-host:8000/v1`.

Neither needs an API key — `mylonite.scan.providers.PROVIDER_ENV_VARS` maps
both `ollama` and `vllm` to `()` (no required env var). `api_base` MUST NOT
embed a credential (no `user:pass@host`, no `?api_key=...` query param) —
`mylonite.yaml` is a committed file, and `LLMPolicy`/`RunConfig` both refuse
to construct with one (see
[`scan/llm_policy.py`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/scan/llm_policy.py)'s
`validate_api_base`). If your self-hosted endpoint sits behind auth, use a
LiteLLM proxy in front of it and authenticate to *that*, or route through a
network boundary (VPN/private network) instead of a URL-embedded secret.

## Model-size guidance if you're running this in CI

If you *are* self-hosting inside CI (e.g. spinning up Ollama in a GitHub
Actions job to keep everything in-runner with no external egress), size your
model to the runner:

- Default `ubuntu-latest` GitHub Actions runners have **~7 GB of RAM**.
- `llama3.2:3b` fits comfortably (~3.5 GB resident).
- `llama3.1:8b`/similar 8B-class models **OOM-kill** on a default runner —
  you'll see the job die with exit code `137` and no useful error message
  from Mylonite itself (the process was killed by the kernel, not by
  anything catchable in Python). Either use a larger (self-hosted or
  `large`-tier GitHub-hosted) runner, or stick to a 3B-class model.
- A **cold** `ollama pull` of a several-GB model takes **8–12 minutes** on a
  fresh runner with no cache. With `actions/cache` keyed on the model tag,
  a **warm** pull is ~35 seconds; a full warm job (image pull + model load +
  scan) is roughly **4 minutes**.
- **`timeout-minutes` is mandatory** on any CI job that touches Ollama.
  Ollama hangs silently (no error, no log line) on certain failure modes
  (e.g. a corrupted cache, a port already in use) rather than failing fast —
  without an explicit job-level timeout, a bad run just sits until the
  runner's own multi-hour ceiling kills it.

## Example CI workflow snippet (self-hosted Ollama, cached)

This is a **worked example**, not something Mylonite scaffolds for you (see
[Why this isn't the CI default](#why-this-isnt-the-ci-default)) — copy it
into your own workflow and adjust the model/target to match your setup.

```yaml
jobs:
  gate-self-hosted:
    runs-on: ubuntu-latest
    timeout-minutes: 15  # mandatory -- Ollama hangs silently, not loudly, on failure
    steps:
      - uses: actions/checkout@v4

      - name: Cache Ollama models
        uses: actions/cache@v4
        with:
          path: ~/.ollama/models
          key: ollama-models-llama3.2-3b-v1

      - name: Install Ollama
        run: curl -fsSL https://ollama.com/install.sh | sh

      - name: Start Ollama and pull the model
        run: |
          ollama serve &
          # Wait for the server instead of a fixed sleep -- still bounded by
          # the job's own timeout-minutes above if it never comes up.
          until curl -sf http://localhost:11434/ >/dev/null; do sleep 1; done
          ollama pull llama3.2:3b

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - run: pip install mylonite

      - name: Gate against the self-hosted model
        env:
          MYLONITE_MODEL: ollama_chat/llama3.2:3b
          MYLONITE_API_BASE: http://localhost:11434
        run: mylonite gate --target-file target.yaml --authorize my-app
```

## Why this isn't the CI default

Mylonite's scaffolded `mylonite-gate.yml`/`mylonite-discovery.yml` workflows
(see [CI gating](ci-gating.md)) default to a small **hosted** model
(`gpt-4o-mini`/`claude-haiku-4-5`-class), not a self-hosted 3B model, even
though the 3B path is cheaper and needs no external API key. A 3B model's
quality ceiling measurably degrades both roles Mylonite's LLM calls play:

- **The planner** (`scan.llm_planner.LLMPlanner`) drives the agent-under-test
  through tool-calling — a weaker model follows instructions and invokes
  tools less reliably, which shows up as *false negatives* (a real weakness
  the agent would exploit under a competent planner never gets exercised at
  all, because the weak planner never drives the right sequence of calls).
- **The judge** (`scan.judge.SuccessJudge`)'s LLM-fallback rubric verdict is
  exactly the kind of nuanced "did the damaging effect actually materialise"
  judgement smaller models are worse at — which shows up as *both* false
  positives and false negatives on the (predicate-inconclusive) cases that
  reach it.

Both failure modes are corrosive to a **security** tool specifically: a
false negative means a real exploit ships silently uncaught; a false
positive erodes trust in every subsequent finding. Self-hosting is a
legitimate, fully-supported choice for privacy/cost/network reasons — this
page exists so you can make it deliberately — but it is a choice that trades
against detection quality, so Mylonite does not make it for you by default.

## Where to go next

- [Enterprise & air-gapped networking](enterprise-networking.md) — the
  broader story on internal model gateways, TLS-inspecting proxies, and
  self-hosted CI runners.
- [CI gating](ci-gating.md) — the full `mylonite gate` flow and the
  scaffolded, hosted-model-by-default workflows.
- [Concepts](concepts.md) — `mylonite.yaml` precedence rules and the flat
  `MYLONITE_*` env var layer.
