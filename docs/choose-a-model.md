# Choose a model

Mylonite has no default provider and no default model. Every live command —
one that makes an LLM call — needs you to choose one, once, before it does
any work. This page is the full provider table, how to hand over a key, and
which commands need one at all.

## The provider table

Generated from `mylonite.providers.registry.PROVIDERS`, the one table in the
code that decides which providers Mylonite backs
(`scripts/gen_provider_table.py` writes it; `tests/test_choose_a_model_docs.py`
fails the build if this page and the registry ever disagree).

**measured** means Mylonite has run its own verification campaign against
that provider and the results are in the repo. **supported** means LiteLLM
routes to it and Mylonite checks for its credential before spending a call,
but there is no dedicated verification evidence yet — don't read "supported"
as "measured", and don't describe a supported-only provider as measured in
your own docs either.

<!-- BEGIN GENERATED PROVIDER TABLE -->

| Provider | Status | LiteLLM prefix | Key env var(s) | Other required vars | Extra headers | Example model |
|---|---|---|---|---|---|---|
| anthropic | measured | `anthropic/` | `ANTHROPIC_API_KEY` | — | `anthropic-workspace-id` | `anthropic/claude-haiku-4-5-20251001` |
| ollama | measured | `ollama_chat/` | none — local, no key | — | none yet | `ollama_chat/llama3.2:3b` |
| azure | supported | `azure/` | `AZURE_API_KEY` | `AZURE_API_BASE`, `AZURE_API_VERSION` | none yet | not published yet |
| bedrock | supported | `bedrock/` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | — | none yet | not published yet |
| google | supported | `gemini/` | `GEMINI_API_KEY` | — | none yet | not published yet |
| litellm-proxy | supported | `litellm_proxy/` | none — see notes below the table | — | none yet | not published yet |
| openai | supported | `openai/` | `OPENAI_API_KEY` | — | none yet | not published yet |
| vertex_ai | supported | `vertex_ai/` | none — see notes below the table | `VERTEXAI_PROJECT`, `VERTEXAI_LOCATION` | none yet | not published yet |
| vllm | supported | `hosted_vllm/` | none — local, no key | — | none yet | not published yet |

<!-- END GENERATED PROVIDER TABLE -->

**No bare key for Vertex AI or a LiteLLM proxy.** Vertex AI authenticates
through Google's Application Default Credentials (a `gcloud`-managed
file or the metadata service, not an environment variable Mylonite can
check), so Mylonite checks for its project/location pair instead. A LiteLLM
proxy sits in front of your own provider accounts and handles auth on the
proxy side; point `model` at `litellm_proxy/<model>` and `api_base` at the
proxy, and authenticate to the proxy however it expects.

A provider outside this table isn't refused outright: Mylonite falls back to
LiteLLM's own `<PROVIDER>_API_KEY` naming convention and warns once. See
["The approved-provider registry"](self-hosted-models.md#the-approved-provider-registry)
for why that fallback exists instead of asking LiteLLM directly, and
[Self-hosted models](self-hosted-models.md) for the full Ollama/vLLM setup
and CI sizing guidance (local providers need no key at all).

## Picking a model

Set `model` with the provider's LiteLLM prefix from the table above, for
example `anthropic/claude-haiku-4-5-20251001` or `openai/gpt-4o`. Three
places can set it, in this order — the first one set wins:

1. `--model` on the command itself.
2. `model:` in `mylonite.yaml`.
3. the `MYLONITE_MODEL` environment variable.

This is the same precedence every other `mylonite.yaml` field follows — see
[Concepts](concepts.md) for the full rule and the rest of the fields it
applies to (`--planner-model`/`--customiser-model`/`--judge-model` each
follow the same order and default to whatever `model` resolves to when left
unset).

## Giving Mylonite a key

A provider's key goes wherever an API key normally goes for your setup —
Mylonite reads the provider's own environment variable (the table above)
from whichever of these already has it set:

- your shell's ambient environment (the usual `export ANTHROPIC_API_KEY=…` /
  `$env:ANTHROPIC_API_KEY = "…"`, or a CI secret mapped to that name);
- `--env-file path/to/.env` — a dotenv file of `KEY=VALUE` lines. Only
  recognised provider credential/config names are loaded (provider key
  variables like `*_API_KEY`/`AZURE_*`, plus the `MYLONITE_*` run-config
  vars); anything else in the file is reported and dropped, never loaded
  silently;
- `--api-key-file path/to/key` — either a dotenv-style file (handled the
  same way as `--env-file`) or a single bare key on its own line, with the
  provider inferred from the key's own shape (`sk-ant-…` → Anthropic,
  `sk-…` → OpenAI, `AKIA…` → the AWS access-key half of Bedrock's pair). If
  the shape isn't recognised, Mylonite says so and asks for a dotenv file or
  `--env-file` instead, rather than guessing.

Both flags are global — they work before any command, not just the ones
that call a model. **When more than one source sets the same variable, the
flag loaded closer to the end of start-up wins** — concretely, `--api-key-
file` overrides `--env-file`, and both override whatever was already in your
shell's ambient environment, printing a warning on stderr each time they
override something. Pass only the one you mean to use if you want to avoid
reading that warning.

**A key that needs a header.** If your key needs a header on every request,
for example the workspace id an unscoped Anthropic key needs (the "Extra
headers" column above), pass it with the global `--llm-header NAME=VALUE`
option or the `MYLONITE_LLM_HEADERS` variable (which `--env-file` also loads). Mylonite never logs or saves the value. See
the [CLI reference](cli-reference.md) for details.

## Does this command need a key?

| Command | Needs a model and key? |
|---|---|
| `mylonite demo` | No — it replays a recorded run. Pass `--live` to make real calls, which then needs a key for whatever `--provider`/`--model` you pass it. |
| `mylonite check` | No — a static look at your server's tool surface, no LLM call. |
| `mylonite scan --scaffold` | No — introspects your server once and writes a starter `target.yaml`, no LLM call. |
| `mylonite scan` (without `--scaffold`) | Yes. `--dry-run` previews the planned attack with no key and no calls. |
| `mylonite generate` | No — offline and deterministic, turns a saved finding into a pytest test. |
| `mylonite validate` | Yes. |
| `mylonite gate` | Yes — it runs `scan` → `generate` → `validate` in one command. |
| `mylonite ablate` | Yes. |
| `mylonite report` | No — renders an already-saved scan or validation result. |

Every command that needs a model checks every role it will call (planner,
customiser, judge) **before** doing any work and names the missing
environment variable, rather than spending a call and failing partway
through. It then sends one tiny request per remote role model, so a key the
provider refuses (invalid, expired, or missing a required header) stops the
run in one line, exit `4`, before the target starts. With nothing configured anywhere — no `--model`, no `model:` in
`mylonite.yaml`, no `MYLONITE_MODEL` — Mylonite refuses to run and lists the
approved providers from the table above, each with its key variable and an
example model string, plus the no-key local option (a self-hosted Ollama
model — see [Self-hosted models](self-hosted-models.md)).

## Where to go next

- [Self-hosted models (Ollama/vLLM)](self-hosted-models.md) — the no-key
  local path, and why it isn't the CI default.
- [Concepts](concepts.md) — the full `mylonite.yaml`/env-var precedence
  rule.
- [CI gating](ci-gating.md) — which key variable a gating workflow expects,
  and how to point it at a different provider.
- [CLI reference](cli-reference.md) — exit codes for a missing or
  unreachable credential, and every command's full flag list.
