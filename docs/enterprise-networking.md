# Enterprise & air-gapped networking

Mylonite's per-PR gate re-drives *your* MCP server in CI. Because Mylonite uses
the **stdio** MCP transport, the server is spawned as a subprocess **inside the
runner** (from your `target.yaml`'s `command`/`args`/`env`) — there is no
inbound connection to your agent. So "can CI reach my MCP server?" reduces to
three questions, each with an answer.

## 1. Your MCP server's backend dependencies (internal DBs, private APIs)

A GitHub-hosted runner can't reach services behind your corporate gate. Options:

- **Self-hosted runner (recommended).** Set `runs-on` to a self-hosted runner
  inside your perimeter — Mylonite scaffolds the workflows with a `--runs-on`
  you choose (`mylonite gate --runs-on "[self-hosted, linux]"`). The runner
  reaches your internal backends; nothing leaves the network.
- **Staging or mock backend.** Mylonite tests the *AI layer* (system prompt,
  tool schemas, planning loop), not your backend data. Point `target.yaml`'s
  `env` at a CI-reachable staging or stubbed backend — the exploit is about
  the agent's behaviour, so a mock DB is a legitimate gate environment.

## 2. The LLM provider endpoint

If you use an internal model gateway (Azure OpenAI private endpoint, an
internal LiteLLM proxy, a Bedrock VPC endpoint), Mylonite routes there via
LiteLLM (`--provider`/`--model` and the provider's `api_base`). With a
local or small model the provider need never be public egress.

## 3. TLS-inspecting corporate proxy

Mylonite uses the OS trust store automatically
(`pip install "mylonite[enterprise]"`), so a proxy CA is trusted without
disabling verification. Escape hatches: `MYLONITE_NO_TRUSTSTORE=1` or
`SSL_CERT_FILE=/path/to/ca.pem`.

## Not just GitHub

`mylonite gate` is a plain pip package + pytest. An air-gapped team can run
the identical command in any in-perimeter CI (Jenkins, GitLab) with no GitHub
dependency. **Self-hosted runner + internal/local model + stdio-spawned
server** gives a fully in-network gate.

## Where to go next

- [CI gating](ci-gating.md) — the full `mylonite gate` flow, the reusable
  Action, and the two scaffolded workflows.
- [Quickstart](quickstart.md) — install and the commands that work today.
- [Security and responsible use](security.md) — the `--authorize` rules and
  dual-use policy.
