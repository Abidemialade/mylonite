# Running live end-to-end tests

The recorded integration tests under `tests/integration/test_scan_mcp_*_recorded.py`
mock the MCP subprocess and the LLM, so they run in CI under a few seconds
and produce deterministic results. They cover the call-routing logic but
not the wire interaction with real servers.

The **live** counterparts under `tests/integration/test_scan_mcp_*_live.py`
spawn real MCP server subprocesses and call a real LLM. We run them
**before each release** to validate that the bundled-target wiring still
matches the upstream servers.

## Gating

All three live tests check `os.environ["MYLONITE_LIVE_E2E"] == "1"` and
skip otherwise. They also skip individually when their prerequisites
aren't present:

- `npx` (Node.js) for filesystem + github servers.
- `uvx` (uv) for fetch server.
- `ANTHROPIC_API_KEY` env var for the real LLM call.
- `GITHUB_TOKEN` + `MYLONITE_TEST_GITHUB_REPO` env vars for the github
  test.

## Prerequisites (one-time)

```bash
# Node-based MCP servers
npm install -g @modelcontextprotocol/server-filesystem
npm install -g @modelcontextprotocol/server-github

# Python-based MCP server (via uv)
pip install uv
uvx --from mcp-server-fetch mcp-server-fetch --help  # warm the cache

# Anthropic API
export ANTHROPIC_API_KEY=sk-ant-...

# For the github test only — use a throwaway repo with a fine-grained PAT
# scoped to that repo only.
export GITHUB_TOKEN=ghp_throwaway_token
export MYLONITE_TEST_GITHUB_REPO=myhandle/mylonite-test-repo
```

## Running

```bash
MYLONITE_LIVE_E2E=1 pytest tests/integration/test_scan_mcp_filesystem_live.py -v
MYLONITE_LIVE_E2E=1 pytest tests/integration/test_scan_mcp_fetch_live.py -v
MYLONITE_LIVE_E2E=1 pytest tests/integration/test_scan_mcp_github_live.py -v
```

Each test takes 30s–2min depending on cold-start state of the MCP
subprocess. The first run on a clean machine pays the npm/uv install cost
(per `npx -y` semantics, ~50MB downloaded). Subsequent runs hit the warm
cache and start in well under a second.

## Cleanup

- **Filesystem**: the test writes inside `tmp_path`; pytest cleans it
  automatically.
- **Fetch**: stateless; nothing to clean.
- **GitHub**: the test creates real issues in
  `$MYLONITE_TEST_GITHUB_REPO` and does **NOT** auto-close them. The
  MCP server doesn't expose a `close_issue` tool in v1. Run with
  `--max-llm-calls 20` (the test's default) to keep issue creation
  bounded; archive or delete the repo periodically.

## Cost guard

The live tests cap `max_llm_calls` to 20-50 (depending on family) so a
runaway loop can't burn budget. Even at Anthropic's full rate, a single
live test should cost well under $1.
