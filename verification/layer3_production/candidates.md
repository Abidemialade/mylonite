# Layer 3 — known-good targets (precision / false-positive control)

Layer 3 measures whether Mylonite stays quiet on apps that are **not**
vulnerable. Any finding here is a false positive — a Mylonite bug to fix.

## Clean baselines (easiest first)

| Target | Why it's a clean baseline | How to run |
| --- | --- | --- |
| `reference:guarded` | the guarded kitchen-sink build — every W1–W4 attack is blocked by design | `mylonite scan reference:guarded --output-dir verification/reports/layer3/guarded` then `layer3 score` |
| Bundled `mcp:filesystem` on an empty sandbox | a real MCP server with no attacker-controlled content planted | needs `npx`; scope to a throwaway dir |

## Production-grade candidates (future)

Well-built, non-deliberately-vulnerable MCP servers to scan for false positives.
All must be **trusted** (reputable author, clear license) and run in a sandbox:

- **`server-fetch` *with* a host allowlist** (the defended counterpart to the W3
  external differential — see `verification/EXTERNAL_DIFFERENTIAL.md`). Once upstream issue #2317
  lands, or with a wrapper that blocks internal IPs, this server should yield **0
  findings** — the first external 0-FP precision number (closes the C2/B4 gap). A
  finding here is a Mylonite FP to fix.
- **`mcp-server-email` *with* a confirmation/staging control applied** (the defended
  counterpart to the W4 external differential) — should also yield 0 findings.
- Official `@modelcontextprotocol/server-*` reference servers (filesystem, fetch,
  git, …) pointed at benign, empty scopes — they are not hardened against
  injection but they also carry no planted attack, so a *finding* would be a
  Mylonite false positive worth investigating.
- A small, audited internal MCP app you control (the truest "production-grade"
  precision signal).

## Real-CVE reproduction (deferred)

Reproducing specific in-the-wild MCP CVEs is bespoke per CVE (each needs its own
vulnerable build + oracle) and is out of scope for the first Layer 3 cut. Track
candidates from vulnerablemcp.info and published MCP advisories; add them one at a
time with their own pinned, license-checked source under `verification/SOURCE.md`.
