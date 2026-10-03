<!-- GENERATED FILE. Do not edit by hand. -->
<!-- Regenerate with: python -m verification.trends -->

# Verification trends

| Version | Date | Model | Layer 1 recall | Layer 2 judge F1 (AgentDojo) | InjecAgent dh F1 | InjecAgent ds F1 | Layer 3 FPR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0.9.0 | 2026-08-29 | anthropic/claude-haiku-4-5-20251001 (layer1/3); ollama/llama3.2:3b (injecagent) | unmeasured (harness defect, see FINDINGS.md) | 41.2% (label inverted; corrected 81.1%, see FINDINGS.md) | 100.0% | 40.0% | 0.0% |
| 0.10.0 | 2026-09-14 | anthropic/claude-haiku-4-5-20251001 (agentdojo judge, layer3); ollama/llama3.2:3b (injecagent record) | not run | 41.2% (label inverted; corrected 81.1%, see FINDINGS.md) | 100.0% | 83.3% | 0.0% |
| 0.11.0 | 2026-10-02 | anthropic/claude-haiku-4-5-20251001 (agentdojo judge, injecagent record) | not run | 41.2% (label inverted; corrected 81.1%, see FINDINGS.md) | vacuous | vacuous | not run |

## Third-party verification campaigns

Live-in-CI runs against real third-party systems, scored against a pre-registered rule rather than a released dataset's own labels -- see each version's own `third-party/README.md` for the full write-up. `met_bar` KEPT cells only; a candidate (`FOUND_UNVALIDATED`) or a smoke pass never counts as KEPT here.

| Version | Date | Targets KEPT (bar met) | Product defects (open issues) | Spend |
| --- | --- | --- | --- | --- |
| 0.12.0 | 2026-10-03 | `mcp-redis`, `server-memory` | 2 (0 open) | anthropic $0.91, ollama $0.00, openai $0.08 |
