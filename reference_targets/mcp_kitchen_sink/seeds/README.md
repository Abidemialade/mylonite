# Seed catalogue index

Human index for [`seeds.yaml`](seeds.yaml) — the source of truth for the
reference app's four seeded weaknesses (IDs, summaries, loci, taxonomy tags).
The Mylonite attack patterns that exercise each weakness live in
`src/mylonite/scan/seeds.py` (kitchen-sink subset shown below). Taxonomy IDs
and guards are tabulated in the [package README](../README.md); the full
walkthrough is [`docs/quarry.md`](../../../docs/quarry.md).

| W  | Name                                    | Vulnerable locus (`server_vulnerable`) | Guarded locus (`server_guarded`)            | Exercised by attack patterns (`pattern_id`)                                                                                 |
|----|-----------------------------------------|----------------------------------------|---------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| W1 | tool-description-instruction-smuggling | `list_tools`                            | `list_tools` (description allowlist)        | `tool-description-summary-smuggle`                                                                                            |
| W2 | indirect-injection-via-note-body       | `call_tool` (read_note branch)          | `call_tool` (read_note wraps `<untrusted>`) | `indirect-injection-note-body-direct`, `indirect-injection-note-body-roleplay`, `indirect-injection-note-body-tool-chain`     |
| W3 | unrestricted-web-fetch                 | `call_tool` (web_fetch branch)          | `call_tool` (hostname allowlist)            | `excessive-agency-fetch-attacker-url-direct`, `excessive-agency-fetch-via-note-body`                                          |
| W4 | unconfirmed-email-send                 | `call_tool` (send_email branch)         | `call_tool` (two-step + `confirm_send`)     | `excessive-agency-send-email-direct-unconfirmed`, `excessive-agency-send-email-via-note-injection`                            |

This bank doubles as the planned "mutant set" for the Phase 2 security
mutation score check — see the header comment in `seeds.yaml`.
