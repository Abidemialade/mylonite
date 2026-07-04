# CLI reference

Every command, its key options, and a worked example. Run `mylonite COMMAND --help` for
the authoritative, always-current list (the help strings and usage examples live in the
CLI itself). Global options `--api-key-file` and `--env-file` work before any command.

**Exit codes:** `0` ok/kept · `2` config or usage error (incl. an empty scan) · `3`
LLM-call budget exceeded · `4` provider unreachable · `5` test rejected (not kept).

---

## `scan` — find weaknesses

Run the exploit-finding loop against a target.

**Target** (positional): `reference:vulnerable` / `reference:guarded` (the bundled
reference app builds), or `mcp:custom` with `--command`/`--arg`. Omit when using `--target-file`
(your own MCP app). Non-reference targets need `--authorize`.

Key options: `--target-file PATH`, `--authorize NAME`, `--provider`, `--model`,
`--planner-model`, `--customiser-model`, `--judge-model`, `--max-llm-calls N`,
`--max-concurrent N`, `--output-dir PATH`, `--config mylonite.yaml`, `--dry-run`,
`--allow-no-seed-arm`, `--purpose "…"` (a one-line description of what the app is for;
tailors the probes to its domain — overrides `purpose` in the target file, and is
persisted so `generate`/`validate` reuse it). For a custom target: `--command`, `--arg`,
`--env`, `--scope`, `--system-prompt[-file]`, `--primary-tool`, `--weakness-class`.

**Scaffold mode** — `--scaffold PATH` (with `--command`) introspects an MCP server
(one launch, **no LLM call, no attack**, so no `--authorize` needed) and writes a
commented starter `target.yaml` with suggested `weakness_classes` and auto-detected
`seed_arm`/`effect_probe` candidates. Add `--force` to overwrite. Edit it, then scan
with `--target-file`.

```bash
mylonite scan --command python --arg my_server.py --scaffold app.yaml   # generate the target file
mylonite scan --target-file app.yaml --authorize me                     # then scan it
```

## `generate` — emit the regression test

Emit a pytest regression test from a confirmed exploit. Offline and deterministic — no
LLM call. Carries the compliance metadata.

Options: `scan_path` (an `exploit_*.json` or scan dir) or `--latest`; `--out PATH`;
`--target-file PATH` (custom targets — co-locates the YAML so the live test re-drives
your app); `--prove-control` (emit a control-efficacy test).

```bash
mylonite generate --latest --out .mylonite/generated/my-finding
```

## `validate` — prove the test

Run the generated test through the [validation engine](validation.md), LIVE. On a real
`--target-file` app the [control-efficacy check](validation.md#the-control-efficacy-check)
holds the model constant and toggles only the safeguard; against the bundled reference app
it runs the two-build differential. A test is **kept** only when it discriminates reliably.

Options: `target` (the generated dir/file); `--iterations N` (default 5); `--provider`,
`--model`; `--target-file PATH` (re-drive your REAL app instead of the reference build); `--fast`
(skip the differential leg — faster, weaker); `--randomize-exfil/--no-randomize-exfil`
(mint a unique exfil address per run so the finding proves the target blocks ANY attacker
destination, not one demo literal — **defaults ON for live custom-target runs**, off for the
reference/replay path); `--iteration-timeout S`. `--prove-control` is a back-compat no-op
(the differential is now default).

```bash
mylonite validate .mylonite/generated/my-finding --target-file app.yaml
```

## `gate` — scan → generate → validate → PR (the full pipeline)

The whole pipeline; only a kept test makes it through. Scaffolds the CI workflows.

Options: `target` or `--target-file`; `--authorize`; `--open-pr` (push a branch + open
the PR via `gh`); `--config`; `--provider`, `--model`; `--out PATH`; `--max-llm-calls`;
`--iterations N` (validation-leg iterations, **default 3** — the kept verdict reflects
reproducibility across runs; pass `1` for the fastest, weakest gate); `--runs-on LABEL`
(GitHub runner; use a self-hosted label for in-perimeter MCP backends);
`--workflows/--no-workflows`; `--llm-enrich` (append a labelled, unverified LLM fix
suggestion); `--fast`; `--randomize-exfil/--no-randomize-exfil` (defaults ON for a live
custom target).

```bash
mylonite gate --target-file app.yaml --authorize me --open-pr
```

## `report` — render findings

Render a saved scan or validation as a terminal trust panel, offline. See [Reading the
results](reading-results.md).

Options: `target` (a scan/validated dir or `*_report.json`); `--sarif PATH` (SARIF 2.1.0
for GitHub code scanning); `--json PATH` (machine-readable finding bundle). Both carry
the differential proof and the OWASP/ASI/ATLAS/NIST tags.

```bash
mylonite report .mylonite/validated/my-finding --sarif out.sarif --json finding.json
```

## `ablate` — score the safeguards

Toggle each AI safeguard and report which are **load-bearing**, **security theater**, or
**redundant**. See [the control-efficacy check](validation.md#the-control-efficacy-check).

Options: `--target-file PATH` (required); `--authorize`; `--controls W2,W3,W4`;
`--iterations N`; `--redundancy` (all-minus-one, to tell redundant from theater);
`--max-seeds N`; `--provider`, `--model`.

```bash
mylonite ablate --target-file app.yaml --authorize me --controls W2,W4 --redundancy
```

> **Scaffolding moved.** The old `mylonite init-target` command is now `mylonite scan
> --scaffold PATH` (see [`scan`](#scan-find-weaknesses) above). See [Test your own
> app](test-your-app.md) and the [target.yaml reference](target-file.md).

## `demo` — the reference-app playground

Zero-config: run the vulnerable-vs-guarded differential on the bundled reference agent.
Replays recorded fixtures by default; `--live` makes real calls. See [the reference app](quarry.md).

```bash
mylonite demo            # offline, instant
mylonite demo --live     # real calls (~a minute, a few cents on Haiku)
```

## `doctor` — preflight the provider

Diagnose provider connectivity before a live scan. Exit `4` if unreachable.

Options: `--provider`, `--model`, `--config`.

```bash
mylonite doctor --provider anthropic
```

## `taxonomy list` — browse the threat data

List entries from a bundled threat taxonomy. See [Standards mapping](standards-mapping.md).

```bash
mylonite taxonomy list --framework owasp-llm
```

## `version`

Print the installed version.

```bash
mylonite version
```

---

### Run config (`mylonite.yaml`)

`scan` and `gate` accept `--config mylonite.yaml` (auto-discovered from `./mylonite.yaml`)
to declare `target_file` / `authorize` / `provider` / `model` / budget once. An explicit
flag always wins. `doctor` reads it too, so it pings the same model your scan will use.
