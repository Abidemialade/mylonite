# CLI reference

Every command, its key options, and a worked example. Run `mylonite COMMAND --help` for
the authoritative, always-current list (the help strings and usage examples live in the
CLI itself). Global options `--api-key-file` and `--env-file` work before any command.

**Exit codes:** `0` ok/kept · `1` `check --enforce`: structural findings present · `2`
config or usage error (incl. an empty scan) · `3` LLM-call budget exceeded · `4` provider
unreachable · `5` test rejected (not kept) · `6` `gate`: the test generator returned
nothing (internal collaborator failure) · `7` `gate`: the validator returned nothing
(internal collaborator failure).

---

## `check` — static structural pre-check

Zero-key, zero-spend on-ramp: connects to a target ONCE (`describe()` — no LLM call, no
attack) and reports structural exposure from the tool schemas alone. Belongs in CI stage
1, next to lint — cheap enough to run on every push.

Options: `--target-file PATH` (required — or set `target_file:` in `mylonite.yaml`);
`--enforce` (exit `1` if any finding is present, instead of reporting and exiting `0` —
the report-then-enforce adoption ramp); `--config mylonite.yaml` (auto-discovered from
`./mylonite.yaml` when present).

```bash
mylonite check --target-file app.yaml
mylonite check --target-file app.yaml --enforce   # CI gate once the surface is clean
```

Reports: consequential tools with no approval-shaped sibling tool, descriptions that
steer the agent, tools taking an apparent network destination, content-processing tools
that could carry an indirect-injection payload, unpinned tool descriptions (paste-ready
digests for `control_config.description_pins`), and which weakness classes the surface
suggests. Every finding is a hint to confirm, never a verdict — `scan`/`gate` are what
prove an attack actually lands.

## `scan` — find weaknesses

Run the exploit-finding loop against a target.

**Target** (positional): `reference:vulnerable` / `reference:guarded` (the bundled
reference app builds), or `mcp:custom` with `--command`/`--arg`. Omit when using `--target-file`
(your own MCP app). Non-reference targets need `--authorize`.

Key options: `--target-file PATH`, `--authorize NAME`, `--model` (any LiteLLM
provider via a `provider/model` prefix, e.g. `openai/gpt-4o`),
`--planner-model`, `--customiser-model`, `--judge-model`, `--max-llm-calls N`,
`--max-concurrent N`, `--output-dir PATH`, `--config mylonite.yaml`, `--dry-run`,
`--allow-no-seed-arm`, `--purpose "…"` (a one-line description of what the app is for;
tailors the probes to its domain — overrides `purpose` in the target file, and is
persisted so `generate`/`validate` reuse it); `--randomize-exfil/--no-randomize-exfil`
(mint a unique exfil address per run so a finding proves the target leaks to ANY
attacker destination, not one demo literal — **defaults ON for live custom-target
scans**, off for the reference/replay path; matches `generate`/`validate`/`gate`).
For a custom target: `--command`, `--arg`,
`--env`, `--scope`, `--system-prompt[-file]`, `--primary-tool`, `--weakness-class`.

**Scaffold mode** — `--scaffold PATH` (with `--command`) introspects an MCP server
(one launch, **no LLM call, no attack**, so no `--authorize` needed) and writes a
commented starter `target.yaml` with suggested `weakness_classes` and auto-detected
`seed_arm`/`effect_probe` candidates. Add `--force` to overwrite. Edit it, then scan
with `--target-file`.

```bash
mylonite scan --command python --arg my_server.py --scaffold app.yaml   # generate the target file
mylonite scan --target-file app.yaml --authorize custom                 # then scan it
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

Options: `target` (the generated dir/file); `--iterations N` (default 5); `--model`
(any LiteLLM provider via a `provider/model` prefix); `--target-file PATH` (re-drive
your REAL app instead of the reference build);
`--authorize` (**required** when `--target-file` names a custom target — must equal the
target's declared `scope`, or its family name if no scope is declared; see
[target-file.md](target-file.md)); `--fast`
(skip the differential leg — faster, weaker); `--randomize-exfil/--no-randomize-exfil`
(mint a unique exfil address per run so the finding proves the target blocks ANY attacker
destination, not one demo literal — **defaults ON for live custom-target runs**, off for the
reference/replay path); `--iteration-timeout S`.

```bash
mylonite validate .mylonite/generated/my-finding --target-file app.yaml --authorize my-app
```

## `gate` — scan → generate → validate → PR (the full pipeline)

The whole pipeline; only a kept test makes it through. Scaffolds the CI workflows. The
PR body always includes a **Proven fix** (control-efficacy findings) or **Recommended
fix** (otherwise) — an evidence-anchored recommendation naming the actual tool and
argument that landed the exploit, as a fenced code sketch. See [Reading the
results](reading-results.md#the-gating-pr).

Options: `target` or `--target-file`; `--authorize`; `--open-pr` (push a branch + open
the PR via `gh`); `--config`; `--model` (any LiteLLM provider via a `provider/model`
prefix); `--out PATH`; `--max-llm-calls`;
`--iterations N` (validation-leg iterations, **default 3** — the kept verdict reflects
reproducibility across runs; pass `1` for the fastest, weakest gate); `--runs-on LABEL`
(GitHub runner; use a self-hosted label for in-perimeter MCP backends);
`--workflows/--no-workflows`; `--llm-enrich` (append a labelled, unverified LLM fix
suggestion, rendered after the structural recommendation above); `--fast`;
`--randomize-exfil/--no-randomize-exfil` (defaults ON for a live custom target).

```bash
mylonite gate --target-file app.yaml --authorize my-app --open-pr
```

## `report` — render findings

Render a saved scan or validation as a terminal trust panel — including the same
evidence-anchored recommendation the gating PR carries — offline. See [Reading the
results](reading-results.md).

Options: `target` (a scan/generated dir or `*_report.json`); `--sarif PATH` (SARIF 2.1.0
for GitHub code scanning); `--json PATH` (machine-readable finding bundle). Both carry
the differential proof, the OWASP/ASI/ATLAS/NIST tags, and the same recommendation.

```bash
mylonite report .mylonite/generated/my-finding --sarif out.sarif --json finding.json
```

## `ablate` — score the safeguards

Toggle each AI safeguard and report which are **load-bearing**, **security theater**, or
**redundant**. See [the control-efficacy check](validation.md#the-control-efficacy-check).

Options: `--target-file PATH` (required); `--authorize`; `--controls W2,W3,W4`;
`--iterations N`; `--redundancy` (all-minus-one, to tell redundant from theater);
`--max-seeds N`; `--model` (any LiteLLM provider via a `provider/model` prefix).

```bash
mylonite ablate --target-file app.yaml --authorize my-app --controls W2,W4 --redundancy
```

> **Scaffolding moved.** The old `mylonite init-target` command is now `mylonite scan
> --scaffold PATH` (see [`scan`](#scan-find-weaknesses) above). See [Test your own
> app](test-your-app.md) and the [target.yaml reference](target-file.md).

## `version`

Print the installed version.

```bash
mylonite version
```

---

### Run config (`mylonite.yaml`)

`scan` and `gate` accept `--config mylonite.yaml` (auto-discovered from `./mylonite.yaml`)
to declare `target_file` / `authorize` / `provider` / `model` / budget once. An explicit
flag always wins.
