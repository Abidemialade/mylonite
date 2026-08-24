# Releasing & versioning

How a Mylonite release is cut, what the version numbers mean, and what the
automation will refuse to let you do.

## The happy path

```bash
python scripts/prepare_release.py 0.8.0   # bump + roll the CHANGELOG + refresh the baseline
git diff                                  # review it
# commit, open a PR, merge to main
git tag v0.8.0 && git push origin v0.8.0  # this is what publishes
```

`prepare_release.py` deliberately does **not** tag or push. Pushing the tag is
the single irreversible act in the process, and it stays a human decision.

Before tagging, you can rehearse the exact check the release will run:

```bash
python scripts/prepare_release.py --check 0.8.0
```

## What the automation checks for you

A pushed `vX.Y.Z` tag runs `gate → ci → build → testpypi → pypi →
github-release`. Everything irreversible is downstream of the first two.

| Gate | What it refuses |
|---|---|
| `gate` | A tag that doesn't match `version.py`, a `pyproject.toml` that disagrees, a missing or blank `## [X.Y.Z]` CHANGELOG section, a missing link-reference |
| `ci` | Any test, lint, type, or packaging failure **on the tagged commit** |
| `build` | A distribution that won't build or whose metadata `twine` rejects |

This exists because of a specific history: 0.7.6 and 0.7.7 both merged with the
version bump or the CHANGELOG update unfinished and no tag ever pushed, and
0.7.8's GitHub Release came out with an empty body. Those are now mechanical
failures rather than things to remember.

Two things worth knowing about the gate:

- It reports **every** problem it finds, not just the first.
- It runs **before** the build. A PyPI upload cannot be undone and a version
  number cannot be reused, so nothing reaches PyPI on a tag the gate rejects.

### Tag format

The trigger is `v[0-9]+.[0-9]+.[0-9]+` — any plain `vX.Y.Z`. Prereleases
(`v1.0.0rc1`) deliberately do **not** match, because this workflow publishes
straight to PyPI.

If a release fails late (say a GitHub outage during `github-release`), don't
invent a throwaway version — re-run the workflow via **Actions → Release → Run
workflow** and give it the existing tag.

## Versioning policy

Mylonite follows [Semantic Versioning](https://semver.org/), with one rule that
matters more than any other right now:

!!! warning "While the version starts with `0.`, the **minor** position carries breaking changes."

    `0.7.x → 0.8.0` is **not** a safe upgrade. Pin an exact version if you
    depend on Mylonite's CLI surface or output formats.

This documents what the project has actually done rather than adding a new rule:
0.7.4 removed `scan --adaptive`, `--synthesize`, `report --html` and `export`
outright, and 0.8.0 removes `demo`, `init`, `doctor` and `taxonomy list` and
changes which control each weakness class is guarded by.

| Position | While `0.x` | Examples from this project |
|---|---|---|
| major | reserved for 1.0.0 | — |
| minor | features **and** breaking changes | commands removed (0.7.4, 0.8.0); primary W1/W2 controls swapped (0.8.0) |
| patch | fixes only, no surface change | 0.7.7's claim corrections; 0.7.8's execution-context fix |

### The road to 1.0.0

1.0.0 is when the deprecation promise starts, so it should not be spent on a
version number alone. The criteria are meant to be checkable, not aspirational:

1. All five `CONTRACT_VERSION`s at `>= 1.0.0`, with a written deprecation window.
2. The plugin registry's compatibility rules exercised against a real
   third-party plugin, not only the bundled reference implementations.
3. An external differential published in `verification/` — a finding proven
   against a control **the project did not author** (see
   [Verification](../verification.md)).
4. A stated precision/recall floor for the bundled corpus, enforced in CI.
5. A supported-version window in `SECURITY.md`.

## Two independent version axes

The package version and the extension contracts move separately. Nothing links
them, and a contract bump does not imply a package bump or the reverse.

| Contract | Current |
|---|---|
| `attack_module` | 0.1.0 |
| `compliance_mapper` | 0.1.0 |
| `test_generator` | 0.2.0 |
| `target_adapter` | 0.5.0 |
| `validator` | 0.5.0 |

**A contract major bump is a bigger event than a package major bump.**
`mylonite.plugins.registry` *refuses* to load a plugin whose major differs and
only warns on a minor mismatch, so bumping a contract's major breaks every
third-party plugin built against it, immediately. It additionally requires an
issue tagged `contract-change` open for at least a week — see
[GOVERNANCE.md](https://github.com/Abidemialade/mylonite/blob/main/GOVERNANCE.md).

!!! note "Known gap"

    Only `target_adapter` and `validator` are pinned by literal assertions
    (`tests/contracts/test_attack_session_contract.py`,
    `tests/contracts/test_validation_metrics.py`). The other three can be bumped,
    or left stale, without any test noticing. Worth closing before 1.0.0.

## Known-untagged history

Three versions are documented in `CHANGELOG.md` as released but have no tag and
were never published. The work shipped; only the release ceremony was skipped.
They are kept, not deleted — the entries are accurate about what was built.

| Version | What happened | Its link points at |
|---|---|---|
| 0.6.0 | Release commit `529ff26` landed on `main`, never tagged. Much of it was then removed again in 0.7.4. | the commit |
| 0.7.1 | Squash-merged into the commit `v0.7.3` tags | `v0.7.3` |
| 0.7.2 | Same | `v0.7.3` |

**Do not create these tags retroactively.** `v0.6.0` matches `release.yml`'s
trigger, so pushing it would publish a months-old build to PyPI under a version
number that can never be reused. `tests/test_changelog.py` enforces this via
`KNOWN_UNTAGGED`.

## The `.secrets.baseline` step

Editing `CHANGELOG.md` shifts the line numbers of the deliberately-fake
credentials `detect-secrets` has baselined in it, which fails CI's `precommit`
and `security` jobs. `prepare_release.py` refreshes the baseline for you; if you
do it by hand:

```bash
git ls-files | xargs detect-secrets scan --baseline .secrets.baseline
git add .secrets.baseline
```

`xargs` is load-bearing. `filenames` is a *positional* argument, so piping
straight in passes zero files — it scans nothing, writes nothing, and exits `0`.
That silent no-op is why this problem recurred for 0.7.7 *and* 0.7.8 after being
written down: the documented command never worked.

On Windows, normalise the `results` keys back to forward slashes afterwards —
`detect-secrets` writes them with `os.sep`, and a backslash-keyed baseline
matches nothing on ubuntu, making every entry read as a brand-new secret.

Verify with the hook (the baseline must be **staged** first, or it aborts before
scanning). Exit `0` is clean, `3` means "baseline updated", only `1` is a real
finding:

```bash
git ls-files | xargs detect-secrets-hook --baseline .secrets.baseline
```

## Before a release

Run the [live end-to-end tests](live-e2e-tests.md). They are gated behind
`MYLONITE_LIVE_E2E=1` and don't run in CI, so a break in the real wire
interaction with MCP servers or providers only shows up here.

Also run the CLI from a real terminal on Windows. CI is ubuntu-only and never
catches the cp1252 console-encoding class of bug.

## Kitchen-sink releases

`mcp-kitchen-sink` — the deliberately-vulnerable reference target — is a
separate PyPI package released on its own `ks-vX.Y.Z` tag prefix, so a routine
`mylonite` release never republishes it. It has the same version gate and
deliberately keeps **no** CHANGELOG of its own and **no** GitHub Release (a
`gh release create` would mark the vulnerable target as the repo's *Latest*
release).

!!! warning "Coordination constraint"

    The published `mcp-kitchen-sink` 0.1.0 pins `mcp<2.0` in immutable
    distribution metadata. Any move to mcp 2.0 therefore needs a **paired**
    `ks-v0.2.0` and `vX.Y.Z` release — bumping the root package alone leaves an
    unsatisfiable combination for anyone installing both.
