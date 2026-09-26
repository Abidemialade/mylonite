# Publishing `mcp-kitchen-sink` to PyPI (front-door handoff)

> **Status: 0.2.1 (metadata only) follows 0.2.0.** 0.2.1 adds the Python 3.14
> classifier; the code, tool names, descriptions and schemas are byte-identical
> to 0.2.0, so the demo fixtures stay valid and need no re-record.
>
> 0.2.0 was published 2026-09-14; v0.1.0 went to PyPI on 2026-08-05.
> 0.2.0 is the release in which the guarded twin's behaviour changed: the
> `<untrusted>` envelope was replaced by a code-enforced taint gate, which
> changes `read_note`'s observable output and every tool schema hash derived
> from it.
>
> **Why the two had to move together.** `mylonite`'s `[demo]` extra pins an
> exact version, and the demo's replay cache key folds in the tool schemas. The
> demo fixtures were recorded against the 0.2.0 source, so while the pin still
> named 0.1.0 anyone running `pip install "mylonite[demo]"` would have received
> the 0.1.0 wheel and missed every fixture. CI's `demo` job installs the
> published wheel precisely to catch that, and it was red until 0.2.0 shipped.
> The root `pyproject.toml` now pins `mcp-kitchen-sink==0.2.1` (0.2.0's code with
> the 3.14 classifier).
>
> The base `pip install mylonite` is unaffected and **never** pulls this
> deliberately-vulnerable agent — that invariant is preserved.

## Releasing a new version

```bash
git tag ks-vX.Y.Z && git push origin ks-vX.Y.Z
```

`.github/workflows/release-kitchen-sink.yml` builds from this directory and
publishes TestPyPI → PyPI via Trusted Publishing. It publishes irreversibly, so
it is left to a maintainer rather than automated on merge. **Afterwards**, in
this order: re-pin the exact version in the root `pyproject.toml`, re-record the
demo fixtures if any tool name or description moved
(`python scripts/record_demo_fixtures.py --force`), then confirm the `demo` job
is green.

## Status (published 2026-08-05)

- Builds cleanly: `python -m build reference_targets/mcp_kitchen_sink` → sdist + wheel.
- `twine check` **PASSED** on both artifacts (metadata is PyPI-valid).
- Version `0.1.0`, Apache-2.0, `requires-python >=3.11`.
- The `mcp` extra is pinned `>=1.0,<2.0`, matching the root package. **This pin had to
  land before the first release**: `mcp` 2.0 renamed `Tool.inputSchema` → `input_schema`
  and `CallToolResult.isError` → `is_error`, which this target's server shim uses, and a
  published version's metadata is immutable — an unbounded floor would have baked the
  breakage in permanently.
- It depends on `mylonite` (on PyPI, latest published 0.7.5). Independent packages,
  each resolves on its own — publish order does not matter.
- **The release automation is already wired**: `.github/workflows/release-kitchen-sink.yml`
  builds from this directory and publishes TestPyPI → PyPI via Trusted Publishing on a
  `ks-v*` tag. Only the one-time PyPI-side setup below is outstanding.

## Step 1 — one-time PyPI setup (maintainer, browser) — ✅ done

The workflow exists but cannot publish until the projects exist and trust this repo. Do
this on **both** [pypi.org](https://pypi.org/manage/account/publishing/) and
[test.pypi.org](https://test.pypi.org/manage/account/publishing/):

1. Go to *Your projects → Publishing → Add a new pending publisher*.
2. Fill in exactly:
   - **PyPI project name:** `mcp-kitchen-sink`
   - **Owner:** `Abidemialade`
   - **Repository name:** `mylonite`
   - **Workflow name:** `release-kitchen-sink.yml`  ← note: *not* `release.yml`
   - **Environment name:** `pypi` on PyPI, `testpypi` on TestPyPI
3. Save. (A *pending* publisher is correct here — the project doesn't exist yet; PyPI
   creates it on the first successful upload.)

The workflow filename is what distinguishes this from the `mylonite` publisher, so the
two projects can safely share the `pypi`/`testpypi` environment names.

## Step 2 — release it — ✅ done (v0.1.0, 2026-08-05)

```bash
git tag ks-v0.1.0
git push origin ks-v0.1.0
```

That triggers `release-kitchen-sink.yml`: build → `twine check` → TestPyPI → PyPI. Watch
it with `gh run watch`. Nothing else is needed — no local credentials, no manual upload.

<details>
<summary>Fallback — one-off manual upload (only if Trusted Publishing can't be set up)</summary>

Requires a PyPI API token. Prefer Step 2; this path leaves no audit trail in Actions.

```powershell
python -m build reference_targets/mcp_kitchen_sink --outdir dist_ks
python -m twine check dist_ks/*        # expect: PASSED, PASSED

# TestPyPI first (recommended dry run):
python -m twine upload --repository testpypi dist_ks/*
python -m pip install --index-url https://test.pypi.org/simple/ `
    --extra-index-url https://pypi.org/simple/ mcp-kitchen-sink   # resolves mylonite from real PyPI

# then the real index:
python -m twine upload dist_ks/*
```
</details>

**Option B — one-off manual upload (fastest, a PyPI API token).**
```powershell
# TestPyPI first (recommended dry run):
python -m twine upload --repository testpypi dist_ks/*
python -m pip install --index-url https://test.pypi.org/simple/ `
    --extra-index-url https://pypi.org/simple/ mcp-kitchen-sink   # resolves mylonite from real PyPI

# then the real index:
python -m twine upload dist_ks/*
```

## Step 3 — verify the front door from a clean venv

```powershell
python -m venv /tmp/clean-verify
/tmp/clean-verify/Scripts/Activate.ps1
pip install mylonite mcp-kitchen-sink   # both resolve from PyPI, no clone
$env:ANTHROPIC_API_KEY = "sk-ant-..."  # pragma: allowlist secret (placeholder)
mylonite scan reference:vulnerable      # finds the seeded weaknesses
mylonite scan reference:guarded         # comes up clean
```

The README, `docs/quickstart.md` and `docs/quarry.md` document
`pip install "mylonite[demo]"` as the primary path for trying the reference app;
`pip install mylonite mcp-kitchen-sink` still works and installs the same two
packages.

**Releasing this package is not routine.** `mylonite`'s `[demo]` extra pins it with
`==`, and the offline demo's recorded fixtures are keyed on this package's tool
schemas (the v2 replay cache key folds in `tools`). A release that renames a tool or
edits a description invalidates those fixtures inside every `mylonite` wheel already
on PyPI, and a fixture miss is not loud — it is caught by the demo runner's
post-run recorder inspection, which a user experiences as the demo refusing to run.
Pair any such release with a fixture re-record (`scripts/record_demo_fixtures.py`)
and a matching bump of the pin in `mylonite`'s `pyproject.toml`.

## Environment caveats

- TLS to PyPI/TestPyPI can fail cert verification behind a TLS-inspecting proxy —
  `truststore` is now a base dependency of `mylonite` and auto-enables the OS trust store,
  but `twine` itself may still need `SSL_CERT_FILE` set or `--cert`. See
  `docs/enterprise-networking.md`.
- Endpoint-protection software can interfere with build/upload steps — if a step stalls,
  retry outside a scan window.
