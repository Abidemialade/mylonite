# Publishing `mcp-kitchen-sink` to PyPI (front-door handoff)

> **Status: done.** `mcp-kitchen-sink` v0.1.0 was published to PyPI on 2026-08-05, so
> `pip install mylonite mcp-kitchen-sink` resolves both packages from a clean install
> with no clone needed. The base `pip install mylonite` is unaffected and **never**
> pulls this deliberately-vulnerable agent — that invariant is preserved. (The
> `mylonite[demo]` extra that originally wrapped this install has since been retired
> along with the `mylonite demo` command — see CHANGELOG.md.) This doc is
> kept as the record of how the release was set up, for future re-releases (`ks-vX.Y.Z`
> tags) of this package.

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

The README, `docs/quickstart.md` and `docs/quarry.md` document `pip install mylonite
mcp-kitchen-sink` as the primary path for trying the reference app.

## Caveats specific to this machine

- TLS to PyPI/TestPyPI can fail cert verification behind the corporate proxy — `truststore`
  is now a base dependency of `mylonite` and auto-enables the OS trust store, but `twine`
  itself may still need `SSL_CERT_FILE` set or `--cert`. See `docs/enterprise-networking.md`.
- Local AV (Norton) has interfered with build/upload steps before — if a step stalls, retry
  outside an AV scan window.
