# Publishing `mcp-kitchen-sink` to PyPI (front-door handoff)

> **Why this matters.** `pip install "mylonite[demo]"` declares
> `mcp-kitchen-sink>=0.1.0`, but that package is **not on PyPI yet**, so the `[demo]`
> extra is currently inert — a clean `pip install "mylonite[demo]"` can't resolve it and
> users must clone the repo to run `mylonite demo`. Publishing this package once is what
> makes `mylonite demo` work from a clean install (the plan's "fix the front door"). The
> base `pip install mylonite` is unaffected and **never** pulls this deliberately-
> vulnerable agent — that invariant is preserved.

## Status (verified this pass)

- Builds cleanly: `python -m build reference_targets/mcp_kitchen_sink` → sdist + wheel.
- `twine check` **PASSED** on both artifacts (metadata is PyPI-valid).
- Version `0.1.0`, Apache-2.0, `requires-python >=3.11`.
- It depends on `mylonite` (already on PyPI at 0.7.3), and `mylonite[demo]` depends back
  on it. This circular *extra* is fine for pip: each resolves independently. Publish order
  does not matter.

## Step 1 — build the artifacts

```powershell
python -m build reference_targets/mcp_kitchen_sink --outdir dist_ks
python -m twine check dist_ks/*       # expect: PASSED, PASSED
```

## Step 2 — publish (maintainer credentials required — pick ONE)

**Option A — Trusted Publisher (OIDC), the same path `mylonite` uses.**
1. On PyPI (and TestPyPI), create the project `mcp-kitchen-sink` and add a Trusted
   Publisher pointing at this repo + the publish workflow + a `pypi` environment, exactly
   as was done for `mylonite` (that OIDC exchange is already known-good — it published
   `mylonite` 0.7.3).
2. Add a tag-triggered job (mirror `.github/workflows/release.yml`) that builds from
   `reference_targets/mcp_kitchen_sink/` and `pypa/gh-action-pypi-publish`. A separate tag
   prefix (e.g. `ks-v0.1.0`) keeps it independent of `mylonite` releases.

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
python -m venv /tmp/clean-demo
/tmp/clean-demo/Scripts/Activate.ps1
pip install "mylonite[demo]"          # must now resolve mcp-kitchen-sink from PyPI
mylonite demo                          # 2 exploits on vulnerable, 0 on guarded — no clone
```

When that runs green from a clean install, bump the README/CHANGELOG note that currently
says the `[demo]` extra is "inert until published" to "available" and drop the
clone-first fallback as the primary path.

## Caveats specific to this machine

- TLS to PyPI/TestPyPI can fail cert verification behind the corporate proxy — `truststore`
  is now a base dependency of `mylonite` and auto-enables the OS trust store, but `twine`
  itself may still need `SSL_CERT_FILE` set or `--cert`. See `docs/enterprise-networking.md`.
- Local AV (Norton) has interfered with build/upload steps before — if a step stalls, retry
  outside an AV scan window.
