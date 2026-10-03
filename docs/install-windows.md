# Installing on Windows

Mylonite runs on Windows, but a few platform defaults bite. This page collects
the friction points so a Windows install takes minutes, not half an hour.

## 1. Pick a supported Python (3.11–3.14)

Mylonite requires `>=3.11,<3.15`. The upper bound tracks **litellm**, which
declares `<3.15`, so on a newer Python the install fails with a resolver error.

If you have more than one Python installed, pick a supported one explicitly
with the `py` launcher:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python --version   # 3.14.x
```

Any of 3.11–3.14 works: `py -3.12 -m venv .venv` is fine too.

All commands below assume this venv is active.

## 2. Clone with the schannel TLS backend (corporate proxy)

Behind a TLS-inspecting proxy, git's bundled OpenSSL backend can't find the org
CA and fails with `unable to get local issuer certificate`. Use Windows'
native certificate store:

```powershell
git -c http.sslBackend=schannel clone https://github.com/Abidemialade/mylonite
```

## 3. Install Mylonite (+ the reference target for the test suite)

```powershell
pip install -e ".[dev]"
# The full test suite imports the deliberately-vulnerable reference target,
# which is a SEPARATE editable package:
pip install -e ./reference_targets/mcp_kitchen_sink
```

For **live scans** behind a corporate proxy, provider calls can fail
`CERTIFICATE_VERIFY_FAILED` unless Mylonite reads your OS's own certificate store —
see [Enterprise networking](enterprise-networking.md) for why. Nothing extra to
install: `truststore` is a base dependency of `mylonite` itself (and so already
present in the `[dev]` install above), not a separate add-on step.

## 4. UTF-8 output — handled automatically, with a fallback

The Windows console defaults to the legacy `cp1252` code page, which used to crash on
the non-ASCII glyphs Mylonite prints (✓, │, …). The `mylonite` CLI now forces UTF-8 on
its own stdout/stderr before any output (`errors="replace"`, so it degrades rather than
crashes even if a stream still can't encode something) — verified locally against a
`chcp 1252` console with `PYTHONUTF8` unset: `mylonite scan reference:vulnerable` renders
cleanly. You should not need to set anything for `mylonite` commands themselves.

`pytest` run directly (not through the `mylonite` CLI) does **not** get this automatic
reconfiguration, since it never goes through `cli.py`'s startup path. If you see mangled
output or a `UnicodeEncodeError` from a plain `pytest` run, force UTF-8 for the session as
a fallback:

```powershell
$env:PYTHONUTF8 = "1"
```

Add it to your profile (or set it as a user environment variable) to make it permanent.
CI does run a Windows job (`test-windows`, plus a Windows leg of the offline demo), so an
encoding regression should be caught there too — but if you hit one locally that CI missed,
it is worth filing, since Windows-only failures are the easiest class to miss in review.

## 5. Verify

```powershell
mylonite version
pytest -q
```

A green suite (run from the project root) confirms the install. If a live `scan`/`gate`/
`validate` run can't reach the configured provider, it classifies the failure as
auth/TLS/network/rate-limit with a concrete remedy rather than a raw traceback.
