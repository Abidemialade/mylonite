# Installing on Windows

Mylonite runs on Windows, but a few platform defaults bite. This page collects
the friction points so a Windows install takes minutes, not half an hour.

## 1. Pick a supported Python (3.11–3.13, not 3.14)

Mylonite requires `>=3.11,<3.14`. The upper bound tracks **litellm**, which has
no installable wheel on Python 3.14 yet — so if your system default is 3.14 the
install fails with a confusing resolver error.

Install Python 3.12 (or 3.11/3.13) and invoke it explicitly via the `py`
launcher:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python --version   # 3.12.x
```

All commands below assume this 3.12 venv is active.

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

For **live scans** behind a corporate proxy, also install the OS-trust-store
helper so provider calls don't fail `CERTIFICATE_VERIFY_FAILED` — see
[Enterprise networking](enterprise-networking.md). It now also ships in `[dev]`,
so a dev install already has it:

```powershell
pip install -e ".[enterprise]"   # end users / non-dev installs
```

## 4. Force UTF-8 output (`PYTHONUTF8=1`)

The Windows console defaults to the legacy `cp1252` code page, which crashes on
the non-ASCII glyphs Mylonite prints (✓, │, …). Force UTF-8 for the session:

```powershell
$env:PYTHONUTF8 = "1"
```

Add it to your profile (or set it as a user environment variable) to make it
permanent. CI runs on Linux and never catches this, so it only shows up locally.

## 5. Verify

```powershell
$env:PYTHONUTF8 = "1"
mylonite version
pytest -q
```

A green suite (run from the project root) confirms the install. If a scan reaches
a provider, `mylonite doctor` classifies any TLS/auth/network failure with a
concrete remedy.
