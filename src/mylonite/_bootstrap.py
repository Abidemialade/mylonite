"""Process-environment bootstrap shared by the CLI and the library/testkit paths.

The CLI's Typer ``_root`` callback is the only place that prepares the runtime
environment (stdio encoding, TLS trust store, secret redaction). Library callers
— most importantly an emitted regression test running under pytest, which calls
``mylonite.testkit`` directly and never goes through the CLI — bypass that
callback. This module holds the pieces that BOTH paths need, so the deliverable
behaves the same whether it's driven by ``mylonite scan`` or by ``pytest``.

Keep this module dependency-light: stdlib plus a best-effort optional import only.
It must be importable without litellm or any scan/plugin machinery.
"""

from __future__ import annotations

import os


def enable_truststore() -> bool:
    """Use the OS trust store for TLS when ``truststore`` is installed.

    Enterprise environments behind a TLS-inspecting proxy present a CA that the
    OS trusts but Python's bundled certifi does not — so provider calls fail
    ``CERTIFICATE_VERIFY_FAILED``. ``truststore`` (an optional ``[enterprise]``
    extra) bridges to the OS trust store without disabling verification. Opt out
    with ``MYLONITE_NO_TRUSTSTORE=1``.

    Best-effort and idempotent: an absent/failed import or an opt-out is a silent
    no-op (verification stays at certifi defaults). Returns ``True`` if injection
    ran, ``False`` otherwise — so callers/tests can observe the outcome.
    """
    if os.environ.get("MYLONITE_NO_TRUSTSTORE"):
        return False
    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception:  # not installed, or injection unsupported → leave defaults
        return False
    return True
