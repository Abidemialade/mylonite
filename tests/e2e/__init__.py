"""Gated live end-to-end tests.

Every test in this package is gated behind ``MYLONITE_LIVE_E2E=1`` and SKIPS in
normal CI (no API key, no network, no subprocess). They exist as the live proof
behind the docs' two-tier claim — run before each release.
"""
