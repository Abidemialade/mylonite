"""Pinned fetch of external datasets/targets (no vendoring).

Everything is fetched at a **pinned commit** (the raw URL carries the SHA, so the
content is fixed); InjecAgent additionally verifies each file against a recorded
**sha256** digest. This is the supply-chain guard that keeps the "third-party
ground truth" claim honest. Nothing is committed to the repo; downloads land in a
gitignored ``.cache/``.

Provenance for every pin lives in ``verification/SOURCE.md``.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import sys
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

_CACHE_ROOT = Path(__file__).with_name(".cache")

# --- InjecAgent (UIUC, MIT) --------------------------------------------------
INJECAGENT_COMMIT = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
_INJECAGENT_BASE = (
    f"https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/{INJECAGENT_COMMIT}/data/"
)
#: filename -> sha256 (recorded from the pinned commit; see SOURCE.md).
INJECAGENT_FILES: dict[str, str] = {
    "test_cases_dh_base.json": "0a8186468d21389af432e8c7b399ae42264d1b93a07b65c7a489468508604305",
    "test_cases_dh_enhanced.json": "885602716b72c18af80695ce6c2e1f242fa03163bc90b0788b0c5e4ab6216d50",
    "test_cases_ds_base.json": "4daab35c62a3845e8b9400f4dca58b9c9f37e57cd33b2337552557fbb26282e9",
    "test_cases_ds_enhanced.json": "7bc510868df032511053fc40e8470e68a041fb7148d055112093594bf73ab0ce",
    "tools.json": "e21a8f70b1d5de4677d6d52642936a322655d79b17a72c84f600550384083a1e",
}


def _enable_truststore() -> None:
    """Use the OS trust store for TLS where available (corporate-proxy friendly).

    This machine's Python can fail cert verification against public hosts behind
    a proxy; ``truststore`` resolves it. Best-effort — absence is non-fatal.
    """
    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception:
        # DCR-0001: best-effort, but never SILENTLY so — a swallowed
        # ImportError/inject failure here previously surfaced only as a
        # confusing downstream TLS verification error with no clue that
        # truststore was the missing piece.
        logger.debug("truststore injection failed (best-effort, continuing)", exc_info=True)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _fetch_one(url: str, dest: Path, expected_sha256: str) -> Path:
    if dest.exists() and _sha256(dest) == expected_sha256:
        return dest  # cached + verified
    dest.parent.mkdir(parents=True, exist_ok=True)
    _enable_truststore()
    with urllib.request.urlopen(url) as resp:
        data = resp.read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise RuntimeError(
            f"digest mismatch for {url}\n  expected {expected_sha256}\n  actual   {actual}\n"
            "Refusing to use unverified third-party data."
        )
    dest.write_bytes(data)
    return dest


def fetch_injecagent(*, dest_dir: Path | None = None) -> dict[str, Path]:
    """Download + verify all pinned InjecAgent data files. Returns name -> path."""
    dest_dir = dest_dir or (_CACHE_ROOT / "injecagent")
    out: dict[str, Path] = {}
    for name, sha in INJECAGENT_FILES.items():
        out[name] = _fetch_one(_INJECAGENT_BASE + name, dest_dir / name, sha)
    return out


def injecagent_cache_dir() -> Path:
    return _CACHE_ROOT / "injecagent"


# --- AgentDojo (ETH SPY Lab, MIT) — Layer 2 via released runs ----------------
# We score Mylonite's judge against AgentDojo's RECORDED runs (no model run): the
# released trajectories include real positives (security=False) from weaker models.
# Pinned commit fixes the content; a bounded subset of one vulnerable model + suite
# is enough for a confusion matrix with positives. See verification/SOURCE.md.
AGENTDOJO_COMMIT = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
_AGENTDOJO_RAW = f"https://raw.githubusercontent.com/ethz-spylab/agentdojo/{AGENTDOJO_COMMIT}/runs"
# gpt-3.5-turbo (a known-vulnerable model) on the banking suite, important_instructions
# attack — user_task 0..2 x injection_task 0..8 (a mix of security True/False).
_AGENTDOJO_MODEL = "gpt-3.5-turbo-0125"
_AGENTDOJO_SUITE = "banking"
_AGENTDOJO_USER_TASKS = range(3)
_AGENTDOJO_INJECTION_TASKS = range(9)


def agentdojo_cache_dir() -> Path:
    return _CACHE_ROOT / "agentdojo"


def fetch_agentdojo_runs(*, dest_dir: Path | None = None) -> list[Path]:
    """Download a pinned subset of AgentDojo's recorded runs. Returns the file paths.

    Commit-pinned (the raw URL carries the SHA) — the provenance guard. A missing
    run (404) is skipped, not fatal (the run grid is sparse).
    """
    dest_dir = dest_dir or agentdojo_cache_dir()
    _enable_truststore()
    out: list[Path] = []
    for u in _AGENTDOJO_USER_TASKS:
        for i in _AGENTDOJO_INJECTION_TASKS:
            rel = (
                f"{_AGENTDOJO_MODEL}/{_AGENTDOJO_SUITE}/user_task_{u}/"
                f"important_instructions/injection_task_{i}.json"
            )
            dest = dest_dir / rel
            if dest.exists():
                out.append(dest)
                continue
            url = f"{_AGENTDOJO_RAW}/{rel}"
            try:
                with urllib.request.urlopen(url) as resp:
                    data = resp.read()
            except Exception as exc:
                # DCR-0002: a missing combo (404) is expected — the run grid is
                # sparse — so this stays non-fatal, but the exception is still
                # captured at DEBUG so a persistent proxy/TLS error is
                # distinguishable from ordinary sparse-grid misses instead of
                # silently discarded (both used to look identical: 0 runs
                # fetched, no clue why).
                logger.debug("fetch_agentdojo_runs: skipping %s (%r)", url, exc)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            out.append(dest)
    return out


# --- DVMCP (Damn Vulnerable MCP Server) — Layer 1 ---------------------------
# README claims MIT but the repo ships NO LICENSE file (verified). We therefore
# clone at a pinned commit at runtime and never vendor it; running it locally for
# testing is not redistribution. Gated behind ``include_unlicensed`` so a user
# must opt in to the license ambiguity. See verification/SOURCE.md.
DVMCP_COMMIT = "79734c19f5104cd11486c90926d245560f53befa"
_DVMCP_SLUG = "harishsg993010/damn-vulnerable-MCP-server"
_DVMCP_URL = f"https://github.com/{_DVMCP_SLUG}.git"


def _clone_dvmcp(dest: Path) -> None:
    """``git clone`` DVMCP. On Windows, use the native ``schannel`` SSL backend so
    the OS cert store (incl. corporate-proxy certs the bundled OpenSSL CA bundle may
    miss) is trusted — the git analogue of ``truststore`` for Python."""
    cmd = ["git"]
    if sys.platform.startswith("win"):
        cmd += ["-c", "http.sslBackend=schannel"]
    cmd += ["clone", _DVMCP_URL, str(dest)]
    subprocess.run(cmd, check=True)


def dvmcp_cache_dir() -> Path:
    return _CACHE_ROOT / "dvmcp"


def fetch_dvmcp(*, include_unlicensed: bool = False) -> Path:
    """Clone DVMCP at the pinned commit into the gitignored cache. Returns the dir.

    Raises unless ``include_unlicensed=True`` — DVMCP has no LICENSE file, so the
    caller must explicitly accept that before we fetch deliberately-vulnerable,
    unlicensed code.
    """
    if not include_unlicensed:
        raise RuntimeError(
            "DVMCP has no LICENSE file (its README claims MIT). Pass include_unlicensed=True "
            "to fetch it at runtime anyway (it is cloned, never vendored, and run locally)."
        )
    dest = dvmcp_cache_dir()
    if (dest / ".git").exists():
        # Already cloned — ensure it's at the pinned commit.
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if head == DVMCP_COMMIT:
            return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").exists():
        _clone_dvmcp(dest)
    # Checkout the pinned commit. This is a LOCAL git op (no network/SSL) since a
    # full clone already contains it.
    subprocess.run(["git", "-C", str(dest), "checkout", DVMCP_COMMIT], check=True)
    return dest
