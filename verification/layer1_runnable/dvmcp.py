"""DVMCP (Damn Vulnerable MCP Server) — Layer 1 catalogue + target builder.

DVMCP (``harishsg993010/damn-vulnerable-MCP-server``) is the genuine runnable
*MCP* target: 10 CTF challenges, each a FastMCP server exposed over SSE on its
own port, with a ``solutions/challengeN_solution.md`` write-up as ground truth.
Mylonite scans it (via the SSE transport) and we score **recall**: did Mylonite
flag the weakness the challenge documents?

This is recall-only by design (a deliberately-vulnerable target has no clean
baseline — precision is a Layer 3 concern), and it covers only the challenges
that fall within Mylonite's AI-layer surface (W1-W4). Challenges that are
traditional code-exec / command-injection (8, 9) are explicitly out of scope and
recorded as such — we do not claim coverage Mylonite's surface doesn't address.

NOTE (license): DVMCP's README states MIT, but the repo ships **no LICENSE
file**. We therefore fetch it at a pinned commit at runtime and never vendor it
(see ``verification/SOURCE.md`` and ``fetch.fetch_dvmcp``).

NOTE (research correction): an earlier research pass named DVAA
(``opena2a-org/damn-vulnerable-ai-agent``) as the Layer 1 target. Verified
against the repo, DVAA is an A2A / AI-infrastructure playground with no MCP
endpoint for Mylonite's adapter to drive (and no license), so it is unusable
here. DVMCP is the correct MCP target.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from mylonite.plugins._mcp.target_file import TargetFile


@dataclass(frozen=True)
class DvmcpChallenge:
    """One DVMCP challenge and its mapping to Mylonite's weakness classes."""

    number: int
    difficulty: str  # "easy" | "medium" | "hard"
    title: str
    weakness_classes: tuple[str, ...]  # Mylonite W-classes (empty => out of scope)
    note: str
    in_scope: bool = True

    @property
    def cid(self) -> str:
        return f"challenge{self.number}"

    @property
    def family(self) -> str:
        return f"dvmcp-c{self.number}"

    def server_relpath(self) -> str:
        return f"challenges/{self.difficulty}/{self.cid}/server.py"

    def sse_server_relpath(self) -> str:
        """The SSE entrypoint we actually launch (runs on port 9000+N, distinct
        from server.py's port)."""
        return f"challenges/{self.difficulty}/{self.cid}/server_sse.py"

    def solution_relpath(self) -> str:
        return f"solutions/{self.cid}_solution.md"


# Catalogue hand-built from the DVMCP README + solutions/ (cited per row). The
# W-class mapping is the Mylonite-authored judgement; the titles/difficulty are
# the benchmark's own.
CATALOGUE: tuple[DvmcpChallenge, ...] = (
    DvmcpChallenge(
        1,
        "easy",
        "Basic Prompt Injection",
        ("W2",),
        "unsanitised input manipulates the LLM (direct prompt injection)",
    ),
    DvmcpChallenge(
        2,
        "easy",
        "Tool Poisoning",
        ("W1",),
        "hidden instructions in tool descriptions (tool-description smuggling)",
    ),
    DvmcpChallenge(
        3,
        "easy",
        "Excessive Permission Scope",
        ("W3",),
        "overly permissive tools reach unauthorised resources (egress/over-reach)",
    ),
    DvmcpChallenge(
        4,
        "medium",
        "Rug Pull Attack",
        ("W1",),
        "tool description mutates after approval (tool-description trust abuse)",
    ),
    DvmcpChallenge(
        5,
        "medium",
        "Tool Shadowing",
        ("W1",),
        "a malicious tool shadows/overrides a trusted one via its description",
    ),
    DvmcpChallenge(
        6,
        "medium",
        "Indirect Prompt Injection",
        ("W2",),
        "instructions injected through a data source the agent reads",
    ),
    DvmcpChallenge(
        7, "medium", "Token Theft", ("W3",), "credential/token exfiltration to an attacker sink"
    ),
    DvmcpChallenge(
        8,
        "hard",
        "Malicious Code Execution",
        (),
        "arbitrary code execution — traditional RCE, outside Mylonite's AI-layer surface",
        in_scope=False,
    ),
    DvmcpChallenge(
        9,
        "hard",
        "Remote Access Control",
        (),
        "OS command injection — outside Mylonite's AI-layer surface",
        in_scope=False,
    ),
    DvmcpChallenge(
        10,
        "hard",
        "Multi-Vector Attack",
        ("W1", "W2"),
        "chains tool poisoning + indirect injection (partial AI-layer coverage)",
    ),
)

CATALOGUE_BY_NUMBER: dict[int, DvmcpChallenge] = {c.number: c for c in CATALOGUE}


def in_scope_challenges() -> list[DvmcpChallenge]:
    """Challenges that fall within Mylonite's W1-W4 surface."""
    return [c for c in CATALOGUE if c.in_scope]


_PORT_RE = re.compile(r"port\s*=\s*(\d+)")


def extract_port(server_py: Path, *, default: int | None = None) -> int:
    """Read the uvicorn port from a challenge's ``server.py`` (e.g. ``port=8002``).

    DVMCP servers run ``uvicorn.run(..., port=800N)``; reading it from the clone
    keeps us accurate without hardcoding (the README's port numbers drift).
    """
    text = server_py.read_text(encoding="utf-8")
    m = _PORT_RE.search(text)
    if m:
        return int(m.group(1))
    if default is not None:
        return default
    raise ValueError(f"no uvicorn port found in {server_py}")


def build_target_file(
    challenge: DvmcpChallenge,
    *,
    port: int,
    host: str = "localhost",
    sse_path: str = "/sse",
) -> TargetFile:
    """Build a remote (SSE) ``TargetFile`` pointing Mylonite at a running challenge.

    The challenge server must already be running (the user starts DVMCP, e.g. via
    its Dockerfile or ``python server.py``). ``seed_arm`` is intentionally left
    unset: Mylonite auto-wires it from the introspected tool surface for the W2
    challenges (pass ``--allow-no-seed-arm`` if auto-wire can't find a plant
    path). FastMCP's SSE endpoint defaults to ``/sse``; override if your build
    differs.
    """
    if not challenge.in_scope:
        raise ValueError(f"{challenge.cid} is out of Mylonite's scope; no target file")
    return TargetFile(
        family=challenge.family,
        transport="sse",
        url=f"http://{host}:{port}{sse_path}",
        weakness_classes=list(challenge.weakness_classes),
    )
