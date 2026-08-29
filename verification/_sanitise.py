"""Make it structurally impossible for local-machine detail to reach committed results.

Why this exists
---------------
``verification/results/<version>/`` is committed evidence: it is the only way a
reader can see whether Mylonite's numbers moved between releases. But the runs
that produce it happen on the maintainer's own computer, against servers on
localhost ports, over paths under a home directory. An earlier leak of exactly
this class (session narration and local paths in committed files) had to be
removed with a force-push, so the constraint here is absolute: **nothing
machine-readable containing local-PC information is committed.**

Two complementary controls live in this module, because either one alone fails
in a predictable way:

* :func:`scrub` / :func:`scrub_tree` clean the FREE-TEXT fields. All three layers
  build their reports from explicit dict literals (``verification/report.py``,
  ``layer1_runnable/run.py``, ``layer3_production/run.py``), so the *shape* is an
  allowlist already -- but three of those fields carry text copied out of a live
  run and are therefore the actual leak vectors:

  - ``layer3.target`` falls back to the scan report's ``target_id``, and a custom
    target's ``scope`` may be a filesystem path;
  - ``layer3.false_positive_detail[].reason`` is 200 characters of a verdict
    reason, which quotes scan content;
  - ``layer1.per_challenge[].detail`` and ``layer2.disagreements[].detail`` are
    built from case detail strings, and the DVMCP challenge servers those Layer 1
    scans talk to run on localhost ports.

* :func:`validate_fields` enforces the allowlist as a CONTRACT rather than a
  coincidence. Scrubbing is a denylist at heart -- it only removes shapes it was
  taught -- so the day someone adds a field to one of those dict literals (or
  passes one through ``build_report``'s open-ended ``extra``), scrubbing would
  quietly ship whatever the new field holds. The allowlist stops that at test
  time and demands a human decision instead.

Determinism
-----------
Every replacement is a fixed placeholder, never a hash or a counter, so the same
input always yields the same output and two committed result files diff cleanly
across runs. Scrubbing is idempotent: placeholders match none of the patterns.

What is deliberately NOT scrubbed
---------------------------------
Impersonal absolute paths (``/tmp/...``, ``/usr/...``), repo-relative paths
(``verification/results/0.9.0/meta.json``) and public hostnames. They carry no
information about the machine or the person, and over-scrubbing would strip the
evidence the results exist to provide.
"""

from __future__ import annotations

import re
from typing import Any, Final

__all__ = [
    "HOST_PLACEHOLDER",
    "LAYER1_FIELDS",
    "LAYER1_PER_CHALLENGE_FIELDS",
    "LAYER2_DISAGREEMENT_FIELDS",
    "LAYER2_FIELDS",
    "LAYER2_JUDGE_AGREEMENT_FIELDS",
    "LAYER3_FALSE_POSITIVE_FIELDS",
    "LAYER3_FIELDS",
    "META_FIELDS",
    "PATH_PLACEHOLDER",
    "PORT_PLACEHOLDER",
    "FieldNotAllowed",
    "scrub",
    "scrub_tree",
    "validate_fields",
]

#: A local filesystem path, collapsed whole. The path SHAPE is the leak (it names
#: a user and a directory layout), so no part of it is preserved.
PATH_PLACEHOLDER: Final = "<path>"

#: A loopback / private-network address. Kept distinct from the port so a reader
#: can still tell "this talked to a local server on some port" -- which is the
#: only part of the fact that is about the test, not about the machine.
HOST_PLACEHOLDER: Final = "<host>"
PORT_PLACEHOLDER: Final = "<port>"

# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

# Path separators are matched as one OR two characters because these strings are
# also scanned after JSON encoding, where a Windows path is escaped and arrives
# as ``C:\\Users\\...``.
_SEP = r"[\\/]{1,2}"

# Characters that end a path: whitespace and the quote/bracket characters that
# delimit it in JSON, YAML or prose. Everything else is treated as part of it.
_PATH_BODY = r"[^\s\"'<>|,;]*"

#: ``C:\Users\<name>\...`` (and its forward-slash and drive-less variants). Listed
#: first because it is the most specific and the most common form on this
#: platform; the generic drive rule below would also catch it.
_WINDOWS_USER_PATH: Final = re.compile(
    rf"(?<![\w-])(?:[A-Za-z]:)?{_SEP}Users{_SEP}{_PATH_BODY}",
    re.IGNORECASE,
)

#: Any Windows absolute path. A drive-letter path is local-machine information by
#: definition -- there is no such thing as a portable ``D:\...``. The lookbehind
#: keeps it from firing on a URL scheme (the ``p://`` inside ``http://host``).
_WINDOWS_DRIVE_PATH: Final = re.compile(rf"(?<![\w-])[A-Za-z]:{_SEP}{_PATH_BODY}")

#: POSIX home directories. Scoped to home roots on purpose: ``/tmp`` and ``/usr``
#: are impersonal, and collapsing every absolute path would destroy legitimate
#: content such as an MCP endpoint path or a tool argument.
_POSIX_HOME_PATH: Final = re.compile(rf"(?<![\w-])/(?:home|Users)/{_PATH_BODY}")

#: Loopback, unspecified, and RFC1918 private addresses, with an optional port.
#: A public host is left alone: it is a fact about the target, not the machine.
_LOCAL_HOST = (
    r"localhost"
    r"|127(?:\.\d{1,3}){3}"
    r"|0\.0\.0\.0"
    r"|10(?:\.\d{1,3}){3}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r"|\[::1\]"
    r"|::1"
)
_HOST_PORT: Final = re.compile(
    rf"(?<![\w.:-])(?:{_LOCAL_HOST})(?::(?P<port>\d{{1,5}}))?(?!\.\d)(?![\w-])",
    re.IGNORECASE,
)

#: Characters a path pattern may greedily swallow from the surrounding prose.
#: They are re-emitted after the placeholder so a scrubbed sentence still reads
#: as a sentence (and so the result stays stable under re-scrubbing).
_TRAILING_PUNCTUATION: Final = ".:)]}"


def _collapse_path(match: re.Match[str]) -> str:
    """Replace a matched path with the placeholder, keeping trailing punctuation."""
    text = match.group(0)
    kept = ""
    while text and text[-1] in _TRAILING_PUNCTUATION:
        kept = text[-1] + kept
        text = text[:-1]
    return f"{PATH_PLACEHOLDER}{kept}"


def _collapse_host(match: re.Match[str]) -> str:
    """Replace a matched local address, preserving whether a port was present."""
    if match.group("port") is None:
        return HOST_PLACEHOLDER
    return f"{HOST_PLACEHOLDER}:{PORT_PLACEHOLDER}"


def scrub(text: str) -> str:
    """Return ``text`` with local paths and local addresses replaced by placeholders.

    Deterministic and idempotent: placeholders contain none of the shapes the
    patterns look for, so ``scrub(scrub(x)) == scrub(x)``. That matters because
    committed results are diffed release over release -- a nondeterministic
    scrubber would show phantom changes in every campaign.

    Non-``str`` input is returned unchanged, so callers can pipe values through
    without type-testing first (mirrors ``mylonite._redaction.redact``).
    """
    if not isinstance(text, str):
        return text
    scrubbed = text
    for pattern in (_WINDOWS_USER_PATH, _WINDOWS_DRIVE_PATH, _POSIX_HOME_PATH):
        scrubbed = pattern.sub(_collapse_path, scrubbed)
    return _HOST_PORT.sub(_collapse_host, scrubbed)


def scrub_tree(obj: Any) -> Any:
    """Recursively :func:`scrub` every string in a nested dict/list structure.

    Shape and non-string leaves (numbers, booleans, ``None``) are preserved
    exactly, so a scrubbed report still validates against the same field
    allowlist and still carries the same measurements.

    Dictionary KEYS are deliberately left alone. In every structure this is
    applied to, keys come from the dict literals in the three layer builders --
    they are schema field names, not run data. Rewriting one would silently
    break :func:`validate_fields` (the allowlist would stop matching) and could
    collide two keys into one, losing a value without saying so.
    """
    if isinstance(obj, str):
        return scrub(obj)
    if isinstance(obj, dict):
        return {key: scrub_tree(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [scrub_tree(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(scrub_tree(item) for item in obj)
    return obj


class FieldNotAllowed(ValueError):
    """A committed results payload carries a field nobody has reviewed.

    Raised rather than silently dropping the field: dropping would make the
    committed evidence quietly incomplete, and reviewing a new field for
    local-machine content is a human decision, not a default.
    """


def validate_fields(payload: dict[str, Any], *, allowed: frozenset[str], where: str) -> None:
    """Raise :class:`FieldNotAllowed` if ``payload`` has keys outside ``allowed``.

    ``where`` names the payload for the error message (e.g. ``"layer3-precision"``).

    Missing keys are NOT an error. This guard exists to catch *additions* -- a
    field that appeared without anyone asking what it contains. A field that is
    absent (an optional block, a layer that did not run) leaks nothing.
    """
    extra = sorted(set(payload) - allowed)
    if not extra:
        return
    names = ", ".join(repr(k) for k in extra)
    raise FieldNotAllowed(
        f"{where}: field(s) not on the committed-results allowlist: {names}. "
        "Committed verification results must contain nothing that describes the "
        "machine that produced them. Review the new field for local-machine "
        "content (filesystem paths, usernames, hostnames, ports, environment "
        "detail), scrub it if needed, and then add its name to the allowlist in "
        "verification/_sanitise.py deliberately. Do not widen the allowlist to "
        "make a test pass."
    )


# --------------------------------------------------------------------------- #
# Field allowlists
#
# Each set is transcribed from the dict literal that builds that report. They are
# duplicated here on purpose: a copy that a test compares against is what turns
# "the builders happen to name every field" into "the builders MUST name every
# field", and the duplication is what makes an unreviewed addition fail loudly.
# --------------------------------------------------------------------------- #

#: ``verification/layer1_runnable/run.py`` -> ``build_recall_report``.
LAYER1_FIELDS: Final = frozenset(
    {
        "schema_version",
        "layer",
        "target",
        "in_scope_challenges",
        "recall",
        "found",
        "missed",
        "per_challenge",
        "note",
    }
)

#: ``build_recall_report``'s ``per_challenge`` rows. ``detail`` is free text.
LAYER1_PER_CHALLENGE_FIELDS: Final = frozenset({"challenge", "weakness", "found", "detail"})

#: ``verification/report.py`` -> ``build_report``. Note that ``build_report``
#: ends with ``**(extra or {})``, an open-ended injection point: whatever a
#: future caller passes there lands in the committed file. That is precisely why
#: the allowlist is validated rather than trusted.
LAYER2_FIELDS: Final = frozenset(
    {
        "schema_version",
        "layer",
        "dataset",
        "model",
        "judge_mode",
        "synthetic",
        "cases",
        "benchmark_asr",
        "benchmark_metric",
        "positive_cases",
        "negative_cases",
        "judge_agreement_exercised",
        "fpr_informative",
        "judge_agreement",
        "disagreements",
        "note",
    }
)

#: ``build_report``'s ``judge_agreement`` block (pure numbers).
LAYER2_JUDGE_AGREEMENT_FIELDS: Final = frozenset(
    {"precision", "recall", "f1", "false_positive_rate", "tp", "fp", "fn", "tn"}
)

#: ``build_report``'s ``disagreements`` rows. ``detail`` is free text copied from
#: the scored case, so it goes through :func:`scrub` like the Layer 1 twin.
LAYER2_DISAGREEMENT_FIELDS: Final = frozenset(
    {
        "case",
        "weakness",
        "benchmark_says_exploited",
        "mylonite_says_exploited",
        "detail",
    }
)

#: ``verification/layer3_production/run.py`` -> ``precision_report``.
LAYER3_FIELDS: Final = frozenset(
    {
        "schema_version",
        "layer",
        "target",
        "completed_probes",
        "false_positives",
        "true_negatives",
        "false_positive_rate",
        "false_positive_detail",
        "note",
    }
)

#: ``precision_report``'s ``false_positive_detail`` rows. ``reason`` is 200
#: characters of a verdict reason -- scan content, quoted verbatim.
LAYER3_FALSE_POSITIVE_FIELDS: Final = frozenset({"pattern_id", "reason"})

#: The per-campaign ``meta.json`` envelope. Unlike the three sets above there is
#: no dict literal to transcribe yet, so this is the DECLARED contract: the
#: campaign writer must match it, not the other way round. ``mylonite_origin``
#: records that the measured package came from PyPI rather than the working
#: tree, reduced to ``<site-packages>`` -- never an absolute install path.
#: ``layers`` records which layers ran, because a layer that did not run must
#: read as "not run" and never as a zero.
META_FIELDS: Final = frozenset(
    {
        "schema_version",
        "mylonite_version",
        "mylonite_origin",
        "git_sha",
        "harness_sha",
        "model",
        # `recorded_at`, not `generated_at`: the demo fixtures' own sidecars
        # already use `recorded_at` for "when the live calls were made", and one
        # name for one concept beats two names that drift.
        "recorded_at",
        "layers",
    }
)
