"""The dev/test split, clustered by seed and by scan, and its frozen manifest.

Cases are grouped with union-find over ``seed_id`` and ``scan_id``: two cases
sharing either key land in the same cluster, so no seed and no scan ever
appears on both sides. Whole clusters go to dev, in a fixed-seed shuffled
order, until dev holds at least ``dev_fraction`` of the cases; the rest is the
held-out test set.

The manifest records the held-out IDs and a SHA-256 over them and their
canonical JSON. :func:`verify_manifest` refuses to score if any held-out case
was added, removed or changed after the manifest was frozen.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict

from verification.judge_bench.cases import BenchCase

#: The preregistered split seed (the date the design was frozen).
DEFAULT_RNG_SEED = 20261013
DEFAULT_DEV_FRACTION = 0.25


class ManifestMismatch(Exception):
    """The cases no longer match the frozen manifest."""


class Manifest(BaseModel):
    """The frozen dev/test split."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dev_ids: list[str]
    test_ids: list[str]
    test_sha256: str
    rng_seed: int
    created: str


class _UnionFind:
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self._parent.setdefault(x, x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:  # path compression
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Deterministic root choice, so cluster identity never depends on order.
            lo, hi = sorted((ra, rb))
            self._parent[hi] = lo


def clusters(cases: Iterable[BenchCase]) -> list[list[BenchCase]]:
    """Group cases that share a seed or a scan; deterministic order (by min case_id)."""
    items = list(cases)
    uf = _UnionFind()
    for case in items:
        uf.union(f"seed:{case.seed_id}", f"scan:{case.scan_id}")
    groups: dict[str, list[BenchCase]] = {}
    for case in items:
        groups.setdefault(uf.find(f"seed:{case.seed_id}"), []).append(case)
    out = [sorted(g, key=lambda c: c.case_id) for g in groups.values()]
    out.sort(key=lambda g: g[0].case_id)
    return out


def held_out_hash(test_cases: Sequence[BenchCase]) -> str:
    """SHA-256 of the sorted held-out IDs plus each case's canonical JSON.

    The material is ``"\\n".join(sorted(ids))``, a newline, then the canonical
    JSON of every held-out case in ``case_id`` order, newline-joined.
    """
    ordered = sorted(test_cases, key=lambda c: c.case_id)
    ids = "\n".join(c.case_id for c in ordered)
    body = "\n".join(c.canonical_json() for c in ordered)
    return hashlib.sha256(f"{ids}\n{body}".encode()).hexdigest()


def _check_unique(cases: Sequence[BenchCase]) -> None:
    seen: set[str] = set()
    for c in cases:
        if c.case_id in seen:
            raise ValueError(f"duplicate case_id {c.case_id!r}")
        seen.add(c.case_id)


def make_split(
    cases: Iterable[BenchCase],
    dev_fraction: float = DEFAULT_DEV_FRACTION,
    rng_seed: int = DEFAULT_RNG_SEED,
    *,
    created: str | None = None,
) -> Manifest:
    """Split ``cases`` into dev and test by whole seed/scan clusters."""
    if not 0.0 <= dev_fraction <= 1.0:
        raise ValueError(f"dev_fraction must be in [0, 1]; got {dev_fraction}")
    items = list(cases)
    _check_unique(items)
    groups = clusters(items)
    random.Random(rng_seed).shuffle(groups)  # noqa: S311 - reproducible split, not crypto
    target = dev_fraction * len(items)
    dev: list[BenchCase] = []
    test: list[BenchCase] = []
    for group in groups:
        (dev if len(dev) < target else test).extend(group)
    return Manifest(
        dev_ids=sorted(c.case_id for c in dev),
        test_ids=sorted(c.case_id for c in test),
        test_sha256=held_out_hash(test),
        rng_seed=rng_seed,
        created=created or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def verify_manifest(cases: Iterable[BenchCase], manifest: Manifest) -> None:
    """Raise :class:`ManifestMismatch` unless the held-out set is unchanged.

    Fails when a held-out case is missing or edited, when a case appears that
    the manifest never assigned (it could be a held-out addition), or when a
    case id is duplicated.
    """
    items = list(cases)
    by_id: dict[str, BenchCase] = {}
    for c in items:
        if c.case_id in by_id:
            raise ManifestMismatch(f"duplicate case_id {c.case_id!r}")
        by_id[c.case_id] = c
    test_ids = set(manifest.test_ids)
    if test_ids & set(manifest.dev_ids):
        raise ManifestMismatch("the manifest lists a case on both sides of the split")
    known = test_ids | set(manifest.dev_ids)
    missing = sorted(test_ids - by_id.keys())
    if missing:
        raise ManifestMismatch(f"{len(missing)} held-out case(s) removed, e.g. {missing[:3]}")
    unknown = sorted(by_id.keys() - known)
    if unknown:
        raise ManifestMismatch(
            f"{len(unknown)} case(s) not in the manifest (added after freezing), e.g. {unknown[:3]}"
        )
    actual = held_out_hash([by_id[i] for i in test_ids])
    if actual != manifest.test_sha256:
        raise ManifestMismatch(
            f"held-out set changed: sha256 {actual} != frozen {manifest.test_sha256}"
        )


def select(cases: Iterable[BenchCase], manifest: Manifest, split: str) -> list[BenchCase]:
    """The cases on one side of the split (``dev``, ``test``) or ``all``."""
    items = list(cases)
    if split == "all":
        return items
    if split == "dev":
        keep = set(manifest.dev_ids)
    elif split == "test":
        keep = set(manifest.test_ids)
    else:
        raise ValueError(f"unknown split {split!r}")
    return [c for c in items if c.case_id in keep]


__all__ = [
    "DEFAULT_DEV_FRACTION",
    "DEFAULT_RNG_SEED",
    "Manifest",
    "ManifestMismatch",
    "clusters",
    "held_out_hash",
    "make_split",
    "select",
    "verify_manifest",
]
