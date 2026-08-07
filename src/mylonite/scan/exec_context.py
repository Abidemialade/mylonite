"""Execution-context metadata carried alongside an exploit via ``Payload.metadata``.

**Root cause this closes (T12).** ``TestGenerator.emit(self, exploit)`` only ever
receives an :class:`~mylonite.contracts._types.ExploitRecord`, which has no
model/provider field -- those live on
:class:`~mylonite.contracts._types.ScanReport`, a SIBLING artefact ``emit``
never reads. Left alone, the emitted test's runtime helpers
(:mod:`mylonite.testkit`) fell back to a hardcoded model/provider default --
meaning a committed regression test could silently gate CI using a DIFFERENT
model than the one that actually found/validated the exploit.

Adding fields to ``ExploitRecord`` (a `contract-change`) and changing
``TestGenerator.emit``'s signature (also a contract) are both out of scope for
this release. Instead, :class:`ExecContext` rides in
``Payload.metadata: dict[str, str]`` -- a field whose JSON schema is already
``{"additionalProperties": {"type": "string"}}``, so this needs no schema
change and no `contract-change` clock. Every key this module writes is
namespaced under :data:`METADATA_PREFIX` (``"mylonite.exec."``) -- a prefix
RESERVED for this purpose via a `contract-change`-tagged GitHub issue, so a
third-party plugin cannot collide with it before a future release promotes
this into a real ``emit(exploit, context=...)`` parameter.

**One writer, one reader, allowlisted.**

* Writer: :meth:`mylonite.scan.engine.ScanEngine._finalize` stamps
  :meth:`ExecContext.to_metadata` onto every finding's payload before
  returning the :class:`~mylonite.scan.engine.ScanResult`.
* Reader: :meth:`mylonite.plugins._reference.reference_pytest_generator.ReferencePytestGenerator.emit`
  reads it back via :meth:`ExecContext.from_metadata` to render explicit
  ``model=``/``provider=`` literals into the generated test source; and
  :mod:`mylonite.testkit`'s ``assert_target_resists``/``assert_control_holds``
  read it as one step of their resolution order (explicit kwarg -> exec
  context -> sibling ``scan_report.json`` back-fill -> loud failure).
* Allowlist: :meth:`to_metadata` emits ONLY the fields declared on this
  dataclass -- model ids and a target-file name, nothing shaped like a
  credential. ``exploit_*.json`` files are committed to git and pushed as gate
  PR artefacts by this project's own workflow, so anything returned here
  becomes public. NEVER add ``api_key_env_var`` values or a credentialed
  ``api_base`` to this dataclass without re-reading this warning.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Reserved key prefix for every ``Payload.metadata`` entry this module writes.
#: Reservation tracked by a `contract-change`-tagged GitHub issue (see T12 in
#: the 0.7.7->0.7.10 remediation plan) -- a plugin author must not stamp keys
#: under this prefix for anything other than :class:`ExecContext`.
METADATA_PREFIX = "mylonite.exec."

_PROVIDER_KEY = f"{METADATA_PREFIX}provider"
_MODEL_KEY = f"{METADATA_PREFIX}model"
_PLANNER_MODEL_KEY = f"{METADATA_PREFIX}planner_model"
_CUSTOMISER_MODEL_KEY = f"{METADATA_PREFIX}customiser_model"
_JUDGE_MODEL_KEY = f"{METADATA_PREFIX}judge_model"
_TARGET_FILE_KEY = f"{METADATA_PREFIX}target_file"
_MYLONITE_VERSION_KEY = f"{METADATA_PREFIX}mylonite_version"

#: The exhaustive set of keys :meth:`ExecContext.to_metadata` can ever emit.
#: Exported so tests (and any future auditor) can assert the allowlist is
#: closed -- nothing outside this set, ever.
ALLOWED_METADATA_KEYS = frozenset(
    {
        _PROVIDER_KEY,
        _MODEL_KEY,
        _PLANNER_MODEL_KEY,
        _CUSTOMISER_MODEL_KEY,
        _JUDGE_MODEL_KEY,
        _TARGET_FILE_KEY,
        _MYLONITE_VERSION_KEY,
    }
)


@dataclass(frozen=True)
class ExecContext:
    """The model/provider(s) that actually produced+validated one scan's findings.

    ``provider``/``model`` are the primary pair (what an emitted test re-drives
    with by default). ``planner_model``/``customiser_model``/``judge_model``
    record the role-separated models :class:`~mylonite.scan.engine.ScanConfig`
    supports (its ``resolved_planner_model`` etc., which fall back to ``model``
    when a role has no override, so the writer always populates all three --
    they are never conditionally omitted for equalling ``model``) --
    informational provenance, not currently read by any resolver.
    """

    provider: str
    model: str
    planner_model: str | None = None
    customiser_model: str | None = None
    judge_model: str | None = None
    target_file: str | None = None
    mylonite_version: str | None = None

    def to_metadata(self) -> dict[str, str]:
        """Render this context as an ALLOWLISTED set of ``Payload.metadata`` entries.

        Only the seven keys in :data:`ALLOWED_METADATA_KEYS` are ever emitted,
        all namespaced under :data:`METADATA_PREFIX` -- never an
        ``api_key_env_var`` value or a credentialed ``api_base``. See the
        module docstring: ``exploit_*.json`` is committed/pushed by this
        project's own CI, so anything returned here becomes public.
        """
        out: dict[str, str] = {
            _PROVIDER_KEY: self.provider,
            _MODEL_KEY: self.model,
        }
        if self.planner_model is not None:
            out[_PLANNER_MODEL_KEY] = self.planner_model
        if self.customiser_model is not None:
            out[_CUSTOMISER_MODEL_KEY] = self.customiser_model
        if self.judge_model is not None:
            out[_JUDGE_MODEL_KEY] = self.judge_model
        if self.target_file is not None:
            out[_TARGET_FILE_KEY] = self.target_file
        if self.mylonite_version is not None:
            out[_MYLONITE_VERSION_KEY] = self.mylonite_version
        return out

    @classmethod
    def from_metadata(cls, metadata: dict[str, str]) -> ExecContext | None:
        """Reconstruct an :class:`ExecContext` from a ``Payload.metadata`` dict.

        Returns ``None`` when the two REQUIRED fields (``provider``/``model``)
        are both absent or empty -- i.e. this exploit predates T12 (or was
        built by a third party) and carries no exec context to read. A caller
        that gets ``None`` back should fall through to its own next resolution
        step (a sibling ``scan_report.json``, an explicit kwarg, or a loud
        failure) rather than treat this as a context with blank strings.
        """
        provider = metadata.get(_PROVIDER_KEY)
        model = metadata.get(_MODEL_KEY)
        if not provider or not model:
            return None
        return cls(
            provider=provider,
            model=model,
            planner_model=metadata.get(_PLANNER_MODEL_KEY) or None,
            customiser_model=metadata.get(_CUSTOMISER_MODEL_KEY) or None,
            judge_model=metadata.get(_JUDGE_MODEL_KEY) or None,
            target_file=metadata.get(_TARGET_FILE_KEY) or None,
            mylonite_version=metadata.get(_MYLONITE_VERSION_KEY) or None,
        )


__all__ = ["ALLOWED_METADATA_KEYS", "METADATA_PREFIX", "ExecContext"]
