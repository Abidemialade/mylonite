# Governance

## Current state

Mylonite is currently a **single-maintainer** open-source project. Decisions
are made by the maintainer with lazy consensus on the issue tracker:
proposals are open for at least 72 hours; if no concerned party objects, the
proposal is considered accepted.

## Path to multi-maintainer

Once the project has three or more regular external contributors, governance
will move to a small maintainers' group. The transition will be proposed on
the issue tracker and announced in the changelog. The intent is to follow a
standard "two +1s, no -1s" merge rule for non-trivial changes once there is
more than one maintainer.

### Required reviews

`main` currently requires **zero** approving reviews. That is not a preference.
Branch protection has `enforce_admins` on and there is one maintainer, who
cannot approve their own pull request — requiring an approval would make the
repository unmergeable by the only person able to merge.

The gap is covered from the other side. The `Sensitive paths` check fails on any
pull request touching the files that control what the project's own checks do
(workflows, `gate-action/`, `.pre-commit-config.yaml`, `pyproject.toml`,
`scripts/check_*.py`, `.secrets.baseline`, `reference_targets/`), and clears only
when a maintainer applies the `reviewed:sensitive-paths` label. Applying a label
requires write access, so the contributor under review cannot self-clear. See
`scripts/check_sensitive_paths.py`.

**Trigger:** the moment a second maintainer is onboarded, set
`required_approving_review_count` to 1 and enable `require_code_owner_reviews`.
The reason for the exception disappears with the second maintainer, and the
tripwire is a weaker control than real review — it proves someone looked, not
that someone else agreed.

## Roles

- **Maintainer.** Has merge rights on `main`, can cut releases, manages
  the project's GitHub organisation. Currently a single person; see
  `.github/CODEOWNERS`.
- **Contributor.** Anyone who has had a pull request merged.
- **Registry contributor** *(planned role — not yet active; the registry
  itself doesn't exist yet, see below).* Once it ships, this will apply to a
  contributor who has had at least one attack pattern accepted into it.

## Decision scope

- **Routine work** (bug fixes, doc updates, adding adapters or attack modules
  behind existing contracts): handled in PRs with normal review.
- **Contract changes** (any change to the five extension-point Protocols or
  their JSON schemas): require an issue tagged `contract-change`, at least
  one week of public comment, and a CHANGELOG entry explaining the migration
  path. Major-version bumps require a deprecation cycle. Note that a contract
  major bump is a *harder* break than a package major bump — the plugin registry
  refuses to load a plugin whose contract major differs, so every third-party
  plugin built against it stops working immediately. What the version numbers
  mean, on both axes, is in
  [docs/contributing/releasing.md](docs/contributing/releasing.md).
- **Security-sensitive changes** (anything touching the responsible-use
  rules in `SECURITY.md`, or the loopback default for vulnerable reference
  targets): require explicit maintainer approval and may not be merged by
  bots or auto-merge tools.

## Community attack-pattern registry — acceptance criteria (planned)

A versioned, CI-validated registry of contributed attack patterns is on the
roadmap but not yet built — there is no registry directory or CI job today.
The `attack_pattern_submission.yml` issue template is open for proposals in
the meantime; the intended acceptance criteria, which will apply once the
registry ships, are:

1. **Mapping completeness.** Each pattern must declare its OWASP LLM Top 10
   ID, its OWASP Agentic Security Initiative (ASI) ID, at least one MITRE
   ATLAS technique, and a NIST AI RMF function/subcategory tag.
2. **Differential-oracle proof.** Each pattern must come with (a) a seed
   vulnerable target it reliably exploits and (b) a guarded variant of that
   target it reliably does not exploit. Proof will be the registry CI
   passing the differential check across five runs, once that CI exists;
   until then, submissions are reviewed with hand-verified evidence instead.
3. **No live targeting.** Patterns must reproduce their behaviour on a
   bundled local target, not on a public third-party service.
4. **Public-domain or Apache-2.0 contribution.** Submissions are accepted
   under the project's license; this is asserted via the DCO sign-off on
   the PR.

## Code of conduct

All participation is governed by [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).

## Updating this document

Substantive changes to governance follow the same "issue + one-week comment"
process as contract changes.
