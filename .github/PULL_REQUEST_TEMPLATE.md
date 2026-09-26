<!--
Title: Conventional Commits, under 72 characters, e.g.
  fix(scan): report attempts that never launched as launch_failure
Writing guide: docs/contributing/writing-style.md
The "Summary" and "How this was tested" sections are required; CI checks them.
-->

## Summary

<!-- What changes for users, and why, in two or three sentences. Lead with the
outcome; a reviewer should understand the change before opening the diff. -->

## Changes

<!-- The notable changes, one line each. -->

-

## How this was tested

<!-- The commands you ran and what they showed, e.g.
`pytest tests/scan -q` (412 passed) or a scan against the reference agent. -->

## Docs and changelog

<!-- The docs you updated, and confirm CHANGELOG.md has an entry under
## [Unreleased]. If nothing user-facing changed, replace this comment with:
Docs-Impact: none - <why no docs are needed> -->

## Security and dual-use impact

<!-- Does this change target authorization, the loopback default for the
vulnerable reference targets, secret redaction in logs, or what the registry
accepts? If not, write "None". -->

## Checklist

- [ ] Commits are signed off (`git commit -s`, DCO)
- [ ] Tests added or updated
- [ ] Docs and `CHANGELOG.md` updated, or a `Docs-Impact` line added above
- [ ] If this touches `src/mylonite/contracts/`: a `contract-change` issue has
      been open for at least a week (see `GOVERNANCE.md`)
- [ ] If this touches `SECURITY.md` rules or vulnerable-target defaults: a
      maintainer is reviewing in person, not auto-merging

## Linked issues

<!-- e.g. Closes #123 -->
