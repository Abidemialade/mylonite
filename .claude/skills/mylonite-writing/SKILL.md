---
name: mylonite-writing
description: Mylonite's writing voice and docs-sync workflow. Use this whenever you write or edit anything a person will read in the Mylonite repo — pull-request titles and descriptions, commit messages, CHANGELOG entries, README or docs/ pages, release notes, issue and discussion replies, launch or announcement posts — and whenever you finish a code change, to update the docs that describe it before committing. Use it even for a one-line changelog entry or a quick PR, because those are where the bot-sounding, undersold phrasing creeps in.
---

# Writing for Mylonite

Mylonite's docs and pull requests should read like a well-run open-source
project with a large following: plain, specific, confident, and honest. Two
failure modes keep showing up, and this skill exists to stop both:

1. **Bot voice.** Filler openers, stacked hedges, marketing adjectives and
   phrases like "delve" or "it's worth noting". Readers spot it instantly and
   stop trusting the page.
2. **Underselling.** Mylonite proves things that most tools only claim, yet
   drafts tend to open with caveats, apologise for limits, and bury the proof.
   The project's honesty rules are about not *overclaiming*; they were never
   meant to make every sentence timid.

A third problem is procedural: code changes land without the docs that
describe them. The last section handles that.

## Before writing

Read `docs/contributing/writing-style.md` once per session. It is the source of
truth for voice, the phrase list, and the format of each kind of document. This
skill is the working procedure; the style guide is the rulebook.

Know what Mylonite actually proves, so you can say it with confidence. Check
any number against its source before you cite it (the `verification/` results,
`CHANGELOG.md`, or `docs/verification.md`), and never present a roadmap item as
shipped.

- **The core claim:** a safe model is not the same thing as a safe app.
  Mylonite checks whether your app's own safeguards stop an attack.
- **How it proves it:** where a safeguard can be switched, each attack runs
  with it off and on, repeatedly, and the finding is kept only if it lands
  without the safeguard and is stopped with it. That differential is the thing
  to lead with, so state it precisely:
  - by default the "on" side is Mylonite's stand-in guard at the tool boundary;
    it proves the attack is real and that this kind of guard closes it;
  - with `control_env` (a kill switch for the user's own guard) it proves the
    user's own code does the work, which is the stronger claim;
  - black-box targets (the HTTP `rest` transport, or a custom target with no
    switchable control) get repeat-run, consensus and effect checks instead,
    and the output says no differential ran.
  Never write "your safeguard is what stops it" unless the run used
  `control_env`.
- **What it hands back:** a pytest regression test that gates CI, with
  OWASP LLM, OWASP ASI, MITRE ATLAS and NIST AI RMF tags.
- **Honesty rails:** a check that could not run is never reported as a pass,
  and every output states which level of proof was reached.

## The confidence pass

After drafting, reread with these questions. They fix most drafts.

1. **Does the first sentence say what changes for the reader?** If it opens
   with background, a caveat, or "This PR aims to", rewrite it to lead with the
   outcome.
2. **Is there one piece of proof?** A number, a command, a test result. Swap
   adjectives ("robust", "powerful", "comprehensive") for the evidence.
3. **Is each limit stated once, as scope?** "Mylonite tests MCP servers over
   stdio and remote transports" beats "Unfortunately it can only…". Mention a
   limit where the reader needs it, not in every paragraph.
4. **Are the hedges earned?** "May potentially" becomes "may". If you are sure,
   drop the hedge. If you are not sure, find out or say what is unknown.
5. **Would a senior engineer say it out loud?** Cut filler, cut recaps, cut
   "I hope this helps". Short sentences, active voice, concrete nouns.
6. **Are other projects named?** Compare on capabilities, never by naming and
   criticising another tool.

## Formats

Follow the matching section of the style guide. The short version:

- **PR title:** Conventional Commits, `type(scope): summary`, lower case, no
  full stop, under 72 characters.
- **PR description:** use `.github/PULL_REQUEST_TEMPLATE.md` and fill every
  section. *Summary* (outcome and why, two or three sentences), *Changes* (one
  line each), *How this was tested* (real commands and results), *Docs and
  changelog* (files updated, or a `Docs-Impact` line), *Security and dual-use
  impact* ("None" if none). Delete the HTML guidance comments once filled in.
- **Commit message:** Conventional Commits subject; a body that says why and
  what a reader should know; signed off with `git commit -s`.
- **CHANGELOG entry:** under `## [Unreleased]`, a bold one-line outcome, then
  what changed and how to use it, naming the command, flag or field.
- **Docs page:** one question per page, answered in the first sentence, with a
  runnable example on the first screen of any how-to.

### Example: a PR summary (illustrative change)

Undersold and bot-like:

> This PR aims to improve the gate by adding a new mode that may potentially
> help reduce costs. It's worth noting that this is somewhat experimental.

In the Mylonite voice:

> The per-PR gate no longer calls a model. It replays the recorded tool calls
> against the current build, so the check is free, runs in under a minute, and
> fails closed if anything it recorded has changed. Live re-proof moves to the
> nightly job.

## After a code change: keep the docs in sync

Before committing a code change, update the docs that describe it. The
project's hooks and CI block the commit, push or pull request otherwise, so
doing it up front saves a round trip.

1. Run `python scripts/check_docs_sync.py --base origin/main` (or `--staged`
   before a commit). It lists what is missing.
2. Add the `CHANGELOG.md` entry, and update each page it names. For a larger
   change or before a release, run the gstack `/document-release` skill if it
   is available: it cross-references the diff against every doc, including the
   README, CONTRIBUTING and TODOS.
3. If nothing user-facing changed (a refactor, a test fix), add a line to the
   commit message or PR description instead:

   ```text
   Docs-Impact: none - internal refactor of the scan loop, no behaviour change
   ```

   Give a real reason. "none" on a change that alters a flag or an output is a
   docs bug a reviewer will catch.

## Before handing off

Run the prose check on what you wrote and fix every error it reports:

```bash
python scripts/check_prose.py --diff-base origin/main          # changed docs
python scripts/check_prose.py --text-file <message-or-body.md> # a message or PR body
python scripts/check_prose.py --pr-title "fix(scan): ..." --pr-body-file body.md
```

Warnings ("unfortunately", "simply", "robust") are worth a second look but do
not block. If a flagged phrase is a deliberate quotation, add
`<!-- prose-lint: allow -->` to that line rather than rewording the quote.
