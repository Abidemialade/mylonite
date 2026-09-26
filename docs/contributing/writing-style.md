# Writing style

This is how Mylonite writes: the README, the docs site, the changelog, pull
requests, commit messages, release notes and replies on issues. It applies to
maintainers, contributors and AI assistants alike, and two checks enforce the
mechanical parts (see [Enforcement](#enforcement)).

The goal is writing that a busy engineer trusts on first read. Say what the
thing does, show the proof, state the limits once, and stop.

## The voice

**Plain.** Write the way a senior engineer explains something to a colleague.
Short sentences, common words, active voice. If a sentence needs a second read,
split it.

**Specific.** Name the command, the flag, the file, the number. "Faster" means
nothing; "the per-PR check runs in 40 seconds with no API key" means something.

**Confident.** Mylonite proves things. Say so. A finding that fired 5 out of 5
times without the safeguard and 0 out of 5 with it is not "potentially
interesting", it is a proven weakness, and the writing should read that way.

**Honest.** Confidence is not overclaiming. Every claim is one you could back
with a command, a test or a published result. When a result comes from the
differential, name the safeguard it used: Mylonite's stand-in guard proves the
attack is real and that this kind of guard closes it; only a run with your own
guard switched off and on proves your code does the work. When something has a limit, say
so plainly, once, where the reader needs it.

## Lead with what it does, then prove it

The most common failure is burying the value under caveats. Readers decide in
the first two sentences whether to keep going.

- Open with the outcome for the reader: what they can now do, see or stop
  worrying about.
- Follow with the proof: a number, a command, a result.
- Put limits after the value, framed as scope rather than apology.

| Undersells it | Says it properly |
| --- | --- |
| "This is an experimental feature that may help in some cases to detect certain issues." | "`mylonite gate` turns a confirmed exploit into a pytest test that fails your CI until the fix lands." |
| "Unfortunately, the tool can only test MCP servers for now." | "Mylonite tests MCP servers over stdio and remote transports. Plain HTTP agents are supported for injection testing; other adapters are on the roadmap." |
| "We tried to make the results a bit more reliable." | "This finding fired in 5 of 5 runs without the safeguard and 0 of 5 with it." |

A limitation stated once, in the right place, builds trust. The same limitation
repeated in every paragraph reads as a lack of conviction.

## Say it like a person, not a bot

Some words and phrases mark text as machine-written or as marketing copy.
Readers tune out when they see them. The prose check flags these; use the
plain version instead.

| Avoid | Use instead |
| --- | --- |
| delve, dive into | look at, cover, explain |
| leverage, utilize | use |
| seamless, seamlessly | say what actually happens ("no config needed") |
| robust, powerful, cutting-edge, state-of-the-art | the evidence ("survives 7 rephrasings of the attack") |
| comprehensive | what it covers ("all four weakness classes") |
| unlock, empower, elevate, supercharge | what the reader can now do |
| game-changing, revolutionary, best-in-class | nothing; show the result |
| "it's worth noting", "it is important to note" | just state it |
| furthermore, moreover, additionally | a new sentence, or "also" |
| "in today's fast-paced world", "ever-evolving" | cut it |
| "may potentially", "could possibly" | pick one: "may" or "can" |

Also avoid:

- Openers that restate the request ("This PR aims to…", "In this document we
  will…"). Start with the point.
- Closers that summarise what was just said, or offer help ("I hope this
  helps", "Feel free to…").
- Emoji in docs, changelog entries and commit messages.
- Words that shrink the work: "just a", "merely", "simply", "a small attempt".
  If the change is small, the diff shows it.

## Comparisons

Compare on capabilities, not names. Describe what Mylonite does differently
("each finding is re-run with the safeguard switched on and kept only if the
safeguard stops it") rather than naming another project to criticise it.

## Formats

### README and docs pages

- Each page answers one question. The first sentence answers it.
- Put a runnable example in the first screen of every how-to.
- Match the page type: a tutorial teaches by doing, a how-to solves one task,
  a reference lists facts, an explanation gives the why. Don't mix them.
- Use tables for comparisons, numbered lists for steps, code blocks for
  anything the reader types.

### Changelog entries

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Write for the user who is deciding whether to upgrade.

- Lead with a bold one-line outcome, then say what changed and how to use it.
- Name the command, flag or field. Note anything that breaks, and how to
  migrate.
- Internal refactors that change nothing for users don't need an entry; say
  so in the pull request with a `Docs-Impact` line (below).

```markdown
- **Every live command reports what it spent.** `scan` prints an `llm:` line
  with calls by role, the `--max-llm-calls` budget and the tokens the provider
  reported. `validate` and `gate` print the same line for the whole command.
```

### Pull requests

Titles follow [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): summary`, lower case, no trailing full stop, under 72
characters. For example: `fix(scan): report attempts that never launched as launch_failure`.

The description follows the template in `.github/PULL_REQUEST_TEMPLATE.md`:

- **Summary:** what changes for users and why, in two or three sentences.
- **Changes:** the notable changes, one line each.
- **How this was tested:** the commands you ran and what they showed.
- **Docs and changelog:** the files you updated, or a `Docs-Impact` line.
- **Security and dual-use impact:** say "none" explicitly if there is none.

Write the summary so a reviewer understands the change before opening the diff.
Don't narrate how you got there.

### Commit messages

Conventional Commits, signed off (`git commit -s`). The subject says what
changed; the body, when needed, says why and what the reader should know.

```text
fix(scan): report attempts that never launched as launch_failure

A target that failed to start was reported as a planner failure, which read as
"the attack ran and found nothing". It now reports launch_failure, so a broken
launch can never be mistaken for a clean result.
```

## Enforcement

Two scripts check the mechanical parts. Both run in CI on every pull request,
and you can run them locally before you push.

- `scripts/check_prose.py` flags the phrases above in changed Markdown lines,
  the pull-request title (Conventional Commits) and the pull-request
  description (required sections). To keep a flagged phrase on purpose, for
  example when quoting someone, add `<!-- prose-lint: allow -->` on that line.
- `scripts/check_docs_sync.py` fails when source code changes without a
  `CHANGELOG.md` entry, or when a user-facing module changes without its doc
  page (for example `cli.py` without `docs/cli-reference.md`).

When a change genuinely needs no docs, such as an internal refactor or a test
fix, say so in the pull-request description or a commit message:

```text
Docs-Impact: none - internal refactor of the scan loop, no behaviour change
```

The reason is required. A reviewer should be able to agree with it at a glance.
