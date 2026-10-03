# The testkit API

`mylonite.testkit` is what an emitted regression test imports. `mylonite
generate` writes the calls for you, but the module is also a stability-promised
public surface you can call directly — in a hand-written test, or to understand
exactly what a committed gate is checking.

```python
from mylonite import testkit
```

Its stability promise is the same one `mylonite.contracts` carries: a consumer
repository imports these names and calls them positionally or by keyword, so a
silent signature change would break every downstream regression gate. Any
change to this module's public surface is a `CHANGELOG.md`-gated API change,
major-versioned if it breaks a caller.

## The three assertions

Each re-drives a target and raises on a regression; none of them silently
passes when the evidence is missing (R4 — see
[the validation engine](validation.md#isnt-this-a-tautology)).

### `assert_guard_holds` — offline, the bundled reference app only

```python
testkit.assert_guard_holds(
    exploit,
    *,
    fixtures_dir=None,
    _completion_fn=None,
) -> None
```

Replays a **recorded** reproduction of the attack against the in-process
GUARDED reference twin and asserts the exploit's predicate did not fire. No
network, no API key, no LLM call — the recorded `(model, messages)` → response
pairs in `fixtures_dir` (plus a `_meta.json` sidecar) stand in for the model.
This is what `mylonite generate` emits for `reference:vulnerable` /
`reference:guarded` targets, and it is the only assertion that runs offline.

```python
from pathlib import Path
from mylonite import testkit


def test_guard_holds_tool_description_summary_smuggle():
    exploit = testkit.load_exploit("exploit_tool-description-summary-smuggle.json")
    testkit.assert_guard_holds(
        exploit,
        fixtures_dir=Path(__file__).parent / "fixtures",
    )
```

- `fixtures_dir` — required unless `_completion_fn` is supplied. There is no
  packaged default: the bundled reference fixtures predate the fixture
  format's version sidecar, so a default here would raise on every call.
  `mylonite validate <dir or test file>` records fresh fixtures; `mylonite
  generate` alone only writes the test file and leaves `fixtures/` empty.
- `_completion_fn` — test-only injection seam that drives the scan directly
  and skips fixtures entirely.

Raises `TestkitConfigError` if neither `fixtures_dir` nor `_completion_fn` is
given, and `TestkitFixtureError` if the fixtures are missing, corrupt,
version-mismatched, or the replay never reached a verdict.

### `assert_target_resists` — live, your own target

```python
testkit.assert_target_resists(
    exploit,
    *,
    target_file,
    model=None,
    provider=None,
    attempts=None,
    _completion_fn=None,
) -> None
```

Re-drives the **actual** target declared by `target_file` (a launchable MCP
server, or a `rest` endpoint) and asserts the attack does not take effect this
time. This is a LIVE check — it launches the real target and calls the real
provider — so emitted tests gate it behind `MYLONITE_LIVE_TARGET=1` (see
[below](#environment-variables)). A test named for `mcp:your-app` fails when
*your app* regresses, never when the bundled reference app does.

```python
import os
from pathlib import Path
import pytest
from mylonite import testkit

exploit = testkit.load_exploit(Path(__file__).parent / "exploit_W2.json")


@pytest.mark.skipif(not os.environ.get("MYLONITE_LIVE_TARGET"), reason="live re-drive")
def test_target_resists_W2():
    testkit.assert_target_resists(
        exploit,
        target_file=Path(__file__).parent / "target.yaml",
    )
```

`model`/`provider` default to the exploit's own execution-context metadata (the
model that found it), not a hardcoded default — see
[`TestkitConfigError`](#exceptions) below.

### `assert_control_holds` — live, the control-efficacy gate

```python
testkit.assert_control_holds(
    exploit,
    *,
    target_file,
    control,
    model=None,
    provider=None,
    attempts=None,
    _completion_fn=None,
) -> None
```

The committed control-efficacy test: model held constant, the attack must FIRE
against the raw target and be RESISTED once `control` (e.g. `"W2"`) is applied.
It fails if the control stops carrying the security, **and** if the attack no
longer reproduces on the raw target at all — a control test that can't show the
attack still works would be theater, so it does not pass green either way (see
[`TestkitAttackNotReproduced`](#exceptions)). When the target declares a
server-layer toggle for `control` in its `control_env` (see
[Add a kill switch to your own guard](concepts.md#add-a-kill-switch-to-your-own-guard)),
the raw leg disables your *real* guard instead of relying on Mylonite's
boundary stand-in — this is what earns the stronger claim. `control="input-frame"`
runs the REST input-framing differential instead of a W1–W4 boundary control.

```python
testkit.assert_control_holds(
    exploit,
    target_file=Path(__file__).parent / "target.yaml",
    control="W2",
)
```

Raises `ValueError` up front (before any scan runs) if `control` names a
weakness class with no implemented boundary control, or if no differential can
be built at all for this target+control pair.

## Re-drive attempts and what they cost

Discovery proved a *rate* — an attack that lands 40% of the time still proves
real even though it loses most single re-drives. One clean re-drive in CI would
prove little, so both live assertions re-drive up to several times. They
pass only when no attempt landed and at least one resisted:

| What happens | Result |
|---|---|
| The attack lands on attempt *k* | `AssertionError` at once, naming attempt *k*; no further attempt runs |
| Every attempt resists | Pass |
| Attempt *k* is inconclusive (the agent made no tool calls, no verdict was reached, the seed was skipped) | Not a resist. It uses up attempt *k* and the next attempt runs |
| No attempt lands, at least one resists, the rest are inconclusive | Pass |
| Every attempt is inconclusive | The last attempt's `TestkitFixtureError`, saying no attempt confirmed resistance; never a pass |
| Attempt *k* is cut short by its call budget, time limit or the session's request ceiling | `TestkitRedriveAborted` at once, with the tally so far; no further attempt runs, since a hung target or a spent ceiling would only stop again |

Inconclusive attempts count toward the number of attempts, so a test never
re-drives more than that number of times per leg. A pass where some attempts
were inconclusive emits `testkit.RedriveInconclusiveWarning` (a `UserWarning`)
in the pytest warnings summary, for example *resistance confirmed on 1 of 3
attempts; 2 inconclusive (the agent did not exercise the attack)*. A pass on
every attempt emits nothing.

Mylonite never changes your project's warning filters. If your pytest config
turns warnings into errors (`filterwarnings = ["error"]`), a partial pass fails
the test. To keep partial passes green while still listing the warning, add
this entry after `"error"` in `[tool.pytest.ini_options]`:

```toml
filterwarnings = ["error", "default::mylonite.testkit.RedriveInconclusiveWarning"]
```

The second entry shows `RedriveInconclusiveWarning` in the warnings summary
instead of failing the test, and every other warning is still an error. A
`-W error` flag on the command line takes precedence over this config, so
leave that flag out of the gate job if you add the entry. Under `pending_fix` an
all-inconclusive run still fails the test; only a landing is an expected
failure.

`assert_control_holds` runs its guarded leg on every attempt but its raw leg
only until the attack has landed on it once, so a pass costs one raw re-drive
plus one guarded re-drive **per attempt**. A raw attempt that is inconclusive
has simply not landed yet, so the raw leg runs again on the next attempt. Each re-drive is one seed — roughly
a customiser call, a few planner turns and a judge call — capped at 12 model
calls and 180 seconds:

| Test | Attack lands on attempt 1 | Every attempt resists (default: 3) |
|---|---|---|
| `assert_target_resists` | 1 re-drive | 3 re-drives |
| `assert_control_holds` | 1 raw + 1 guarded | 1 raw + 3 guarded |

`attempts=` sets the number for one test. Otherwise `MYLONITE_REDRIVE_ATTEMPTS`
sets it for the whole run, and with neither it is **3**. Spend less on every
pull request and keep the full check on a schedule:

```bash
# every pull request: one attempt
MYLONITE_LIVE_TARGET=1 MYLONITE_REDRIVE_ATTEMPTS=1 pytest .mylonite/gate
# nightly: the default 3
MYLONITE_LIVE_TARGET=1 pytest .mylonite/gate
```

One attempt proves less: an attack that lands 40% of the time resists a single
re-drive 60% of the time. See
[What a live gate costs](ci-gating.md#what-a-live-gate-costs) for the
CI-operational version of this table, including provider-key setup.

## Environment variables

| Variable | Read by | Effect |
|---|---|---|
| `MYLONITE_LIVE_TARGET` | the emitted test's own skip guard | Unset (or `0`/empty): the live test is skipped and `pytest` exits `0`. Set to any truthy value to actually re-drive the target — this is the testkit's own authorization gesture for a LIVE check. |
| `MYLONITE_REQUIRE_GATE_RUN` | the pytest plugin, session-wide | Makes the run fail if any `mylonite_security`-marked test was skipped or if none was collected, instead of passing silently. Leave unset for local runs. |
| `MYLONITE_REDRIVE_ATTEMPTS` | `assert_target_resists` / `assert_control_holds`, when a test doesn't pass `attempts=` itself | How many re-drive attempts (see above). Must be plain ASCII digits from 1 to 20; anything else raises `TestkitConfigError` before any re-drive runs. Default 3. |
| `MYLONITE_MAX_LLM_REQUESTS` | the whole pytest session | A hard ceiling on LLM requests across every live re-drive in the session. Hitting it raises `TestkitRedriveAborted` naming the ceiling, and every later live re-drive in the same session stops the same way. |

## The pending-fix lifecycle

A finding your own app has not fixed yet would fail the moment its test is
committed, which blocks every later pull request until you ship the fix.
`pending_fix` is the decorator that keeps the gate PR green until then:

```python
@testkit.pending_fix("the attack still worked when this test was committed")
def test_target_resists_W2():
    testkit.assert_target_resists(exploit, target_file=target_file)
```

| State | What happens |
|---|---|
| **Not fixed yet** | The check raises `AssertionError` (the attack still lands). The test reports as an expected failure (`xfail`) and the run stays green. `pytest -ra` lists it as `XFAIL ... pending fix: ...`. |
| **Fixed** | The check passes — for a live check, no re-drive attempt landed and at least one resisted. Because the marker is strict, the test now **fails on purpose**, telling you to delete the `@testkit.pending_fix(...)` line. |
| **Marker removed** | A regular gate: passes while the fix holds, fails if the attack works again. |

Only `AssertionError` counts as "not fixed yet". Any other exception — a
missing fixture, an unresolved model, a target that never started — propagates
unchanged and fails the test, exactly as it would without the marker, so a
check that never reached a verdict is never reported green. `mylonite gate`
adds this marker automatically to every `assert_target_resists` test for a
finding that still works on your target; see
[A finding you haven't fixed yet](ci-gating.md#a-finding-you-havent-fixed-yet)
for the operational side (branch, PR body, `pytest -m mylonite_pending_fix`).

Raises `ValueError` if `reason` is empty.

## `load_exploit`

```python
testkit.load_exploit(path) -> ExploitRecord
```

Reads an `exploit_<pattern_id>.json` artefact written by `mylonite scan` into
an `ExploitRecord`. Raises `FileNotFoundError` if the file is missing,
`ValueError` if it is present but not a valid serialised record.

## Exceptions

All four subclass from the same two roots: `TestkitFixtureError` covers "the
check could not reach a trustworthy verdict"; `TestkitConfigError` covers "the
inputs to the check don't resolve". None of them is a silent pass.

- **`testkit.TestkitFixtureError`** — the offline gate's replay evidence can't be
  trusted: a missing, corrupt, or version-mismatched fixture, or a run that
  produced no conclusive attempt. The message names the re-record command
  (`mylonite validate <dir or test file>`).
- **`testkit.TestkitRedriveAborted`** (subclasses `TestkitFixtureError`) — a LIVE
  re-drive was cut short by its own 12-call/180-second bound, or by
  `MYLONITE_MAX_LLM_REQUESTS`, before reaching a verdict. There is nothing to
  re-record on this path — the message points at the target or the provider
  instead.
- **`testkit.TestkitAttackNotReproduced`** (subclasses `TestkitFixtureError`) — raised
  by `assert_control_holds` when the attack never landed on the raw target on
  any attempt, so there is nothing for the control to stop. Deliberately *not*
  an `AssertionError`: under `pending_fix` an `AssertionError` is the expected
  "not fixed yet" case and keeps the run green, so a control test that proves
  nothing would stay green forever instead of failing.
- **`testkit.TestkitConfigError`** (a `ValueError`) — the model/provider a LIVE test
  needs cannot be resolved from any source (an explicit keyword, the exploit's
  own execution-context metadata, or a sibling `scan_report.json`), or
  `attempts`/`MYLONITE_REDRIVE_ATTEMPTS` is not a whole number from 1 to 20. A
  committed test used to default silently to a hardcoded model — this error
  exists so that is loud instead.

Every assertion's failure message names what it actually re-drove:
`assert_guard_holds` names "the guarded twin" (true for the bundled reference
app); `assert_target_resists` and `assert_control_holds` name your own declared
target — neither re-drives a twin, so neither message calls your app one.

## What this does not do

The testkit re-drives a target described in a `target.yaml` through Mylonite's
own planner; it has no fixture, decorator, or builder for writing "assert my
agent resists this payload" without a scan-produced `ExploitRecord` first. See
[Coverage by app shape](index.md#coverage-by-app-shape) for which app shapes and
weakness classes it reaches at all.
