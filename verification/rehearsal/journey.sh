#!/usr/bin/env bash
# journey.sh -- runs the documented 7-step Mylonite journey (reh3/index.md
# through reh3/7-re-prove.md) end to end, inside a fresh/empty git repo that
# stands in for "your project". Runs on ubuntu-latest and windows-latest
# (Git Bash) with `bash journey.sh`.
#
# Inputs (environment variables only):
#   REH_SERVER          "server-memory" or "kitchen-sink"
#   REH_PROVIDER        "anthropic", "openai" or "ollama"
#   REH_MODEL           full model id, e.g. anthropic/claude-haiku-4-5-20251001
#   REH_MAX_LLM_CALLS   a positive integer; used as BOTH the per-scan
#                        --max-llm-calls cap (4-find.md) AND the global
#                        MYLONITE_MAX_LLM_REQUESTS ceiling (4-find.md) for
#                        this whole run -- see deviations.md #9.
#   the provider's key, in the variable the docs name:
#     anthropic -> ANTHROPIC_API_KEY   (2-choose-a-model.md)
#     openai    -> OPENAI_API_KEY      (2-choose-a-model.md)
#     ollama    -> none (local model; MYLONITE_API_BASE is set by this
#                  script per the doc's literal example)
#
# Deliberately NOT `set -e`: every step's exit code is read and judged
# against that step's documented meaning, not treated as a shell error.
set -u

TIMING_CSV="reh_timing.csv"
: > "$TIMING_CSV"
echo "step,seconds,exit_code" >> "$TIMING_CSV"

banner() {
  echo "== STEP $1: $2 =="
}

record() {
  # record <step-label> <seconds> <exit_code>
  echo "$1,$2,$3" >> "$TIMING_CSV"
}

fail_step() {
  echo "" >&2
  echo "JOURNEY FAILED at step: $1" >&2
  echo "See $TIMING_CSV for per-step timings and exit codes." >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Required inputs (not one of the 7 steps -- a precondition check).
# ---------------------------------------------------------------------------
: "${REH_SERVER:?REH_SERVER must be 'server-memory' or 'kitchen-sink' (3-point-at-your-app.md)}"
: "${REH_PROVIDER:?REH_PROVIDER must be 'anthropic', 'openai' or 'ollama' (2-choose-a-model.md)}"
: "${REH_MODEL:?REH_MODEL must be the full model id (2-choose-a-model.md)}"
: "${REH_MAX_LLM_CALLS:?REH_MAX_LLM_CALLS must be set (4-find.md: --max-llm-calls / MYLONITE_MAX_LLM_REQUESTS)}"

# 4-find.md: "The global --max-llm-requests N (before the command) or
# MYLONITE_MAX_LLM_REQUESTS=N is the hard ceiling across this whole run."
# Set once, here, so it bounds every later step that spends (4, 5, 6, 7).
export MYLONITE_MAX_LLM_REQUESTS="$REH_MAX_LLM_CALLS"

# ===========================================================================
# STEP 1 -- Try it (1-try.md)
# ===========================================================================
banner 1 "Try it"
S=$(date +%s)
# "GitHub-hosted runners (ubuntu-latest, windows-latest) don't preinstall
# uv. In CI, or anywhere you can't install it first, use the pip install
# path above -- it needs only Python." (1-try.md)
pip install "mylonite[demo]" >reh_step1_pip.log 2>&1
RC_PIP=$?
if [ "$RC_PIP" -ne 0 ]; then
  RC=$RC_PIP
else
  mylonite demo
  RC=$?
fi
E=$(date +%s)
record "1-try" "$((E - S))" "$RC"
# 1-try.md: "Exit codes. 0 on success, whether replayed or --live. Replay's
# only failure is 2 (a missing or corrupt fixture -- reinstall mylonite, or
# add --live)." This run uses the default (replayed) path, so 0 is the only
# outcome that lets the journey continue.
if [ "$RC" -ne 0 ]; then
  fail_step "1-try (exit $RC, expected 0)"
fi

# ===========================================================================
# STEP 2 -- Choose a model (2-choose-a-model.md)
# ===========================================================================
banner 2 "Choose a model"
S=$(date +%s)
RC=0
export MYLONITE_MODEL="$REH_MODEL"
case "$REH_PROVIDER" in
  anthropic)
    # "export MYLONITE_MODEL=anthropic/claude-haiku-4-5-20251001"
    # "export ANTHROPIC_API_KEY=sk-ant-..." -- the key is an input to this
    # script (from the caller's environment), never generated here.
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
      echo "ANTHROPIC_API_KEY is not set" >&2
      RC=1
    fi
    ;;
  openai)
    # "Also supported: OpenAI (OPENAI_API_KEY)" -- no literal `export`
    # example is given for OpenAI in the docs; see deviations.md #2.
    if [ -z "${OPENAI_API_KEY:-}" ]; then
      echo "OPENAI_API_KEY is not set" >&2
      RC=1
    fi
    ;;
  ollama)
    # "export MYLONITE_MODEL=ollama_chat/llama3.2:3b"
    # "export MYLONITE_API_BASE=http://localhost:11434" -- no key needed.
    export MYLONITE_API_BASE="${MYLONITE_API_BASE:-http://localhost:11434}"
    ;;
  *)
    echo "Unsupported REH_PROVIDER: $REH_PROVIDER" >&2
    RC=1
    ;;
esac
E=$(date +%s)
record "2-choose-a-model" "$((E - S))" "$RC"
# This step is shell `export` statements in the docs, not a CLI invocation
# with its own documented exit code -- the pass/fail check above (required
# key present) is this script's own invention. See deviations.md #1.
if [ "$RC" -ne 0 ]; then
  fail_step "2-choose-a-model"
fi

# ===========================================================================
# STEP 3 -- Point at your app (3-point-at-your-app.md)
# ===========================================================================
banner 3 "Point at your app"
S=$(date +%s)
case "$REH_SERVER" in
  server-memory)
    SCOPE="server-memory"
    # Bash block verbatim (3-point-at-your-app.md): "the bash block for a
    # bash/zsh/Git-Bash/WSL/Linux/macOS shell (Git Bash provides a writable
    # /tmp even on Windows)".
    mylonite scan --command npx --arg "-y" --arg "@modelcontextprotocol/server-memory" \
      --env "MEMORY_FILE_PATH=/tmp/mylonite-memory.json" \
      --scaffold app.yaml --scope server-memory
    RC=$?
    ;;
  kitchen-sink)
    SCOPE="kitchen-sink"
    pip install "mcp-kitchen-sink[mcp]" >reh_step3_pip.log 2>&1
    RC_PIP=$?
    if [ "$RC_PIP" -ne 0 ]; then
      RC=$RC_PIP
    else
      mylonite scan --command mcp-kitchen-sink-vulnerable --scaffold app.yaml --scope kitchen-sink
      RC=$?
    fi
    ;;
  *)
    echo "Unsupported REH_SERVER: $REH_SERVER (expected server-memory or kitchen-sink)" >&2
    RC=1
    ;;
esac
E=$(date +%s)
record "3-point-at-your-app" "$((E - S))" "$RC"
# 3-point-at-your-app.md: "--scaffold exits 0 once it writes the file, 2 on
# any config/usage error ... There's no 3/4 here: scaffold makes no LLM
# call."
if [ "$RC" -ne 0 ]; then
  fail_step "3-point-at-your-app"
fi

# ===========================================================================
# STEP 4 -- Find (4-find.md)
# ===========================================================================
banner 4 "Find"
S=$(date +%s)
# "--authorize asserts you control the target: its value must match the
# scope you scaffolded with" -- SCOPE was set to the --scope value in step 3.
mylonite scan --target-file app.yaml --authorize "$SCOPE" --max-llm-calls "$REH_MAX_LLM_CALLS"
RC=$?
E=$(date +%s)
record "4-find" "$((E - S))" "$RC"
# 4-find.md: "scan exits 0 whether or not it finds anything -- reporting a
# weakness is not a failure. 2 is a config or usage error (including an
# empty scan), 3 is the budget or request ceiling above, and 4 is a missing
# model choice or a provider/credential that refused the run before the
# target was ever touched."
if [ "$RC" -ne 0 ]; then
  fail_step "4-find (exit $RC, expected 0)"
fi

# ===========================================================================
# STEP 5 -- Prove (5-prove.md)
# ===========================================================================
banner 5 "Prove"
S=$(date +%s)
mylonite generate --latest >reh_step5_generate.log 2>&1
RC=$?
cat reh_step5_generate.log
if [ "$RC" -ne 0 ]; then
  E=$(date +%s)
  record "5-prove" "$((E - S))" "$RC"
  # 5-prove.md (generate): "0 once the test is written. 2 is a config/usage
  # error -- no scan found (run mylonite scan first), or an invalid
  # --target-file. 5 only if you re-run generate against a finding a prior
  # validate already rejected, without passing --unvalidated."
  fail_step "5-prove (generate --latest, exit $RC)"
fi
# "The line after 'Then:' that starts with mylonite validate is the exact
# command to run next -- take it literally, paths and all." (5-prove.md)
# A reference-target finding instead prints only "Next: mylonite validate
# <dir>" -- the same grep matches both forms.
VALIDATE_CMD=$(grep -m1 -o 'mylonite validate .*' reh_step5_generate.log || true)
if [ -z "$VALIDATE_CMD" ]; then
  E=$(date +%s)
  record "5-prove" "$((E - S))" "1"
  fail_step "5-prove (no 'mylonite validate ...' line found in generate output)"
fi
eval "$VALIDATE_CMD"
RC=$?
E=$(date +%s)
record "5-prove" "$((E - S))" "$RC"
# 5-prove.md (validate): "Exits 0 when kept, 5 when cleanly rejected. ... This
# step spends too: the same global --max-llm-requests N /
# MYLONITE_MAX_LLM_REQUESTS=N ceiling from step 4 applies here; hitting it
# exits 3."
if [ "$RC" -ne 0 ]; then
  fail_step "5-prove (validate, exit $RC, expected 0: kept)"
fi

# ===========================================================================
# STEP 6 -- Commit the gate (6-commit-the-gate.md)
# ===========================================================================
banner 6 "Commit the gate"
S=$(date +%s)
# "Committing needs a git identity. On a fresh machine or a CI runner that
# has none, set one in the repository first:" (6-commit-the-gate.md)
git config user.name "Your Name"
git config user.email "you@example.com"
# Plain `gate` (no --open-pr, no --workflows): "By default, nothing outside
# .mylonite/gate/ changes ... and prints the exact git/gh commands to commit
# and open the PR yourself."
mylonite gate --target-file app.yaml --authorize "$SCOPE" --max-llm-calls "$REH_MAX_LLM_CALLS" >reh_step6_gate.log 2>&1
GATE_RC=$?
cat reh_step6_gate.log
FINAL_RC=$GATE_RC
if [ "$GATE_RC" -eq 9 ]; then
  # "To commit the gate without opening a PR, run the plain command above
  # (no --open-pr), then run only the printed git checkout -b and
  # git add/git commit lines yourself, verbatim -- stop before the git
  # push/gh pr create lines." (6-commit-the-gate.md)
  CO_LINE=$(grep -m1 '^[[:space:]]*git checkout -b' reh_step6_gate.log || true)
  ADD_LINE=$(grep -m1 '^[[:space:]]*git add' reh_step6_gate.log || true)
  COMMIT_LINE=$(grep -m1 '^[[:space:]]*git commit' reh_step6_gate.log || true)
  if [ -z "$CO_LINE" ] || [ -z "$ADD_LINE" ] || [ -z "$COMMIT_LINE" ]; then
    FINAL_RC=1
  else
    eval "$CO_LINE" && eval "$ADD_LINE" && eval "$COMMIT_LINE"
    FINAL_RC=$?
  fi
fi
E=$(date +%s)
record "6-commit-the-gate" "$((E - S))" "$FINAL_RC"
# 6-commit-the-gate.md: "9 means at least one proven finding was kept and
# its gate test written; 0 means the scan ran and found nothing. 10 means
# nothing was kept, but something reproduced without proof -- a candidate
# ... never-keep-unproven. 5 is a finding that was rejected rather than
# kept; 6/7 are the generator/validator returning nothing (an internal
# failure); 8 means the git/gh step itself failed."
if [ "$GATE_RC" -ne 9 ]; then
  fail_step "6-commit-the-gate (gate exit $GATE_RC, expected 9: kept + test written)"
fi
if [ "$FINAL_RC" -ne 0 ]; then
  fail_step "6-commit-the-gate (printed git checkout-b/add/commit lines, exit $FINAL_RC)"
fi

# ===========================================================================
# STEP 7 -- Re-prove (7-re-prove.md)
# ===========================================================================
banner 7 "Re-prove"
S=$(date +%s)
# "The environment variable is not optional. Without MYLONITE_LIVE_TARGET=1,
# the test is skipped ... With MYLONITE_LIVE_TARGET=1 set, this re-drives
# your real app live."
MYLONITE_LIVE_TARGET=1 pytest .mylonite/gate/
RC=$?
E=$(date +%s)
record "7-re-prove" "$((E - S))" "$RC"
# 7-re-prove.md, stage 1 ("Before the fix"): "The attack still lands, so the
# check fails -- reported as an expected failure (xfail), and the run stays
# green: pytest itself exits 0." This rehearsal never ships a fix (the docs'
# fix is "a change in your own app's code or configuration" -- out of scope
# here), so stage 1 (exit 0) is the only reachable documented outcome; stage
# 2 ("After the fix", exit 1) and stage 3 (marker removed) require shipping
# a real fix first. See deviations.md #11.
if [ "$RC" -ne 0 ]; then
  fail_step "7-re-prove (exit $RC, expected 0: pending-fix stage, attack still lands / xfail)"
fi

echo ""
echo "All 7 steps reached their documented outcome."
exit 0
