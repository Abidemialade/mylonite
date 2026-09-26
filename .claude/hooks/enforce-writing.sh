#!/usr/bin/env bash
# PreToolUse hook: runs the writing and docs-sync checks before git commit,
# git push and gh pr create/edit. See .claude/hooks/enforce_writing.py.
#
# Picks the first Python 3 that actually runs. On Windows "python3" can be the
# Microsoft Store stub, which exists on PATH but does nothing, so each
# candidate is probed before use. With no working Python the hook allows the
# call: CI runs the same checks.
for candidate in python python3 py; do
  if command -v "$candidate" >/dev/null 2>&1 \
     && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
    exec "$candidate" "$(dirname "$0")/enforce_writing.py"
  fi
done
exit 0
