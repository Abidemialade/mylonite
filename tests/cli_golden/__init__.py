"""Characterisation ("golden") tests for the `mylonite` CLI (PR 0 / #91).

These pin down observable CLI behaviour -- `--help` text, dry-run seed
listings, and the offline `demo` replay -- BEFORE `cli.py` is reorganised
into domain modules. They must pass unchanged before and after every move in
that refactor; a diff here means behaviour changed, which the refactor must
not do.
"""

from __future__ import annotations
