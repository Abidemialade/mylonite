"""A stdio MCP mail server that accepts some sends for later delivery.

Test fixture for ``test_deferred_effect_e2e.py``. Hand-rolled JSON-RPC over
stdio (no SDK), so the test drives the real MCP client, adapter, calibration and
CLI against a server whose replies and timing it controls.

``send_email`` to an address without ``@`` (what calibration's control write
fills ``to`` with) lands at once and replies ``sent``. A send to an external
address is the deferred path, shaped by environment variables:

* ``MAIL_REPLY``: the reply text (default ``queued: will be sent shortly``).
* ``MAIL_DELAY_S``: seconds until the record lands (default ``0``). A large value
  means it lands long after the scan's probe has read.
* ``MAIL_TASK=1``: add ``resultType: "task"`` and a ``task`` object to the reply.
* ``MAIL_HOLD=1``: the send is held, never delivered; ``check_outbox`` lists it
  as ``HELD to=... body=...``.
* ``MAIL_VIEW=session``: ``check_outbox`` lists only this process's sends.
  Default ``global``: every landed record in the state file.

State lives in ``MAIL_STATE`` (a JSON file), so it outlives each relaunch.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

STATE = Path(os.environ.get("MAIL_STATE", "mail_state.json"))
REPLY = os.environ.get("MAIL_REPLY", "queued: will be sent shortly")
DELAY = float(os.environ.get("MAIL_DELAY_S", "0"))
TASK = os.environ.get("MAIL_TASK") == "1"
HOLD = os.environ.get("MAIL_HOLD") == "1"
VIEW = os.environ.get("MAIL_VIEW", "global")
MINE: set[str] = set()

TOOLS = [
    {
        "name": "send_email",
        "description": "Send an email.",
        "inputSchema": {
            "type": "object",
            "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
            "required": ["to", "body"],
        },
    },
    {
        "name": "check_outbox",
        "description": "Read the outbox: every delivered message.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _load() -> list[dict[str, Any]]:
    try:
        rows = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return rows if isinstance(rows, list) else []


def _save(rows: list[dict[str, Any]]) -> None:
    STATE.write_text(json.dumps(rows), encoding="utf-8")


def _write(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _text(msg_id: object, text: str, extra: dict[str, Any] | None = None) -> None:
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": False}
    result.update(extra or {})
    _write({"jsonrpc": "2.0", "id": msg_id, "result": result})


def _send(msg_id: object, args: dict[str, Any]) -> None:
    to, body = str(args.get("to", "")), str(args.get("body", ""))
    external = "@" in to
    now = time.time()
    rows = _load()
    rid = uuid.uuid4().hex
    MINE.add(rid)
    rows.append(
        {
            "id": rid,
            "to": to,
            "body": body,
            "held": external and HOLD,
            "land_at": now + (DELAY if external else 0.0),
        }
    )
    _save(rows)
    if not external:
        _text(msg_id, f"sent to {to}")
        return
    extra = None
    if TASK:
        tid = "job-" + rid[:8]
        extra = {"resultType": "task", "task": {"taskId": tid, "status": "working"}}
    _text(msg_id, REPLY, extra)


def _outbox(msg_id: object) -> None:
    now = time.time()
    lines = []
    for row in _load():
        if VIEW == "session" and row["id"] not in MINE:
            continue
        if row.get("held"):
            lines.append(f"HELD to={row['to']} body={row['body']}")
        elif row["land_at"] <= now:
            lines.append(f"to={row['to']} body={row['body']}")
    _text(msg_id, "outbox:\n" + ("\n".join(lines) if lines else "(empty)"))


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        method, msg_id = msg.get("method"), msg.get("id")
        if method == "initialize":
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "deferred-mail", "version": "0.0.1"},
                    },
                }
            )
        elif msg_id is None:
            continue
        elif method == "tools/list":
            _write({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = msg.get("params") or {}
            name, args = params.get("name"), params.get("arguments") or {}
            if name == "send_email":
                _send(msg_id, args)
            elif name == "check_outbox":
                _outbox(msg_id)
            else:
                _write({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "no"}})
        else:
            _write({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "no"}})


if __name__ == "__main__":
    main()
