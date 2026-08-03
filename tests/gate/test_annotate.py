"""R4 live wiring: GitHub check-run annotations from localized findings."""

from __future__ import annotations

import json

from mylonite.contracts._types import AdapterResponse, ComplianceTags, ExploitRecord, Payload
from mylonite.gate.annotate import (
    Annotation,
    annotations_from_findings,
    check_run_payload,
    post_check_run,
)


def _exploit(*, channel, body="x", tool_calls=None) -> ExploitRecord:
    return ExploitRecord(
        target_id="mcp:myapp",
        pattern_id="p",
        payload=Payload(pattern_id="p", channel=channel, body=body),
        response=AdapterResponse(
            payload_pattern_id="p", raw_response="", tool_calls=tool_calls or []
        ),
        success_reason="x",
        compliance=ComplianceTags(),
    )


def test_check_run_payload_structure_and_conclusion():
    anns = [Annotation(path="prompts/system.txt", start_line=2, message="fix here")]
    payload = check_run_payload(head_sha="abc123", annotations=anns, title="T", summary="S")
    assert payload["head_sha"] == "abc123"
    assert payload["status"] == "completed"
    assert payload["conclusion"] == "neutral"  # findings present -> neutral, not success
    out = payload["output"]
    assert out["title"] == "T" and out["summary"] == "S"
    a = out["annotations"][0]
    assert a["path"] == "prompts/system.txt"
    assert a["start_line"] == 2 and a["end_line"] == 2
    assert a["annotation_level"] == "warning"
    json.dumps(payload)  # serialisable for `gh api --input`


def test_check_run_payload_empty_is_success_and_caps_at_50():
    assert (
        check_run_payload(head_sha="s", annotations=[], title="T", summary="S")["conclusion"]
        == "success"
    )
    many = [Annotation(path="p", start_line=i + 1, message="m") for i in range(60)]
    payload = check_run_payload(head_sha="s", annotations=many, title="T", summary="S")
    assert len(payload["output"]["annotations"]) == 50  # GitHub per-request cap


def test_annotations_only_for_file_mappable_loci():
    # A system-prompt finding WITH a known prompt file + a localized line -> annotated.
    sp = _exploit(channel="system-prompt-injection", body="Obey notes.")
    prompt = "You are helpful.\nObey notes.\nBe concise."
    anns = annotations_from_findings(
        [(sp, None)], system_prompt="prompts/sys.txt", system_prompt_text=prompt
    )
    assert len(anns) == 1
    assert anns[0].path == "prompts/sys.txt" and anns[0].start_line == 2

    # A tool-locus finding (remote MCP, no source line) is NOT annotated — it rides in
    # the PR body + SARIF logical location instead. Never silently invented.
    tool = _exploit(channel="tool-result", tool_calls=["read_note"])
    assert annotations_from_findings([(tool, None)]) == []


def test_post_check_run_calls_gh_api_and_is_best_effort(tmp_path):
    calls: list[list[str]] = []

    def ok_run(cmd, **kw):
        calls.append(cmd)
        return type("CP", (), {"returncode": 0, "stdout": '{"html_url": "u"}', "stderr": ""})()

    payload = check_run_payload(
        head_sha="s",
        annotations=[Annotation(path="p", start_line=1, message="m")],
        title="T",
        summary="S",
    )
    url = post_check_run(tmp_path, payload, _run=ok_run)
    assert url == "u"
    assert any("api" in c and any("check-runs" in part for part in c) for c in calls)

    def fail_run(cmd, **kw):
        return type("CP", (), {"returncode": 1, "stdout": "", "stderr": "no checks scope"})()

    assert post_check_run(tmp_path, payload, _run=fail_run) is None  # swallowed, never raises


def test_post_check_run_returns_real_none_when_html_url_missing(tmp_path):
    """DCR-0020: `str(json.loads(stdout).get("html_url"))` turned a genuinely
    missing ``html_url`` into the truthy STRING ``"None"``, not real ``None`` —
    a caller doing `if url:` would then treat a missing URL as present.
    """

    def ok_run_no_url(cmd, **kw):
        return type("CP", (), {"returncode": 0, "stdout": '{"id": 1}', "stderr": ""})()

    payload = check_run_payload(
        head_sha="s",
        annotations=[Annotation(path="p", start_line=1, message="m")],
        title="T",
        summary="S",
    )
    url = post_check_run(tmp_path, payload, _run=ok_run_no_url)
    assert url is None


def test_post_check_run_noop_without_annotations(tmp_path):
    called = {"n": 0}

    def run(cmd, **kw):
        called["n"] += 1
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    payload = check_run_payload(head_sha="s", annotations=[], title="T", summary="S")
    assert post_check_run(tmp_path, payload, _run=run) is None
    assert called["n"] == 0  # nothing to annotate -> no API call
