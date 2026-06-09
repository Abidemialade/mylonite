"""In-memory note store used by both server variants.

Intentionally trivial. The "untrusted content" used to exercise indirect
injection lives in note bodies and in fetched URLs, not in this storage
layer itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NoteStore:
    notes: dict[str, str] = field(default_factory=dict)
    sent_emails: list[tuple[str, str, str]] = field(default_factory=list)
    fetched_urls: list[str] = field(default_factory=list)

    def write(self, note_id: str, body: str) -> None:
        self.notes[note_id] = body

    def read(self, note_id: str) -> str | None:
        return self.notes.get(note_id)

    def record_email(self, to: str, subject: str, body: str) -> None:
        self.sent_emails.append((to, subject, body))

    def record_fetch(self, url: str) -> None:
        self.fetched_urls.append(url)
