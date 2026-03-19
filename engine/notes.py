"""Per-node note storage keyed by object SID."""

from __future__ import annotations


class NotesStore:
    """Map AD object SIDs to free-text intelligence notes."""

    def __init__(self) -> None:
        self._notes: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def set_note(self, sid: str, text: str) -> None:
        """Upsert a note.  Passing an empty *text* deletes the entry."""
        sid = sid.strip()
        if not sid:
            return
        if text:
            self._notes[sid] = text
        else:
            self._notes.pop(sid, None)

    def delete_note(self, sid: str) -> None:
        self._notes.pop(sid.strip(), None)

    def clear(self) -> None:
        self._notes.clear()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_note(self, sid: str) -> str:
        """Return the note for *sid*, or an empty string if none exists."""
        return self._notes.get(sid.strip(), "")

    def has_note(self, sid: str) -> bool:
        return bool(self._notes.get(sid.strip()))

    def all_notes(self) -> dict[str, str]:
        """Return a shallow copy of the full mapping."""
        return dict(self._notes)

    # ------------------------------------------------------------------
    # Bulk load (used by session restore)
    # ------------------------------------------------------------------

    def load_notes(self, data: dict[str, str]) -> None:
        """Replace the current store with *data*, silently skipping blank entries."""
        self._notes = {k.strip(): v for k, v in data.items() if k and v}
