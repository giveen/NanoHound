"""UI handlers that accept a `state` parameter and delegate to _app_impl.

Wrappers here accept a `state` argument (currently unused) so callers
can pass the engine/state singleton without creating globals. They simply
delegate to the existing implementations in `ui._app_impl`.
"""

from __future__ import annotations

from typing import Any

from . import _app_impl as _impl


async def handle_upload(state: Any, event: Any) -> None:
    return await _impl.handle_upload(event)


def on_find_path(state: Any, source: str, target: str) -> None:
    return _impl.on_find_path(source, target)


def set_filter(state: Any, mode: str) -> None:
    return _impl._set_filter(mode)


def set_auto_calculate_path(state: Any, value: bool) -> None:
    return _impl._set_auto_calculate_path(value)


def sync_local_loot(state: Any) -> None:
    return _impl._sync_local_loot()


def mark_selected_node_owned(state: Any) -> None:
    return _impl._mark_selected_node_owned()


def handle_mark_owned(state: Any, node_id: str) -> None:
    """Mark an arbitrary node as owned and refresh the graph."""
    # Delegate to implementation-level function; add one if missing.
    if hasattr(_impl, "_mark_node_owned"):
        return _impl._mark_node_owned(node_id)
    # Fallback: select the node and use existing selected-node logic.
    try:
        _impl.selected_node_id = node_id
        return _impl._mark_selected_node_owned()
    except Exception:
        return None


def add_loot_for_selected_node(state: Any, password: str, ntlm_hash: str) -> None:
    return _impl._add_loot_for_selected_node(password, ntlm_hash)


def download_session(state: Any) -> None:
    return _impl._download_session()


def find_object(state: Any, query: str) -> None:
    return _impl._find_object(query)


def upsert_loot(state: Any, payload: dict[str, str]) -> None:
    return _impl._upsert_loot(payload)


def import_loot(state: Any, raw_text: str) -> int:
    return _impl._import_loot(raw_text)


def get_note(state: Any, sid: str) -> str:
    try:
        return _impl.notes_store.get_note(sid)
    except Exception:
        return ""


def has_note(state: Any, sid: str) -> bool:
    try:
        return _impl.notes_store.has_note(sid)
    except Exception:
        return False


def set_note(state: Any, sid: str, text: str) -> None:
    try:
        return _impl.notes_store.set_note(sid, text)
    except Exception:
        return None


__all__ = [
    "handle_upload",
    "on_find_path",
    "set_filter",
    "set_auto_calculate_path",
    "sync_local_loot",
    "mark_selected_node_owned",
    "add_loot_for_selected_node",
    "download_session",
    "find_object",
    "upsert_loot",
    "import_loot",
    "get_note",
    "has_note",
    "set_note",
]
# End of module
