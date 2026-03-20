"""Session serialization – export and restore the full NanoHound workspace."""

from __future__ import annotations

import json
from datetime import date
from typing import Any

import networkx as nx
from networkx.readwrite import json_graph

from engine.graph_logic import NanoGraphEngine
from engine.loot import LootManager
from engine.notes import NotesStore

SESSION_VERSION = 1


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def export_session(
    graph_engine: NanoGraphEngine,
    loot_manager: LootManager,
    notes_store: NotesStore,
) -> dict[str, Any]:
    """Serialize the current workspace to a JSON-serialisable dict."""
    return {
        "version": SESSION_VERSION,
        "exported_at": date.today().isoformat(),
        "graph": json_graph.node_link_data(graph_engine.graph),
        "loot": loot_manager.all_credentials(),
        "notes": notes_store.all_notes(),
    }


def session_to_json(
    graph_engine: NanoGraphEngine,
    loot_manager: LootManager,
    notes_store: NotesStore,
) -> bytes:
    """Return a UTF-8-encoded JSON blob for the current session."""
    return json.dumps(
        export_session(graph_engine, loot_manager, notes_store),
        indent=2,
        default=str,
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def is_session_file(data: Any) -> bool:
    """Return True when *data* is a NanoHound session export dict."""
    return (
        isinstance(data, dict)
        and data.get("version") == SESSION_VERSION
        and "graph" in data
    )


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


def load_session(
    data: dict[str, Any],
    graph_engine: NanoGraphEngine,
    loot_manager: LootManager,
    notes_store: NotesStore,
) -> None:
    """Restore a session from a previously exported dict in-place.

    The callers are responsible for calling ``graph_engine.clear()`` before
    invoking this function if they want a clean slate.
    """
    # -- Graph ---------------------------------------------------------------
    graph_data = data.get("graph") or {}
    if graph_data:
        restored: nx.DiGraph = json_graph.node_link_graph(
            graph_data, directed=True, multigraph=False
        )
        # Copy into the shared engine instance rather than replacing the reference.
        graph_engine.graph.clear()
        graph_engine.graph.update(restored)
    # else: leave graph empty

    # -- Loot ----------------------------------------------------------------
    loot_manager.clear()
    for row in data.get("loot") or []:
        principal = (row.get("principal") or "").strip()
        if not principal:
            continue
        loot_manager.upsert_credential(
            principal=principal,
            username=row.get("username", ""),
            domain=row.get("domain", ""),
            password=row.get("password", ""),
            ntlm_hash=row.get("ntlm_hash", ""),
            kerberos_ticket=row.get("kerberos_ticket", ""),
            source=row.get("source", "session"),
        )

    # -- Notes ---------------------------------------------------------------
    notes_store.load_notes(data.get("notes") or {})
