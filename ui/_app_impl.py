"""Core application logic moved from app.py.

This module contains the graph/ingestor/loot/notes instances and
the imperative handler functions used by the UI. It does NOT start
the NiceGUI server; that is the responsibility of top-level `app.py`.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable, Iterable
from datetime import date
from pathlib import Path
from typing import Any

import networkx as nx
from nicegui import events, ui

from engine.commands import CommandOracle
from engine.graph_logic import NanoGraphEngine
from engine.ingestor import SharpHoundIngestor
from engine.loot import LootManager
from engine.notes import NotesStore
from engine import state as session_state
from ui.components import (
    create_loot_table_tab,
    create_notes_panel,
    create_search_bar,
    create_upload_dropzone,
)
from . import graph_renderer


ingestor = SharpHoundIngestor()
graph_engine = NanoGraphEngine()
loot_manager = LootManager()
notes_store = NotesStore()

# Replace NiceGUI notify with a safe wrapper to avoid errors when tasks
# run outside of a NiceGUI slot (background tasks). This keeps calls to
# `ui.notify(...)` safe from raising `RuntimeError` during automated
# ingestion or other background processing.
_old_ui_notify = ui.notify
def _safe_notify(message: str, color: str | None = None) -> None:
    try:
        _old_ui_notify(message, color=color)
    except Exception:
        # Ignore failures to notify when not in a NiceGUI slot.
        return

# Mutate the `ui` module's notify to the safe wrapper for this process.
ui.notify = _safe_notify

# Runtime UI state defaults (exposed for layout/components to read/write)
selected_node_id: str = ""
selected_node_label: str = ""
highlighted_manual_path: list[str] = []
highlighted_live_path: list[str] = []
active_filter: str = "all"
# Whether the UI should auto-calculate a live path to Domain Admins
auto_calculate_path_to_da: bool = True
focused_owned_node_id: str = ""

# UI widget callbacks/placeholders populated by `build_ui()`
chart_placeholder = None
status_label = None
loot_refresh_callback = None
edge_selection_label = None
oracle_content_container = None
update_notes_panel_callback = None
update_selected_node_panel_callback = None
show_oracle_tab_callback = None
path_source_input = None
path_target_input = None

loaded_data: dict = ingestor.empty_parsed()

# Helper: expand a set of principal nodes to include adjacent members via
# MemberOf relationships. Used by quick-filtering to show context.
def _member_of_neighbors(scoped_nodes: set[str]) -> set[str]:
    neighbors: set[str] = set()
    for source, target, attrs in graph_engine.graph.edges(data=True):
        relation = str(attrs.get("raw_right") or attrs.get("relationship") or "")
        if relation != "MemberOf":
            continue
        if source in scoped_nodes:
            neighbors.add(target)
        if target in scoped_nodes:
            neighbors.add(source)
    return neighbors


def _owned_focus_neighborhood(node_id: str, max_out_hops: int = 2) -> set[str]:
    """Return a compact neighborhood around an owned node for visual focus.

    Includes:
    - outbound directed reachability up to ``max_out_hops``
    - immediate inbound neighbors for context
    """
    if node_id not in graph_engine.graph:
        return set()

    try:
        outward = set(
            nx.single_source_shortest_path_length(
                graph_engine.graph,
                node_id,
                cutoff=max_out_hops,
            ).keys()
        )
    except nx.NetworkXError:
        outward = {node_id}

    inbound = {
        src
        for src, dst in graph_engine.graph.in_edges(node_id)
        if dst == node_id
    }
    return outward | inbound | {node_id}


def _set_owned_focus(node_id: str | None) -> None:
    """Activate focus mode around an owned node (or clear when None)."""
    global focused_owned_node_id
    focused_owned_node_id = node_id or ""


def _clear_owned_focus() -> None:
    _set_owned_focus(None)


def _resolve_filtered_nodes(filter_mode: str) -> set[str]:
    """Return visible nodes based on current quick-filter selection."""
    all_nodes = {node_id for node_id, _ in graph_engine.graph.nodes(data=True)}
    if filter_mode == "all":
        return all_nodes

    if filter_mode == "kerberoastable":
        principals = {
            node_id
            for node_id, attrs in graph_engine.graph.nodes(data=True)
            if attrs.get("type") == "user" and bool(attrs.get("is_kerberoastable"))
        }
        return _member_of_neighbors(principals)

    if filter_mode == "asrep_roastable":
        principals = {
            node_id
            for node_id, attrs in graph_engine.graph.nodes(data=True)
            if attrs.get("type") == "user" and bool(attrs.get("is_asrep_roastable"))
        }
        return _member_of_neighbors(principals)

    if filter_mode == "owned":
        principals = {
            node_id
            for node_id, attrs in graph_engine.graph.nodes(data=True)
            if bool(attrs.get("is_owned"))
        }
        return _member_of_neighbors(principals)

    return all_nodes


def _find_matching_nodes(query: str) -> list[tuple[str, str]]:
    """Return (node_id, display_name) tuples matching a SID/name query."""
    needle = query.strip().casefold()
    if not needle:
        return []

    starts_with: list[tuple[str, str]] = []
    contains: list[tuple[str, str]] = []
    for node_id, attrs in graph_engine.graph.nodes(data=True):
        node_name = str(attrs.get("name", ""))
        entry = (str(node_id), node_name or str(node_id))
        node_id_l = str(node_id).casefold()
        node_name_l = node_name.casefold()
        if node_id_l.startswith(needle) or node_name_l.startswith(needle):
            starts_with.append(entry)
        elif needle in node_id_l or needle in node_name_l:
            contains.append(entry)

    starts_with.sort(key=lambda row: row[1].casefold())
    contains.sort(key=lambda row: row[1].casefold())
    return starts_with + contains


def _autocomplete_candidates(query: str, limit: int = 10) -> list[tuple[str, str]]:
    """Return quick search suggestions prioritized for user objects."""
    ranked_matches = _find_matching_nodes(query)
    if not ranked_matches:
        return []

    users: list[tuple[str, str]] = []
    non_users: list[tuple[str, str]] = []
    for node_id, label in ranked_matches:
        node_type = str(graph_engine.graph.nodes.get(node_id, {}).get("type", ""))
        if node_type == "user":
            users.append((node_id, label))
        else:
            non_users.append((node_id, label))

    return (users + non_users)[:limit]


def _find_object(query: str) -> None:
    """Highlight the first matching node in the graph by SID/name."""
    global selected_node_id, selected_node_label
    matches = _find_matching_nodes(query)
    if not matches:
        ui.notify("No matching objects found", color="warning")
        return

    node_id, node_name = matches[0]
    selected_node_id = node_id
    selected_node_label = node_name
    _refresh_chart(manual_path=[node_id])
    if update_notes_panel_callback:
        update_notes_panel_callback(node_id, node_name)
    if update_selected_node_panel_callback:
        update_selected_node_panel_callback(node_id)

    if len(matches) == 1:
        _set_status(f"Found object: {node_name}")
    else:
        _set_status(f"Found {len(matches)} matches, focused first: {node_name}")
    ui.notify(f"Matched {len(matches)} object(s)", color="info")


def _set_owned_by_query(query: str, owned: bool) -> None:
    """Set ownership status for every node matching a SID/name query."""
    matches = _find_matching_nodes(query)
    if not matches:
        ui.notify("No matching objects found", color="warning")
        return

    for node_id, _ in matches:
        graph_engine.graph.nodes[node_id]["is_owned"] = owned

    if owned:
        _set_owned_focus(matches[0][0])
    elif focused_owned_node_id in {node_id for node_id, _ in matches}:
        _clear_owned_focus()

    _refresh_chart(manual_path=[matches[0][0]])
    _recalculate_live_path(notify_when_missing=True)
    state_label = "owned" if owned else "not owned"
    _set_status(f"Marked {len(matches)} object(s) as {state_label}")
    ui.notify(f"Updated {len(matches)} object(s)", color="positive")


def _refresh_chart(
    manual_path: list[str] | None = None,
    live_path: list[str] | None = None,
) -> None:
    if chart_placeholder is None:
        return

    active_manual_path = manual_path if manual_path is not None else highlighted_manual_path
    active_live_path = live_path if live_path is not None else highlighted_live_path

    chart_placeholder.run_chart_method(
        "setOption",
        graph_renderer.build_chart_options(
            manual_path=active_manual_path,
            live_path=active_live_path,
            filter_mode=active_filter,
            focused_owned_node_id=focused_owned_node_id,
        ),
        True,
    )


def _recalculate_live_path(notify_when_missing: bool = False) -> None:
    """Recompute and redraw the weighted path from owned beachheads to DA."""
    global highlighted_live_path

    if not auto_calculate_path_to_da:
        highlighted_live_path = []
        _refresh_chart()
        return

    path = graph_engine.get_shortest_path_from_owned("DOMAIN ADMINS")
    if path:
        highlighted_live_path = path
        _refresh_chart()
        _set_status("Live path to DA updated")
        return

    highlighted_live_path = []
    _refresh_chart()
    if notify_when_missing:
        _set_status("No viable attack path to DA found from current beachheads.")


def _set_filter(mode: str) -> None:
    """Set graph quick-filter mode and refresh visualization."""
    global active_filter
    active_filter = mode
    _refresh_chart()

    if mode == "kerberoastable":
        _set_status("Filter: Kerberoastable users + immediate groups")
        return
    if mode == "asrep_roastable":
        _set_status("Filter: AS-REP roastable users + immediate groups")
        return
    if mode == "owned":
        _set_status("Filter: Owned objects + immediate groups")
        return
    _set_status("Filter cleared")


def _set_auto_calculate_path(value: bool) -> None:
    """Enable/disable reactive DA path calculation."""
    global auto_calculate_path_to_da, highlighted_live_path
    auto_calculate_path_to_da = bool(value)
    if auto_calculate_path_to_da:
        _recalculate_live_path(notify_when_missing=True)
    else:
        highlighted_live_path = []
        _set_status("Auto-Calculate Path to DA disabled")
        _refresh_chart(live_path=[])


def _sync_local_loot() -> None:
    """Read hashes.txt and passwords.txt from CWD and populate the LootManager."""
    cwd = Path.cwd()
    imported = 0
    errors: list[str] = []

    for filename in ("hashes.txt", "passwords.txt"):
        candidate = cwd / filename
        if not candidate.exists():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
            n = loot_manager.import_secrets_text(text)
            imported += n
        except OSError as exc:
            errors.append(f"{filename}: {exc}")

    if errors:
        ui.notify(f"Sync errors: {'; '.join(errors)}", color="warning")

    if imported:
        _refresh_chart()
        _recalculate_live_path(notify_when_missing=True)
        if loot_refresh_callback:
            loot_refresh_callback()
        _set_status(f"Synced {imported} credential entries from local files")
        ui.notify(f"Synced {imported} credentials", color="positive")
    else:
        ui.notify("No credentials found in hashes.txt / passwords.txt", color="info")


def _set_status(message: str) -> None:
    if status_label is not None:
        status_label.text = message


def _render_oracle_panel(
    summary: str,
    commands: list[tuple[str, str]],
) -> None:
    """Rebuild the right-drawer Command Oracle with code blocks and copy buttons."""
    global selected_edge_command, oracle_content_container

    selected_edge_command = commands[0][1] if commands else ""
    if show_oracle_tab_callback is not None:
        show_oracle_tab_callback()
    if edge_selection_label is not None:
        edge_selection_label.text = summary
    if oracle_content_container is None:
        return

    oracle_content_container.clear()
    with oracle_content_container:
        for cmd_label, cmd_text in commands:
            ui.label(cmd_label).classes(
                "text-xs uppercase tracking-wider text-white mt-3"
            )
            ui.code(cmd_text, language="bash").classes("w-full whitespace-pre-wrap")

            def _make_copy_handler(cmd: str = cmd_text) -> Any:
                def _handle() -> None:
                    ui.run_javascript(
                        f"navigator.clipboard.writeText({json.dumps(cmd)})"
                    )
                    ui.notify("Copied!", color="positive")

                return _handle

            (
                ui.button("Copy", on_click=_make_copy_handler())
                .props("flat size=sm icon=content_copy")
                .classes("text-white self-end")
            )


def _set_path_inputs(source: str = "", target: str = "") -> None:
    """Update the path finder inputs when graph interactions provide context."""
    if path_source_input is not None and source:
        path_source_input.value = source
        path_source_input.update()
    if path_target_input is not None and target:
        path_target_input.value = target
        path_target_input.update()


def _default_source_target() -> tuple[str, str]:
    """Return best-effort defaults for path source/target input fields.

    Source preference: first owned node, otherwise first user node, otherwise any node.
    Target preference: Domain Admins group by normalized match, otherwise first group.
    """
    source_value = ""
    target_value = ""

    owned_nodes: list[tuple[str, dict[str, Any]]] = []
    user_nodes: list[tuple[str, dict[str, Any]]] = []
    group_nodes: list[tuple[str, dict[str, Any]]] = []
    all_nodes: list[tuple[str, dict[str, Any]]] = []

    for node_id, attrs in graph_engine.graph.nodes(data=True):
        all_nodes.append((str(node_id), attrs))
        node_type = str(attrs.get("type", "")).casefold()
        if bool(attrs.get("is_owned")):
            owned_nodes.append((str(node_id), attrs))
        if node_type == "user":
            user_nodes.append((str(node_id), attrs))
        if node_type == "group":
            group_nodes.append((str(node_id), attrs))

    if owned_nodes:
        source_value = str(owned_nodes[0][1].get("name") or owned_nodes[0][0])
    elif user_nodes:
        source_value = str(user_nodes[0][1].get("name") or user_nodes[0][0])
    elif all_nodes:
        source_value = str(all_nodes[0][1].get("name") or all_nodes[0][0])

    domain_admin_group = next(
        (
            (node_id, attrs)
            for node_id, attrs in group_nodes
            if graph_engine._is_target_group(node_id, "DOMAIN ADMINS")
        ),
        None,
    )
    if domain_admin_group is not None:
        target_value = str(domain_admin_group[1].get("name") or domain_admin_group[0])
    elif group_nodes:
        target_value = str(group_nodes[0][1].get("name") or group_nodes[0][0])
    else:
        target_value = "DOMAIN ADMINS"

    return source_value, target_value


def _autofill_path_inputs() -> None:
    """Populate source/target path fields with best-effort graph defaults."""
    source_value, target_value = _default_source_target()
    if not source_value and not target_value:
        return
    _set_path_inputs(source=source_value, target=target_value)


def _extract_domain(name: str) -> str:
    if "@" in name:
        return name.split("@", maxsplit=1)[1]
    if "." in name:
        parts = name.split(".")
        if len(parts) > 1:
            return ".".join(parts[1:])
    return ""


def _node_context(node_id: str) -> dict[str, str]:
    """Build command-oracle context from a graph node id."""
    attrs = graph_engine.graph.nodes[node_id] if node_id in graph_engine.graph else {}
    node_name = str(attrs.get("name") or node_id)
    return {
        "id": str(node_id),
        "name": node_name,
        "type": str(attrs.get("type", "entity")),
        "spn": str(attrs.get("spn", "")),
        "domain": str(attrs.get("domain") or _extract_domain(node_name)),
    }


def _resolve_node_reference(value: Any) -> str:
    """Resolve chart click node refs (id/name/index-like values) into graph node ids."""
    if isinstance(value, dict):
        for key in ("id", "name", "value"):
            if key in value:
                return _resolve_node_reference(value[key])
        return ""

    candidate = str(value or "").strip()
    if not candidate:
        return ""
    if candidate in graph_engine.graph:
        return candidate

    # Fallback to name lookup when the chart emits node names.
    lowered = candidate.casefold()
    for node_id, attrs in graph_engine.graph.nodes(data=True):
        node_name = str(attrs.get("name", "")).casefold()
        if node_name == lowered:
            return str(node_id)

    return candidate


def _edge_relationship(source_id: str, target_id: str, fallback: str = "") -> str:
    """Get edge type from graph first, fallback to chart payload value."""
    edge_data = graph_engine.graph.get_edge_data(source_id, target_id) or {}
    relationship = str(
        edge_data.get("raw_right")
        or edge_data.get("relationship")
        or fallback
        or "Unknown"
    )
    return relationship


def _parse_identity_parts(node_id: str) -> tuple[str, str, str]:
    """Infer principal/domain/username from a graph node."""
    attrs = graph_engine.graph.nodes[node_id] if node_id in graph_engine.graph else {}
    node_name = str(attrs.get("name") or node_id)
    domain = str(attrs.get("domain") or _extract_domain(node_name))

    username = node_name
    if "@" in node_name:
        username = node_name.split("@", maxsplit=1)[0]
    elif "\\" in node_name:
        username = node_name.split("\\", maxsplit=1)[1]

    principal = f"{domain}\\{username}".strip("\\") if domain else username
    return principal, domain, username


def _mark_selected_node_owned() -> None:
    """Mark the current node selection as owned."""
    global selected_node_id
    if not selected_node_id or selected_node_id not in graph_engine.graph:
        ui.notify("Select a node first", color="warning")
        return

    graph_engine.graph.nodes[selected_node_id]["is_owned"] = True
    _set_owned_focus(selected_node_id)
    _refresh_chart(manual_path=[selected_node_id])
    _recalculate_live_path(notify_when_missing=True)
    if update_selected_node_panel_callback:
        update_selected_node_panel_callback(selected_node_id)
    _set_status(f"Marked owned: {selected_node_label or selected_node_id}")
    ui.notify("Node marked as owned", color="positive")


def _mark_node_owned(node_id: str) -> None:
    """Mark an arbitrary node as owned and trigger UI refreshes."""
    global selected_node_id, selected_node_label
    if not node_id or node_id not in graph_engine.graph:
        ui.notify("Node not found", color="warning")
        return

    graph_engine.graph.nodes[node_id]["is_owned"] = True
    selected_node_id = node_id
    selected_node_label = str(graph_engine.graph.nodes[node_id].get("name") or node_id)
    _set_owned_focus(node_id)
    _refresh_chart(manual_path=[node_id])
    _recalculate_live_path(notify_when_missing=True)
    if update_selected_node_panel_callback:
        update_selected_node_panel_callback(node_id)
    _set_status(f"Marked owned: {selected_node_label}")
    ui.notify("Node marked as owned", color="positive")


def _add_loot_for_selected_node(password: str, ntlm_hash: str) -> None:
    """Attach password/hash loot to the currently selected node and refresh UI."""
    global selected_node_id
    password = password.strip()
    ntlm_hash = ntlm_hash.strip().lower()

    if not selected_node_id or selected_node_id not in graph_engine.graph:
        ui.notify("Select a node first", color="warning")
        return
    if not password and not ntlm_hash:
        ui.notify("Provide a password or NTLM hash", color="warning")
        return

    principal, domain, username = _parse_identity_parts(selected_node_id)
    loot_manager.upsert_credential(
        principal=principal,
        username=username,
        domain=domain,
        password=password,
        ntlm_hash=ntlm_hash,
        source="node:quick-add",
    )

    if loot_refresh_callback:
        loot_refresh_callback()
    _refresh_chart(manual_path=[selected_node_id])
    _recalculate_live_path(notify_when_missing=True)
    if update_selected_node_panel_callback:
        update_selected_node_panel_callback(selected_node_id)
    _set_status(f"Added loot for: {selected_node_label or selected_node_id}")
    ui.notify("Loot added for selected node", color="positive")


def _on_graph_click(event: events.GenericEventArguments) -> None:
    """Generate exploit command when a node or edge is clicked."""
    global selected_node_id, selected_node_label
    args = event.args if isinstance(event.args, dict) else {}
    data_type = str(args.get("dataType", "")).casefold()
    data = args.get("data", {}) if isinstance(args.get("data"), dict) else {}

    # ECharts/NiceGUI payloads vary depending on where the user clicks (line vs label).
    # Infer edge/node intent when dataType is missing or inconsistent.
    if data_type not in {"edge", "node"}:
        if "source" in data and "target" in data:
            data_type = "edge"
        elif "id" in data:
            data_type = "node"

    if data_type == "edge":
        source_id = _resolve_node_reference(data.get("source", ""))
        target_id = _resolve_node_reference(data.get("target", ""))
        edge_type = _edge_relationship(
            source_id,
            target_id,
            fallback=str(data.get("edge_type") or data.get("value") or ""),
        )
        if not source_id or not target_id:
            return

        source_node = _node_context(source_id)
        target_node = _node_context(target_id)
        _set_path_inputs(source_node["name"], target_node["name"])
        exploit_cmd = command_oracle.get_exploit_command(edge_type, source_node, target_node)
        summary = f"{source_node['name']} -[{edge_type}]\u2192 {target_node['name']}"
        commands: list[tuple[str, str]] = [("Exploit Command", exploit_cmd)]

        # HTB special: append GetUserSPNs if either endpoint is kerberoastable.
        for nid, role_label in ((source_id, "Kerberoast source"), (target_id, "Kerberoast target")):
            node_attrs = graph_engine.graph.nodes[nid] if nid in graph_engine.graph else {}
            if node_attrs.get("is_kerberoastable"):
                kctx = _node_context(nid)
                commands.append((role_label, command_oracle.get_kerberoast_command(kctx)))

        _render_oracle_panel(summary, commands)

    elif data_type == "node":
        node_id = str(data.get("id", ""))
        node_attrs = graph_engine.graph.nodes[node_id] if node_id in graph_engine.graph else {}
        node_name = str(node_attrs.get("name", node_id))
        selected_node_id = node_id
        selected_node_label = node_name
        _set_path_inputs(source=node_name)
        if bool(node_attrs.get("is_owned")):
            _set_owned_focus(node_id)
        if update_selected_node_panel_callback:
            update_selected_node_panel_callback(node_id)
        node_ctx = _node_context(node_id)
        commands = []

        # Always update the notes panel when any node is clicked.
        if update_notes_panel_callback:
            update_notes_panel_callback(node_id, node_name)

        if node_attrs.get("is_kerberoastable"):
            kerb_cmd = command_oracle.get_kerberoast_command(node_ctx)
            commands.append(("\U0001f525 Kerberoast (HTB)", kerb_cmd))

        if node_attrs.get("is_asrep_roastable"):
            domain = node_ctx.get("domain") or "<DOMAIN>"
            target_sam = node_name.split("@")[0] if "@" in node_name else node_name
            asrep_cmd = (
                f"impacket-GetNPUsers {domain}/ "
                f"-usersfile users.txt -request -format hashcat -outputfile asrep.hashes\n"
                f"# Target: {target_sam}"
            )
            commands.append(("\U0001f480 AS-REP Roast", asrep_cmd))

        if not commands:
            return

        _render_oracle_panel(f"Node: {node_name}", commands)


def _upsert_loot(payload: dict[str, str]) -> None:
    """Persist credential rows from loot tab form."""
    principal = payload.get("principal", "").strip()
    if not principal:
        ui.notify("Principal is required", color="warning")
        return

    loot_manager.upsert_credential(
        principal=principal,
        username=payload.get("username", ""),
        domain=payload.get("domain", ""),
        password=payload.get("password", ""),
        ntlm_hash=payload.get("ntlm_hash", ""),
        kerberos_ticket=payload.get("kerberos_ticket", ""),
    )
    _recalculate_live_path(notify_when_missing=True)
    ui.notify("Credential saved", color="positive")


def _import_loot(raw_text: str) -> int:
    """Parse and store credentials from external tooling output."""
    imported = loot_manager.import_secrets_text(raw_text)
    if imported:
        _recalculate_live_path(notify_when_missing=True)
    return imported


async def handle_upload(event: events.UploadEventArguments) -> None:
    """Ingest uploaded SharpHound content and refresh the graph."""
    temp_path = await _persist_uploaded_file(event)

    try:
        if temp_path.suffix.lower() == ".zip":
            parsed = ingestor.unzip_and_parse(temp_path)
        elif temp_path.suffix.lower() == ".json":
            raw_json = json.loads(temp_path.read_text(encoding="utf-8"))
            if session_state.is_session_file(raw_json):
                graph_engine.clear()
                notes_store.clear()
                session_state.load_session(raw_json, graph_engine, loot_manager, notes_store)
                highlighted_manual_path.clear()
                _autofill_path_inputs()
                _refresh_chart()
                _recalculate_live_path(notify_when_missing=True)
                if loot_refresh_callback:
                    loot_refresh_callback()
                _set_status(
                    f"Session loaded: {graph_engine.graph.number_of_nodes()} nodes / "
                    f"{graph_engine.graph.number_of_edges()} edges"
                )
                ui.notify("Session restored", color="positive")
                return  # finally block still runs to clean up temp file
            dataset = ingestor.classify_filename(event.file.name)
            if dataset is None:
                raise ValueError(
                    "JSON upload must be a recognized SharpHound dataset file "
                    "(e.g. users/computers/groups/domains/ous/gpos/containers/ADCS exports) "
                    "or a NanoHound session file",
                )
            parsed = ingestor.empty_parsed()
            parsed[dataset] = ingestor.parse_json_file(temp_path, dataset=dataset)
        else:
            raise ValueError("Unsupported file type. Upload .zip or .json")

        for dataset in loaded_data:
            if parsed.get(dataset):
                loaded_data[dataset] = parsed[dataset]

        graph_engine.build_from_sharphound(loaded_data)
        highlighted_manual_path.clear()
        _autofill_path_inputs()
        _refresh_chart()
        _recalculate_live_path(notify_when_missing=True)
        _set_status(
            f"Loaded {graph_engine.graph.number_of_nodes()} nodes / "
            f"{graph_engine.graph.number_of_edges()} edges",
        )
        ui.notify("SharpHound data ingested", color="positive")
    except Exception as exc:  # noqa: BLE001
        ui.notify(f"Ingestion failed: {exc}", color="negative")
        _set_status("Ingestion failed")
    finally:
        temp_path.unlink(missing_ok=True)


async def _persist_uploaded_file(event: events.UploadEventArguments):
    """Persist an uploaded file from NiceGUI to a temporary path.

    Be flexible about event shapes: NiceGUI may provide `event.file`,
    `event.content`, or `event.data`. Try several access patterns.
    Return a pathlib.Path to the written temporary file.
    """
    import asyncio
    from pathlib import Path as _Path

    filename = None
    data = None

    # Try common attributes in order of likelihood
    if hasattr(event, "content") and event.content is not None:
        data = event.content
    # event.file may be an object with .read() or .name
    if data is None and hasattr(event, "file"):
        f = event.file
        # capture filename
        filename = getattr(f, "name", getattr(f, "filename", None))
        # attempt to read bytes (async or sync)
        if hasattr(f, "read"):
            try:
                maybe = f.read()
                if asyncio.iscoroutine(maybe):
                    data = await maybe
                else:
                    data = maybe
            except Exception:
                data = None

    # fallback to event.data
    if data is None and hasattr(event, "data"):
        maybe = event.data
        if asyncio.iscoroutine(maybe):
            data = await maybe
        else:
            data = maybe

    # fallback: try args/fileName variations
    if not filename:
        filename = getattr(event, "filename", None) or getattr(event, "file_name", None) or getattr(event, "name", None)

    if data is None:
        raise ValueError("No upload data found on event")

    # ensure bytes
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        try:
            data = bytes(data)
        except Exception:
            data = str(data).encode("utf-8")

    suffix = ""
    try:
        suffix = _Path(filename).suffix if filename else ""
    except Exception:
        suffix = ""

    tf = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="nh_upload_")
    try:
        tf.write(data)
        tf.flush()
        return _Path(tf.name)
    finally:
        tf.close()


def on_find_path(source: str, target: str) -> None:
    """Find and highlight the shortest attack path."""
    global highlighted_manual_path
    source = source.strip()
    target = target.strip()
    if not source or not target:
        ui.notify("Provide both source and target", color="warning")
        return

    path = graph_engine.find_shortest_path(source, target)
    if not path:
        ui.notify("No directed path found", color="warning")
        _set_status("No attack path found")
        _refresh_chart()
        return

    highlighted_manual_path = path
    _refresh_chart()

    edge_commands: list[tuple[str, str]] = []
    for source_id, target_id in zip(path, path[1:]):
        source_ctx = _node_context(source_id)
        target_ctx = _node_context(target_id)
        edge_type = _edge_relationship(source_id, target_id)
        edge_label = f"{source_ctx['name']} -[{edge_type}]-> {target_ctx['name']}"
        edge_commands.append(
            (
                edge_label,
                command_oracle.get_exploit_command(edge_type, source_ctx, target_ctx),
            )
        )

    if edge_commands:
        summary = (
            f"Path: {source} -> {target} ({len(path) - 1} hop"
            f"{'s' if len(path) - 1 != 1 else ''})"
        )
        _render_oracle_panel(summary, edge_commands)

    hops = max(len(path) - 1, 0)
    _set_status(f"Shortest path found: {hops} hops")
    ui.notify("Path highlighted", color="positive")


def _download_session() -> None:
    """Serialize the current workspace and trigger a browser download."""
    content = session_state.session_to_json(graph_engine, loot_manager, notes_store)
    filename = f"NanoHound_Session_{date.today().isoformat()}.json"
    ui.download(content, filename)


def build_ui() -> None:
    """Construct the NanoHound dark-mode interface."""
    global chart_placeholder, status_label, loot_refresh_callback
    global edge_selection_label, oracle_content_container, update_notes_panel_callback
    global update_selected_node_panel_callback, show_oracle_tab_callback
    global path_source_input, path_target_input

    ui.colors(
        primary="#27272a",
        secondary="#334155",
        accent="#dc2626",
        dark="#09090b",
        positive="#16a34a",
        negative="#dc2626",
        warning="#ca8a04",
        info="#0284c7",
    )
    ui.dark_mode().enable()

    ui.add_head_html(
        """
        <style>
            body { background: radial-gradient(circle at 10% 10%, #18181b 0%, #09090b 55%); }
            .nanohound-card { backdrop-filter: blur(2px); }
            .q-btn, .q-tab, .q-field__label, .q-field input, .q-field textarea, .q-field__native {
                color: #ffffff !important;
            }
            .q-btn .q-icon, .q-tab .q-icon {
                color: #ffffff !important;
            }
        </style>
        """,
    )

    with ui.header().classes("items-center justify-between bg-zinc-900 text-white"):
        ui.label("NanoHound").classes("text-xl font-semibold tracking-wide")
        ui.label("Lightweight AD Attack Path Mapping").classes("text-gray-100")
        ui.button(
            "Download Session",
            on_click=_download_session,
        ).props("flat icon=download").classes("text-white ml-auto")

    with ui.left_drawer(value=True).classes("bg-zinc-950 text-white w-72 p-4"):
        ui.label("Attack Shortcuts").classes("text-sm uppercase tracking-wider text-gray-100")
        ui.switch(
            "Auto-Calculate Path to DA",
            value=auto_calculate_path_to_da,
            on_change=lambda e: _set_auto_calculate_path(bool(e.value)),
        ).classes("w-full text-white")
        ui.separator().classes("bg-zinc-800")
        (
            ui.button(
                "Find Path to Domain Admins",
                on_click=lambda: ui.notify("Shortcut coming soon"),
            )
            .props("flat")
            .classes("w-full justify-start text-white")
        )
        (
            ui.button(
                "High-Value Principals",
                on_click=lambda: ui.notify("Shortcut coming soon"),
            )
            .props("flat")
            .classes("w-full justify-start text-white")
        )
        (
            ui.button(
                "Show All Kerberoastable",
                on_click=lambda: _set_filter("kerberoastable"),
            )
            .props("outline")
            .classes("w-full mt-2 border-orange-500 text-white")
        )
        (
            ui.button(
                "Show All AS-REP Roastable",
                on_click=lambda: _set_filter("asrep_roastable"),
            )
            .props("outline")
            .classes("w-full mt-2 border-red-600 text-white")
        )
        (
            ui.button(
                "Show Full Graph",
                on_click=lambda: _set_filter("all"),
            )
            .props("flat")
            .classes("w-full justify-start text-white")
        )
        (
            ui.button(
                "Show Owned Objects",
                on_click=lambda: _set_filter("owned"),
            )
            .props("outline")
            .classes("w-full mt-2 border-green-600 text-white")
        )
        (
            ui.button(
                "Clear Owned Focus",
                on_click=lambda: (_clear_owned_focus(), _refresh_chart(), _set_status("Owned focus cleared")),
            )
            .props("outline")
            .classes("w-full mt-2 border-cyan-700 text-white")
        )
        ui.separator().classes("bg-zinc-800 mt-2")
        (
            ui.button(
                "Sync Local Loot",
                on_click=_sync_local_loot,
            )
            .props("outline")
            .classes("w-full mt-2 border-yellow-600 text-white")
        )
        (
            ui.button(
                "Reset Graph",
                on_click=lambda: (
                    loaded_data.update(ingestor.empty_parsed()),
                    graph_engine.clear(),
                    highlighted_manual_path.clear(),
                    highlighted_live_path.clear(),
                    _clear_owned_focus(),
                    _set_filter("all"),
                    _refresh_chart(),
                    _set_status("Graph reset"),
                ),
            )
            .props("outline")
            .classes("w-full mt-2 border-zinc-700 text-white")
        )

    with ui.right_drawer(value=True).classes("bg-zinc-950 text-white w-96 p-4"):
        with ui.tabs().classes("w-full") as right_tabs:
            right_oracle_tab = ui.tab("Oracle", icon="bolt")
            right_node_info_tab = ui.tab("Node Info", icon="info")
            right_notes_tab = ui.tab("Notes", icon="description")

        def _show_oracle_tab() -> None:
            right_tabs.value = right_oracle_tab

        show_oracle_tab_callback = _show_oracle_tab

        with ui.tab_panels(right_tabs, value=right_oracle_tab).classes("w-full"):
            with ui.tab_panel(right_oracle_tab):
                ui.label("Command Oracle").classes(
                    "text-sm uppercase tracking-wider text-gray-100"
                )
                ui.separator().classes("bg-zinc-800")
                edge_selection_label = ui.label(
                    "Click an edge or kerberoastable node"
                ).classes("text-gray-100 text-xs italic pb-1")
                oracle_content_container = ui.column().classes("w-full gap-1")
            @ui.refreshable
            def node_info_panel() -> None:
                """Render the Node Info panel. Reads module-level `selected_node_id` and
                rebuilds the contents when invoked.
                """
                with ui.tab_panel(right_node_info_tab).classes("p-2"):
                    # ── name header ──────────────────────────────────────────
                    with ui.row().classes("w-full items-start gap-2 my-1"):
                        node_type_badge = (
                            ui.label("?")
                            .classes(
                                "text-xs font-bold px-1.5 py-0.5 rounded uppercase "
                                "tracking-widest shrink-0 mt-0.5"
                            )
                            .style("background:#374151;color:#d1d5db")
                        )
                        node_name_label = ui.label("No node selected").classes(
                            "text-white text-sm font-semibold break-all leading-snug"
                        )
                    node_sid_label = ui.label("").classes(
                        "text-xs text-gray-400 font-mono break-all leading-tight mb-1"
                    )
                    ui.separator().classes("bg-zinc-700 mb-1")

                    # ── collapsible section builder ──────────────────────────
                    def _make_info_section(title: str, icon: str):
                        exp = (
                            ui.expansion(title, icon=icon)
                            .props("dark dense")
                            .classes(
                                "w-full bg-zinc-800/30 rounded border border-zinc-700/60 mb-0.5"
                            )
                        )
                        with exp:
                            cont = ui.column().classes(
                                "w-full gap-0 px-2 pb-2 max-h-56 overflow-y-auto"
                            )
                        return exp, cont

                    section_obj,      obj_container      = _make_info_section("Object Information",      "info_outline")
                    section_memberof, memberof_container  = _make_info_section("Member Of",               "group")
                    section_members,  members_container   = _make_info_section("Members",                 "groups")
                    section_admin,    admin_container      = _make_info_section("Local Admin Privileges",  "shield")
                    section_exec,     exec_container       = _make_info_section("Execution Privileges",    "terminal")
                    section_inbound,  inbound_container    = _make_info_section("Inbound Object Control",  "login")
                    section_outbound, outbound_container   = _make_info_section("Outbound Object Control", "logout")

                    for _s in (
                        section_obj, section_memberof, section_members,
                        section_admin, section_exec, section_inbound, section_outbound,
                    ):
                        _s.set_visibility(False)

                    ui.separator().classes("bg-zinc-700 mt-1 mb-2")

                    # ── notes / loot inputs ──────────────────────────────────
                    selected_node_notes = (
                        ui.textarea(
                            "Notes",
                            placeholder="Add node-specific notes here...",
                        )
                        .props("autogrow outlined dark")
                        .classes("w-full")
                    )

                    def _save_selected_node_note(e: events.ValueChangeEventArguments) -> None:
                        if selected_node_id:
                            notes_store.set_note(selected_node_id, e.value or "")
                            _refresh_chart(manual_path=[selected_node_id])

                    selected_node_notes.on_value_change(_save_selected_node_note)

                    with ui.column().classes("w-full gap-2 mt-2"):
                        selected_node_pwd = ui.input("Password").props("type=password").classes("w-full")
                        selected_node_hash = ui.input("NTLM hash").classes("w-full")

                    def _quick_add_loot_from_details() -> None:
                        _add_loot_for_selected_node(
                            selected_node_pwd.value or "",
                            selected_node_hash.value or "",
                        )
                        selected_node_pwd.value = ""
                        selected_node_hash.value = ""

                    with ui.row().classes("w-full gap-2 mt-2"):
                        (
                            ui.button("Mark Selected Owned", on_click=_mark_selected_node_owned)
                            .props("outline icon=check_circle")
                            .classes("w-full border-green-600 text-white")
                        )
                        (
                            ui.button("Add Loot", on_click=_quick_add_loot_from_details)
                            .props("outline icon=key")
                            .classes("w-full border-yellow-600 text-white")
                        )

                    # ── helpers for update callback ──────────────────────────
                    def _fmt_ts(ts: Any) -> str:
                        if ts is None:
                            return "-"
                        try:
                            import datetime as _dt
                            v = int(ts)
                            if v <= 0:
                                return "-"
                            return _dt.datetime.fromtimestamp(v, tz=_dt.timezone.utc).strftime("%Y-%m-%d")
                        except Exception:
                            return str(ts)[:16]

                    _CONTROL_RELS = {
                        "Owns", "GenericAll", "CanWriteDacl", "WriteDacl",
                        "CanWriteOwner", "WriteOwner", "CanGenericWrite", "GenericWrite",
                        "AddKeyCredentialLink", "AllExtendedRights", "CanForceChangePassword",
                        "ForceChangePassword", "AddSelf", "CanAddMember", "AddMember",
                        "AddMembers", "AddAllowedToAct", "AllowedToAct", "AllowedToDelegate",
                        "DCSync", "DumpSMSAPassword", "DelegatedEnrollmentAgent", "Enroll",
                        "EnrollOnBehalfOf", "ExecuteDCOM", "EnterpriseCAFor", "ExtendedByPolicy",
                        "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC6a", "ADCSESC6b",
                        "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
                        "CoerceAndRelayNTLMToADCS", "CoerceAndRelayNTLMToLDAP",
                        "CoerceAndRelayNTLMToLDAPS", "CoerceAndRelayNTLMToSMB", "CoerceToTGT",
                    }

                    _TYPE_BADGE_STYLES: dict[str, str] = {
                        "USER":         "background:#1e3a5f;color:#93c5fd",
                        "COMPUTER":     "background:#14532d;color:#86efac",
                        "GROUP":        "background:#4a1d96;color:#c4b5fd",
                        "DOMAIN":       "background:#7f1d1d;color:#fca5a5",
                        "OU":           "background:#713f12;color:#fde68a",
                        "GPO":          "background:#431407;color:#fdba74",
                        "CONTAINER":    "background:#374151;color:#d1d5db",
                        "CERTTEMPLATE": "background:#1a2e1a;color:#a7f3d0",
                        "ENTERPRISECA": "background:#1c1a2e;color:#c4b5fd",
                    }

                    def _fill_section(
                        container: Any,
                        items: list,
                        fmt: Any = None,
                        limit: int = 60,
                    ) -> None:
                        container.clear()
                        with container:
                            for item in items[:limit]:
                                text = fmt(item) if fmt else str(item[1])
                                ui.label(text).classes(
                                    "text-xs text-gray-100 py-px leading-tight"
                                )
                            if len(items) > limit:
                                ui.label(f"\u2026and {len(items) - limit} more").classes(
                                    "text-xs text-gray-500 italic"
                                )

                    def _node_section_data(node_id: str) -> dict:
                        G = graph_engine.graph
                        memberof: list = []
                        local_admin: list = []
                        exec_privs: list = []
                        outbound_ctrl: list = []
                        members: list = []
                        inbound_ctrl: list = []
                        for nbr in G.successors(node_id):
                            rel = (G.get_edge_data(node_id, nbr) or {}).get("relationship", "")
                            name = G.nodes[nbr].get("name", nbr) if nbr in G.nodes else nbr
                            if rel == "MemberOf":
                                memberof.append((nbr, name))
                            elif rel == "AdminTo":
                                local_admin.append((nbr, name))
                            elif rel in ("CanRDP", "CanPSRemote"):
                                exec_privs.append((nbr, name, rel))
                            elif rel in _CONTROL_RELS:
                                outbound_ctrl.append((nbr, name, rel))
                        for nbr in G.predecessors(node_id):
                            rel = (G.get_edge_data(nbr, node_id) or {}).get("relationship", "")
                            name = G.nodes[nbr].get("name", nbr) if nbr in G.nodes else nbr
                            if rel == "MemberOf":
                                members.append((nbr, name))
                            elif rel in _CONTROL_RELS:
                                inbound_ctrl.append((nbr, name, rel))
                        return {
                            "memberof": memberof,
                            "members": members,
                            "local_admin": local_admin,
                            "exec_privs": exec_privs,
                            "outbound": outbound_ctrl,
                            "inbound": inbound_ctrl,
                        }

                    def _update_and_render(node_id: str) -> None:
                        # This function updates module state and triggers a redraw
                        # by calling the refreshable itself.
                        global selected_node_id
                        selected_node_id = node_id

                        # Build UI elements from current selected_node_id
                        if selected_node_id not in graph_engine.graph:
                            node_name_label.text = "No node selected"
                            node_type_badge.text = "?"
                            node_type_badge.style("background:#374151;color:#d1d5db")
                            node_sid_label.text = ""
                            for sec in (
                                section_obj, section_memberof, section_members,
                                section_admin, section_exec, section_inbound, section_outbound,
                            ):
                                sec.set_visibility(False)
                            selected_node_notes.value = ""
                            return

                        attrs = graph_engine.graph.nodes[selected_node_id]
                        node_name = str(attrs.get("name") or selected_node_id)
                        node_type = str(attrs.get("type", "entity")).upper()
                        props = attrs.get("raw_properties") or {}
                        principal, domain, username = _parse_identity_parts(selected_node_id)
                        owned = "yes" if bool(attrs.get("is_owned")) else "no"
                        cred = loot_manager.get_credential(selected_node_id) or loot_manager.get_credential(principal)
                        has_loot = "yes" if cred else "no"
                        has_note = "yes" if notes_store.has_note(selected_node_id) else "no"

                        node_name_label.text = node_name
                        node_type_badge.text = node_type
                        node_type_badge.style(
                            _TYPE_BADGE_STYLES.get(node_type, "background:#374151;color:#d1d5db")
                        )
                        node_sid_label.text = selected_node_id

                        # Object Information rows
                        obj_container.clear()
                        with obj_container:
                            info_rows = [
                                ("Domain",         domain or props.get("domain") or "-"),
                                ("Enabled",        str(props.get("enabled", "-")).lower()),
                                ("Admin Count",    "yes" if props.get("admincount") else "no"),
                                ("Kerberoastable", "yes" if attrs.get("is_kerberoastable") else "no"),
                                ("AS-REP Roast",   "yes" if attrs.get("is_asrep_roastable") else "no"),
                                ("Last Logon",     _fmt_ts(props.get("lastlogon") or props.get("lastlogontimestamp"))),
                                ("Pwd Last Set",   _fmt_ts(props.get("pwdlastset") or attrs.get("pwdlastset"))),
                                ("Owned",          owned),
                                ("Has Loot",       has_loot),
                                ("Has Notes",      has_note),
                                ("OS",             props.get("operatingsystem") or "-"),
                                ("Description",    props.get("description") or "-"),
                                ("Dist. Name",     props.get("distinguishedname") or "-"),
                                ("Func. Level",    str(props.get("functionallevel") or "-")),
                            ]
                            for key, val in info_rows:
                                if val and val != "-" and val != "no":
                                    with ui.row().classes(
                                        "w-full justify-between py-0.5 border-b border-zinc-700/40"
                                    ):
                                        ui.label(key).classes(
                                            "text-xs text-gray-400 shrink-0 w-28"
                                        )
                                        ui.label(str(val)).classes(
                                            "text-xs text-gray-100 text-right break-all"
                                        )
                        section_obj.set_visibility(True)

                        # Graph-derived sections
                        sd = _node_section_data(selected_node_id)

                        _fill_section(memberof_container, sd["memberof"])
                        section_memberof.text = f"Member Of ({len(sd['memberof'])})"
                        section_memberof.set_visibility(bool(sd["memberof"]))

                        _fill_section(members_container, sd["members"])
                        section_members.text = f"Members ({len(sd['members'])})"
                        section_members.set_visibility(bool(sd["members"]))

                        _fill_section(admin_container, sd["local_admin"]) 
                        section_admin.text = f"Local Admin ({len(sd['local_admin'])})"
                        section_admin.set_visibility(bool(sd["local_admin"]))

                        _fill_section(exec_container, sd["exec_privs"], fmt=lambda r: f"{r[1]} ({r[2]})")
                        section_exec.text = f"Exec Privs ({len(sd['exec_privs'])})"
                        section_exec.set_visibility(bool(sd["exec_privs"]))

                        _fill_section(inbound_container, sd["inbound"], fmt=lambda r: f"{r[1]} ({r[2]})")
                        section_inbound.text = f"Inbound Control ({len(sd['inbound'])})"
                        section_inbound.set_visibility(bool(sd["inbound"]))

                        _fill_section(outbound_container, sd["outbound"], fmt=lambda r: f"{r[1]} ({r[2]})")
                        section_outbound.text = f"Outbound Control ({len(sd['outbound'])})"
                        section_outbound.set_visibility(bool(sd["outbound"]))

                    # Wire external callback so other code can request a node update
                    def _update_selected_node_panel(node_id: str) -> None:
                        _update_and_render(node_id)

                    # Expose the updater to the rest of the module
                    globals()["update_selected_node_panel_callback"] = _update_selected_node_panel

            # Ensure the panel is rendered once at startup
            node_info_panel()

            # Notes tab placeholder
            with ui.tab_panel(right_notes_tab):
                # create_notes_panel returns an `update_notes_panel(sid, node_label)` callback
                globals()["update_notes_panel_callback"] = create_notes_panel(
                    notes_store.get_note, notes_store.set_note
                )