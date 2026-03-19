"""NanoHound entry point and NiceGUI layout."""

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


ingestor = SharpHoundIngestor()
graph_engine = NanoGraphEngine()
loot_manager = LootManager()
notes_store = NotesStore()
command_oracle = CommandOracle(loot_manager)
loaded_data: dict[str, list[dict]] = {"users": [], "computers": [], "groups": []}
status_label = None
chart_placeholder = None
active_filter = "all"
loot_refresh_callback = None
edge_selection_label = None
oracle_content_container = None
selected_edge_command = ""
update_notes_panel_callback: Callable[[str, str], None] | None = None
update_selected_node_panel_callback: Callable[[str], None] | None = None
selected_node_id = ""
selected_node_label = ""
highlighted_manual_path: list[str] = []
highlighted_live_path: list[str] = []
auto_calculate_path_to_da = True
focused_owned_node_id = ""

NODE_TYPE_COLORS = {
    "user": "#22c55e",
    "computer": "#3b82f6",
    "group": "#eab308",
}


async def _persist_uploaded_file(event: events.UploadEventArguments) -> Path:
    """Store uploaded file content in a temporary file for parsing."""
    suffix = Path(event.file.name).suffix.lower() or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="nanohound_") as tmp:
        tmp.write(await event.file.read())
        return Path(tmp.name)


def _build_chart_options(
    manual_path: list[str] | None = None,
    live_path: list[str] | None = None,
    filter_mode: str | None = None,
) -> dict[str, Any]:
    """Create ECharts graph options from the in-memory NetworkX graph."""
    max_nodes = 3000
    selected_filter = filter_mode or active_filter
    included = _resolve_filtered_nodes(selected_filter)
    if focused_owned_node_id and focused_owned_node_id in graph_engine.graph:
        focus_nodes = _owned_focus_neighborhood(focused_owned_node_id)
        included = (included & focus_nodes) if selected_filter != "all" else focus_nodes
        included.add(focused_owned_node_id)

    graph_nodes = [
        (node_id, attrs)
        for node_id, attrs in graph_engine.graph.nodes(data=True)
        if node_id in included
    ][:max_nodes]
    included = {node_id for node_id, _ in graph_nodes}
    highlighted_nodes = set((manual_path or []) + (live_path or []))
    highlighted_manual_edges = set(zip(manual_path or [], (manual_path or [])[1:]))
    highlighted_live_edges = set(zip(live_path or [], (live_path or [])[1:]))

    nodes, links = _graph_to_echarts_data(
        graph_nodes=graph_nodes,
        included_nodes=included,
        highlighted_nodes=highlighted_nodes,
        highlighted_manual_edges=highlighted_manual_edges,
        highlighted_live_edges=highlighted_live_edges,
    )

    categories = [
        {"name": "User"},
        {"name": "Computer"},
        {"name": "Group"},
        {"name": "Entity"},
    ]

    return {
        "backgroundColor": "#09090b",
        "tooltip": {"trigger": "item"},
        "animationDuration": 300,
        "series": [
            {
                "type": "graph",
                "layout": "force",
                "roam": True,
                "draggable": True,
                "force": {"repulsion": 110, "edgeLength": 90},
                "categories": categories,
                "label": {"show": True, "color": "#ffffff", "fontSize": 10},
                "edgeLabel": {
                    "show": True,
                    "color": "#ffffff",
                    "fontSize": 9,
                    "formatter": "{c}",
                },
                "lineStyle": {"curveness": 0.1, "opacity": 0.95},
                "data": nodes,
                "links": links,
            }
        ],
    }


def _graph_to_echarts_data(
    graph_nodes: list[tuple[str, dict[str, Any]]],
    included_nodes: set[str],
    highlighted_nodes: set[str],
    highlighted_manual_edges: set[tuple[str, str]],
    highlighted_live_edges: set[tuple[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Convert NetworkX nodes and edges into ECharts graph JSON data."""

    nodes: list[dict[str, Any]] = []
    for node_id, attrs in graph_nodes:
        node_type = str(attrs.get("type", "entity")).lower()
        node_color = NODE_TYPE_COLORS.get(node_type, "#94a3b8")
        display_name = str(attrs.get("name", node_id))

        is_kerberoastable = bool(attrs.get("is_kerberoastable"))
        is_asrep_roastable = bool(attrs.get("is_asrep_roastable"))

        symbol = "circle"
        shadow_blur = 0
        shadow_color = "transparent"

        if is_kerberoastable:
            display_name = f"🔥 {display_name}"
            symbol = "diamond"
            shadow_blur = 18
            shadow_color = "rgba(251, 146, 60, 0.95)"

        if is_asrep_roastable:
            display_name = f"💀 {display_name}"
            symbol = "pin"
            shadow_blur = 24
            shadow_color = "rgba(239, 68, 68, 0.98)"

        if node_id in highlighted_nodes:
            node_color = "#ef4444"
            shadow_blur = max(shadow_blur, 20)
            shadow_color = "rgba(239, 68, 68, 0.98)"

        # Loot visual feedback: red border + key icon when credentials are available.
        # Try SID, full AD name, and bare SAMAccountName (covers secretsdump imports).
        _node_ad_name = str(attrs.get("name", ""))
        _node_sam = _node_ad_name.split("@")[0].split("\\")[-1]
        has_loot = (
            loot_manager.get_credential(node_id) is not None
            or loot_manager.get_credential(_node_ad_name) is not None
            or bool(_node_sam and loot_manager.get_credential(_node_sam) is not None)
        )
        border_color = "transparent"
        border_width = 0
        if has_loot:
            display_name = f"\U0001f511 {display_name}"
            border_color = "#ef4444"
            border_width = 3

        # Notes visual feedback: indigo border + document icon when notes exist.
        if notes_store.has_note(node_id):
            display_name = f"\U0001f4c4 {display_name}"
            if border_width == 0:  # don't override the loot red border
                border_color = "#6366f1"
                border_width = 2

        # Owned-object visual feedback: green border + check icon.
        if bool(attrs.get("is_owned")):
            display_name = f"\u2705 {display_name}"
            border_color = "#22c55e"
            border_width = max(border_width, 4)
            shadow_blur = max(shadow_blur, 20)
            shadow_color = "rgba(34, 197, 94, 0.80)"

        # Focused owned node gets extra emphasis.
        if node_id == focused_owned_node_id:
            border_color = "#06b6d4"
            border_width = max(border_width, 5)
            shadow_blur = max(shadow_blur, 28)
            shadow_color = "rgba(6, 182, 212, 0.95)"

        nodes.append(
            {
                "id": node_id,
                "name": display_name,
                "symbol": symbol,
                "symbolSize": 16 if node_id in highlighted_nodes else 10,
                "itemStyle": {
                    "color": node_color,
                    "shadowBlur": shadow_blur,
                    "shadowColor": shadow_color,
                    "borderColor": border_color,
                    "borderWidth": border_width,
                },
                "value": node_type,
                "category": node_type.capitalize(),
            }
        )

    links: list[dict[str, Any]] = []
    for source, target, attrs in graph_engine.graph.edges(data=True):
        if source not in included_nodes or target not in included_nodes:
            continue

        edge_label = str(attrs.get("raw_right") or attrs.get("relationship") or "")
        is_live_path_edge = (source, target) in highlighted_live_edges
        is_manual_path_edge = (source, target) in highlighted_manual_edges
        links.append(
            {
                "source": source,
                "target": target,
                "value": edge_label,
                "edge_type": edge_label,
                "label": {"show": True, "formatter": edge_label, "color": "#ffffff"},
                "lineStyle": {
                    "color": "#f43f5e" if is_live_path_edge else ("#ef4444" if is_manual_path_edge else "#334155"),
                    "width": 4 if is_live_path_edge else (2 if is_manual_path_edge else 1),
                    "opacity": 0.95,
                    "type": "dashed" if is_live_path_edge else "solid",
                },
                "effect": {
                    "show": is_live_path_edge,
                    "period": 4,
                    "trailLength": 0.25,
                    "symbolSize": 5,
                    "color": "#fb7185",
                },
            }
        )

    return nodes, links


def _member_of_neighbors(node_ids: Iterable[str]) -> set[str]:
    """Return directly connected group memberships for a set of principals."""
    scoped_nodes = set(node_ids)
    neighbors: set[str] = set(scoped_nodes)

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
        _build_chart_options(
            manual_path=active_manual_path,
            live_path=active_live_path,
            filter_mode=active_filter,
        ),
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
                .classes("text-red-200 self-end")
            )


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
    data_type = str(args.get("dataType", ""))
    data = args.get("data", {}) if isinstance(args.get("data"), dict) else {}

    if data_type == "edge":
        source_id = str(data.get("source", ""))
        target_id = str(data.get("target", ""))
        edge_type = str(data.get("edge_type") or data.get("value") or "Unknown")
        if not source_id or not target_id:
            return

        source_node = _node_context(source_id)
        target_node = _node_context(target_id)
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
                    "JSON upload must be users.json, computers.json, or groups.json "
                    "(or a NanoHound session file)",
                )
            parsed = {"users": [], "computers": [], "groups": []}
            parsed[dataset] = ingestor.parse_json_file(temp_path, dataset=dataset)
        else:
            raise ValueError("Unsupported file type. Upload .zip or .json")

        for dataset in loaded_data:
            if parsed.get(dataset):
                loaded_data[dataset] = parsed[dataset]

        graph_engine.build_from_sharphound(loaded_data)
        highlighted_manual_path.clear()
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
    global update_selected_node_panel_callback

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
            .classes("w-full mt-2 border-orange-500 text-orange-300")
        )
        (
            ui.button(
                "Show All AS-REP Roastable",
                on_click=lambda: _set_filter("asrep_roastable"),
            )
            .props("outline")
            .classes("w-full mt-2 border-red-600 text-red-300")
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
            .classes("w-full mt-2 border-green-600 text-green-300")
        )
        (
            ui.button(
                "Clear Owned Focus",
                on_click=lambda: (_clear_owned_focus(), _refresh_chart(), _set_status("Owned focus cleared")),
            )
            .props("outline")
            .classes("w-full mt-2 border-cyan-700 text-cyan-300")
        )
        ui.separator().classes("bg-zinc-800 mt-2")
        (
            ui.button(
                "Sync Local Loot",
                on_click=_sync_local_loot,
            )
            .props("outline")
            .classes("w-full mt-2 border-yellow-600 text-yellow-300")
        )
        (
            ui.button(
                "Reset Graph",
                on_click=lambda: (
                    loaded_data.update({"users": [], "computers": [], "groups": []}),
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
            right_notes_tab = ui.tab("Notes", icon="description")
        with ui.tab_panels(right_tabs, value=right_oracle_tab).classes("w-full"):
            with ui.tab_panel(right_oracle_tab):
                ui.label("Command Oracle").classes(
                    "text-sm uppercase tracking-wider text-gray-100"
                )
                ui.separator().classes("bg-zinc-800")
                edge_selection_label = ui.label(
                    "Click an edge or kerberoastable node"
                ).classes("text-gray-100 text-xs italic pb-1")
                with ui.card().classes("w-full bg-zinc-900/70 border border-zinc-800 p-2 mb-2"):
                    ui.label("Selected Node Details").classes(
                        "text-xs uppercase tracking-wider text-gray-100"
                    )
                    selected_node_title = ui.label("No node selected").classes(
                        "text-white text-sm"
                    )
                    selected_node_meta = ui.label("Click a graph node to inspect it").classes(
                        "text-gray-100 text-xs"
                    )

                    # Inline notes editor for the selected node.
                    selected_node_notes = (
                        ui.textarea(
                            "Notes",
                            placeholder="Add node-specific notes here...",
                        )
                        .props("autogrow outlined dark")
                        .classes("w-full mt-2")
                    )

                    def _save_selected_node_note(e: events.ValueChangeEventArguments) -> None:
                        if selected_node_id:
                            notes_store.set_note(selected_node_id, e.value or "")
                            _refresh_chart(manual_path=[selected_node_id])

                    selected_node_notes.on_value_change(_save_selected_node_note)

                    with ui.row().classes("w-full gap-2 mt-2"):
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
                            .classes("w-full border-green-600 text-green-300")
                        )
                        (
                            ui.button("Add Loot", on_click=_quick_add_loot_from_details)
                            .props("outline icon=key")
                            .classes("w-full border-yellow-600 text-yellow-300")
                        )

                    def _update_selected_node_panel(node_id: str) -> None:
                        if node_id not in graph_engine.graph:
                            selected_node_title.text = "No node selected"
                            selected_node_meta.text = "Click a graph node to inspect it"
                            selected_node_notes.value = ""
                            return

                        attrs = graph_engine.graph.nodes[node_id]
                        node_name = str(attrs.get("name") or node_id)
                        node_type = str(attrs.get("type", "entity")).upper()
                        owned = "yes" if bool(attrs.get("is_owned")) else "no"
                        has_note = "yes" if notes_store.has_note(node_id) else "no"
                        principal, domain, username = _parse_identity_parts(node_id)
                        cred = loot_manager.get_credential(node_id) or loot_manager.get_credential(principal)
                        has_loot = "yes" if cred else "no"
                        selected_node_title.text = node_name
                        selected_node_meta.text = (
                            f"SID: {node_id} | Type: {node_type} | Domain: {domain or '-'} | "
                            f"User: {username or '-'} | Owned: {owned} | Loot: {has_loot} | Notes: {has_note}"
                        )
                        selected_node_notes.value = notes_store.get_note(node_id)

                    update_selected_node_panel_callback = _update_selected_node_panel
                oracle_content_container = ui.column().classes("w-full gap-1")
            with ui.tab_panel(right_notes_tab):
                update_notes_panel_callback = create_notes_panel(
                    get_note=notes_store.get_note,
                    set_note=notes_store.set_note,
                )

    with ui.column().classes("w-full p-6 gap-4"):
        with ui.expansion("Control Panel", icon="tune").props("default-opened")\
            .classes("w-full bg-zinc-900/80 border border-zinc-800 rounded-lg nanohound-card"):
            with ui.card().classes("w-full bg-transparent border-0 shadow-none"):
                status_label = ui.label("Awaiting SharpHound upload...").classes("text-white")
                create_upload_dropzone(handle_upload)
                create_search_bar(on_find_path)
                with ui.row().classes("w-full items-end gap-2 mt-2"):
                    owned_query_input = ui.input("Find object (SID or Name)").classes("w-full")
                    (
                        ui.button(
                            "Find",
                            on_click=lambda: _find_object(owned_query_input.value or ""),
                        )
                        .props("outline")
                        .classes("border-cyan-600 text-cyan-300")
                    )
                    (
                        ui.button(
                            "Mark Owned",
                            on_click=lambda: _set_owned_by_query(owned_query_input.value or "", True),
                        )
                        .props("outline")
                        .classes("border-green-600 text-green-300")
                    )
                    (
                        ui.button(
                            "Unmark",
                            on_click=lambda: _set_owned_by_query(owned_query_input.value or "", False),
                        )
                        .props("outline")
                        .classes("border-zinc-600 text-white")
                    )
                suggestion_hint = ui.label("Start typing to see matching users/objects").classes(
                    "text-xs text-white"
                )
                suggestion_list = ui.column().classes("w-full gap-1")

                def _refresh_owned_search_suggestions(query: str) -> None:
                    suggestion_list.clear()
                    candidates = _autocomplete_candidates(query)
                    if not query.strip():
                        suggestion_hint.text = "Start typing to see matching users/objects"
                        return
                    if not candidates:
                        suggestion_hint.text = "No matches"
                        return

                    suggestion_hint.text = f"{len(candidates)} suggestion(s)"
                    with suggestion_list:
                        for node_id, label in candidates:
                            node_type = str(
                                graph_engine.graph.nodes.get(node_id, {}).get("type", "entity")
                            )

                            def _fill_and_focus(entry: str = label) -> None:
                                owned_query_input.value = entry
                                _find_object(entry)

                            (
                                ui.button(
                                    f"{label} [{node_type}]",
                                    on_click=_fill_and_focus,
                                )
                                .props("flat dense")
                                .classes(
                                    "w-full justify-start text-left text-white "
                                    "hover:bg-zinc-800 rounded"
                                )
                            )

                owned_query_input.on_value_change(
                    lambda e: _refresh_owned_search_suggestions(e.value or "")
                )

        with ui.tabs().classes("w-full") as tabs:
            graph_tab = ui.tab("Graph View")
            loot_tab = ui.tab("Loot Table")

        with ui.tab_panels(tabs, value=graph_tab).classes("w-full"):
            with ui.tab_panel(graph_tab):
                with ui.expansion("Graph Canvas", icon="hub").props("default-opened")\
                    .classes("w-full bg-zinc-900/80 border border-zinc-800 rounded-lg"):
                    with ui.card().classes("w-full bg-transparent border-0 shadow-none"):
                        ui.label("Graph View").classes("text-white")
                        chart_placeholder = ui.echart(_build_chart_options()).classes("w-full h-[70vh]")
                        chart_placeholder.on("click", _on_graph_click)

            with ui.tab_panel(loot_tab):
                with ui.card().classes("w-full bg-zinc-900/80 border border-zinc-800"):
                    ui.label("Loot Table").classes("text-white")
                    loot_refresh_callback = create_loot_table_tab(
                        on_upsert=_upsert_loot,
                        on_import=_import_loot,
                        get_rows=loot_manager.all_credentials,
                    )


build_ui()
ui.run(title="NanoHound", reload=False)
