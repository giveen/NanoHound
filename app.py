"""NanoHound entry point and NiceGUI layout."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable, Iterable
from datetime import date
from pathlib import Path
from typing import Any

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


def _build_chart_options(path: list[str] | None = None, filter_mode: str | None = None) -> dict[str, Any]:
    """Create ECharts graph options from the in-memory NetworkX graph."""
    max_nodes = 3000
    selected_filter = filter_mode or active_filter
    included = _resolve_filtered_nodes(selected_filter)
    graph_nodes = [
        (node_id, attrs)
        for node_id, attrs in graph_engine.graph.nodes(data=True)
        if node_id in included
    ][:max_nodes]
    included = {node_id for node_id, _ in graph_nodes}
    highlighted_nodes = set(path or [])
    highlighted_edges = set(zip(path or [], (path or [])[1:]))

    nodes, links = _graph_to_echarts_data(
        graph_nodes=graph_nodes,
        included_nodes=included,
        highlighted_nodes=highlighted_nodes,
        highlighted_edges=highlighted_edges,
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
                "label": {"show": True, "color": "#e2e8f0", "fontSize": 10},
                "edgeLabel": {
                    "show": True,
                    "color": "#cbd5e1",
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
    highlighted_edges: set[tuple[str, str]],
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
        is_path_edge = (source, target) in highlighted_edges
        links.append(
            {
                "source": source,
                "target": target,
                "value": edge_label,
                "edge_type": edge_label,
                "label": {"show": True, "formatter": edge_label, "color": "#cbd5e1"},
                "lineStyle": {
                    "color": "#ef4444" if is_path_edge else "#334155",
                    "width": 2 if is_path_edge else 1,
                    "opacity": 0.95,
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

    return all_nodes


def _refresh_chart(path: list[str] | None = None) -> None:
    if chart_placeholder is None:
        return

    chart_placeholder.run_chart_method(
        "setOption", _build_chart_options(path, filter_mode=active_filter)
    )


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
    _set_status("Filter cleared")


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
                "text-xs uppercase tracking-wider text-slate-400 mt-3"
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
                .classes("text-red-400 self-end")
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


def _on_graph_click(event: events.GenericEventArguments) -> None:
    """Generate exploit command when a node or edge is clicked."""
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
    ui.notify("Credential saved", color="positive")


def _import_loot(raw_text: str) -> int:
    """Parse and store credentials from external tooling output."""
    return loot_manager.import_secrets_text(raw_text)


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
                _refresh_chart()
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
        _refresh_chart()
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

    _refresh_chart(path)
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

    with ui.header().classes("items-center justify-between bg-zinc-900 text-slate-100"):
        ui.label("NanoHound").classes("text-xl font-semibold tracking-wide")
        ui.label("Lightweight AD Attack Path Mapping").classes("text-slate-400")
        ui.button(
            "Download Session",
            on_click=_download_session,
        ).props("flat icon=download").classes("text-slate-300 ml-auto")

    with ui.left_drawer(value=True).classes("bg-zinc-950 text-slate-200 w-72 p-4"):
        ui.label("Attack Shortcuts").classes("text-sm uppercase tracking-wider text-slate-400")
        ui.separator().classes("bg-zinc-800")
        (
            ui.button(
                "Find Path to Domain Admins",
                on_click=lambda: ui.notify("Shortcut coming soon"),
            )
            .props("flat")
            .classes("w-full justify-start text-slate-200")
        )
        (
            ui.button(
                "High-Value Principals",
                on_click=lambda: ui.notify("Shortcut coming soon"),
            )
            .props("flat")
            .classes("w-full justify-start text-slate-200")
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
            .classes("w-full justify-start text-slate-200")
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
                    _set_filter("all"),
                    _refresh_chart(),
                    _set_status("Graph reset"),
                ),
            )
            .props("outline")
            .classes("w-full mt-2 border-zinc-700 text-slate-200")
        )

    with ui.right_drawer(value=True).classes("bg-zinc-950 text-slate-200 w-96 p-4"):
        with ui.tabs().classes("w-full") as right_tabs:
            right_oracle_tab = ui.tab("Oracle", icon="bolt")
            right_notes_tab = ui.tab("Notes", icon="description")
        with ui.tab_panels(right_tabs, value=right_oracle_tab).classes("w-full"):
            with ui.tab_panel(right_oracle_tab):
                ui.label("Command Oracle").classes(
                    "text-sm uppercase tracking-wider text-slate-400"
                )
                ui.separator().classes("bg-zinc-800")
                edge_selection_label = ui.label(
                    "Click an edge or kerberoastable node"
                ).classes("text-slate-400 text-xs italic pb-1")
                oracle_content_container = ui.column().classes("w-full gap-1")
            with ui.tab_panel(right_notes_tab):
                update_notes_panel_callback = create_notes_panel(
                    get_note=notes_store.get_note,
                    set_note=notes_store.set_note,
                )

    with ui.column().classes("w-full p-6 gap-4"):
        with ui.card().classes("w-full bg-zinc-900/80 border border-zinc-800 nanohound-card"):
            status_label = ui.label("Awaiting SharpHound upload...").classes("text-slate-300")
            create_upload_dropzone(handle_upload)
            create_search_bar(on_find_path)

        with ui.tabs().classes("w-full") as tabs:
            graph_tab = ui.tab("Graph View")
            loot_tab = ui.tab("Loot Table")

        with ui.tab_panels(tabs, value=graph_tab).classes("w-full"):
            with ui.tab_panel(graph_tab):
                with ui.card().classes("w-full grow min-h-[520px] bg-zinc-900/80 border border-zinc-800"):
                    ui.label("Graph View").classes("text-slate-300")
                    chart_placeholder = ui.echart(_build_chart_options()).classes("w-full h-[70vh]")
                    chart_placeholder.on("click", _on_graph_click)

            with ui.tab_panel(loot_tab):
                with ui.card().classes("w-full bg-zinc-900/80 border border-zinc-800"):
                    ui.label("Loot Table").classes("text-slate-300")
                    loot_refresh_callback = create_loot_table_tab(
                        on_upsert=_upsert_loot,
                        on_import=_import_loot,
                        get_rows=loot_manager.all_credentials,
                    )


build_ui()
ui.run(title="NanoHound", reload=False)
