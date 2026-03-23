"""UI layout entrypoints for NanoHound.

This module exposes a minimal `build_ui()` that assembles the application
layout and contains small layout helper builders. The heavy lifting lives
in `ui._app_impl`.
"""

from __future__ import annotations

from typing import Any, Callable
from pathlib import Path
from nicegui import ui, run
from . import _app_impl as _impl
from engine import state as est
import json
import gzip
import logging

log = logging.getLogger("nanohound.ui.layout")


def build_ui() -> None:
    """Assemble and register the UI. This module composes visual
    components and delegates state/handlers to `ui._app_impl`.
    """
    # Load component modules directly from the components/ directory to avoid
    # colliding with the top-level ui/components.py module.
    import importlib.util
    from pathlib import Path as _Path

    _components_dir = _Path(__file__).parent / "components"
    def _load_component_module(name: str):
        p = _components_dir / f"{name}.py"
        if not p.exists():
            raise ImportError(f"component {name} not found at {p}")
        spec = importlib.util.spec_from_file_location(f"{__package__}.components.{name}", str(p))
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        return mod

    comp_node_info = _load_component_module("node_info")
    comp_pathfinder = _load_component_module("pathfinder")

    impl = _impl
    from . import handlers as ui_handlers

    # Initialize UI theme
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

    # Header
    with ui.header().classes("items-center justify-between bg-zinc-900 text-white"):
        ui.label("NanoHound").classes("text-xl font-semibold tracking-wide")
        ui.label("Lightweight AD Attack Path Mapping").classes("text-gray-100")
        ui.button("Download Session", on_click=lambda: ui_handlers.download_session(None)).props("flat icon=download").classes("text-white ml-auto")

    # Main status / control panel
    # Create the main layout controls (status label) and expose the status
    # label to the implementation so `_set_status()` can update it.
    registry = create_main_layout()
    try:
        impl.status_label = registry.get("status_label")
    except Exception:
        pass
    # Left drawer (controls)
    with ui.left_drawer(value=True).classes("bg-zinc-950 text-white w-72 p-4"):
        # Upload control for SharpHound zip
        import ui.handlers as core_handlers
        ui.upload(
            label="Upload SharpHound ZIP/JSON",
            auto_upload=True,
            multiple=False,
            on_upload=lambda e: core_handlers.handle_upload(None, e),
        ).props("accept=.zip,.json").classes("w-full bg-zinc-900 text-white border border-zinc-700 rounded-xl p-2 mb-2")

        ui.label("Attack Shortcuts").classes("text-sm uppercase tracking-wider text-gray-100")
        ui.switch(
            "Auto-Calculate Path to DA",
            value=impl.auto_calculate_path_to_da,
            on_change=lambda e: ui_handlers.set_auto_calculate_path(None, bool(e.value)),
        ).classes("w-full text-white")
        ui.separator().classes("bg-zinc-800")
        (
            ui.button("Find Path to Domain Admins", on_click=lambda: impl._recalculate_live_path(notify_when_missing=True))
            .props("flat")
            .classes("w-full justify-start text-white")
        )
        ui.separator().classes("bg-zinc-800 mt-2")

        # Pathfinder component
        source_input, target_input, _ = comp_pathfinder.create_pathfinder(lambda s, t: ui_handlers.on_find_path(None, s, t))
        impl.path_source_input = source_input
        impl.path_target_input = target_input

        ui.separator().classes("bg-zinc-800 mt-2")
        ui.button("Sync Local Loot", on_click=lambda: ui_handlers.sync_local_loot(None)).props("outline").classes("w-full mt-2 border-yellow-600 text-white")

    # Main chart area
    comp_graph = _load_component_module("graph")
    with ui.column().classes("w-full p-4"):
        comp_graph.create_graph_area(impl)

    # Right drawer (oracle / node info / notes)
    with ui.right_drawer(value=True).classes("bg-zinc-950 text-white w-96 p-4"):
        with ui.tabs().classes("w-full") as right_tabs:
            right_oracle_tab = ui.tab("Oracle", icon="bolt")
            right_node_info_tab = ui.tab("Node Info", icon="info")
            right_notes_tab = ui.tab("Notes", icon="description")

        def _show_oracle_tab() -> None:
            right_tabs.value = right_oracle_tab

        impl.show_oracle_tab_callback = _show_oracle_tab

        with ui.tab_panels(right_tabs, value=right_oracle_tab).classes("w-full"):
            with ui.tab_panel(right_oracle_tab):
                ui.label("Command Oracle").classes("text-sm uppercase tracking-wider text-gray-100")
                ui.separator().classes("bg-zinc-800")
                impl.edge_selection_label = ui.label("Click an edge or kerberoastable node").classes("text-gray-100 text-xs italic pb-1")
                impl.oracle_content_container = ui.column().classes("w-full gap-1")

            # Node Info component (moved to components/node_info.py)
            update_node = comp_node_info.create_node_info(
                right_node_info_tab,
                impl.graph_engine,
                impl.loot_manager,
                None,  # notes handled via handlers, not direct store access
                {
                    "get_selected_node_id": lambda: impl.selected_node_id,
                    "set_selected_node_id": lambda v: setattr(impl, "selected_node_id", v),
                    "parse_identity_parts": impl._parse_identity_parts,
                    "mark_selected_node_owned": lambda: ui_handlers.mark_selected_node_owned(None),
                    "add_loot_for_selected_node": lambda pwd, ntlm: ui_handlers.add_loot_for_selected_node(None, pwd, ntlm),
                    "handle_mark_owned": lambda sid: ui_handlers.handle_mark_owned(None, sid),
                    "get_note": lambda sid: ui_handlers.get_note(None, sid),
                    "has_note": lambda sid: ui_handlers.has_note(None, sid),
                    "set_note": lambda sid, txt: ui_handlers.set_note(None, sid, txt),
                    "refresh_chart": impl._refresh_chart,
                },
            )

            # Expose updater callbacks for handlers to call
            impl.update_selected_node_panel_callback = update_node

            # Notes tab: reuse existing top-level component module (ui/components.py)
            from . import components as core_components
            with ui.tab_panel(right_notes_tab):
                impl.update_notes_panel_callback = core_components.create_notes_panel(
                    impl.notes_store.get_note, impl.notes_store.set_note
                )

    # Do not call refreshable `refresh()` here — NiceGUI background tasks
    # require an active event loop. The node_info component rendered the
    # panel synchronously during creation, so no further action is required.

    # --- In-server ingestion endpoint -------------------------------------------------
    # Provide a small HTTP API so test harnesses can POST a SharpHound ZIP/JSON
    # directly to the running server and have it ingested inside the NiceGUI
    # context. This ensures UI widgets (chart, path inputs) are updated.
    try:
        from starlette.requests import Request
        from nicegui import app as ng_app
        import tempfile
        import pathlib

        impl = _impl

        from starlette.responses import JSONResponse

        async def _api_ingest_handler(request: Request) -> JSONResponse:
            # Read multipart form manually to avoid Pydantic forward-ref issues
            form = await request.form()
            upload = form.get("file") or form.get("upload")
            if upload is None:
                return {"status": "error", "error": "no file provided"}
            data = await upload.read()
            tf = tempfile.NamedTemporaryFile(delete=False, suffix="" , prefix="nh_upload_")
            try:
                tf.write(data)
                tf.flush()
            finally:
                tf.close()

            temp_path = pathlib.Path(tf.name)
            try:
                if temp_path.suffix.lower() == ".zip":
                    parsed = impl.ingestor.unzip_and_parse(temp_path)
                elif temp_path.suffix.lower() == ".json":
                    parsed = impl.ingestor.parse_json_file(temp_path)
                else:
                    # Try to guess by content
                    parsed = impl.ingestor.unzip_and_parse(temp_path)

                for dataset in impl.loaded_data:
                    if parsed.get(dataset):
                        impl.loaded_data[dataset] = parsed[dataset]

                impl.graph_engine.build_from_sharphound(impl.loaded_data)
                impl.highlighted_manual_path.clear()
                impl._autofill_path_inputs()
                impl._refresh_chart()
                impl._recalculate_live_path(notify_when_missing=True)
                if impl.loot_refresh_callback:
                    impl.loot_refresh_callback()
                impl._set_status(
                    f"Loaded {impl.graph_engine.graph.number_of_nodes()} nodes / {impl.graph_engine.graph.number_of_edges()} edges"
                )
                return JSONResponse(
                    {
                        "status": "ok",
                        "nodes": impl.graph_engine.graph.number_of_nodes(),
                        "edges": impl.graph_engine.graph.number_of_edges(),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                return JSONResponse({"status": "error", "error": str(exc)}, status_code=500)
            finally:
                try:
                    temp_path.unlink(missing_ok=True)
                except Exception:
                    pass
        # Register route explicitly using the NiceGUI app helper to avoid
        # decorator signature issues with UploadFile / Pydantic.
        try:
            ng_app.add_route("/api/ingest", _api_ingest_handler, methods=["POST"])  # type: ignore[arg-type]
        except Exception:
            # Non-fatal if route registration fails in some envs.
            pass
    except Exception:
        # Best-effort: if FastAPI or NiceGUI app binding isn't available,
        # skip adding the route (non-fatal).
        pass


__all__ = ["build_ui"]


def create_main_layout() -> dict[str, Any]:
    """Create the main app layout and return a small registry of widgets.

    The function keeps layout concerns separated from event handlers.
    """
    registry: dict[str, Any] = {}

    with ui.column().classes("w-full p-6 gap-4"):
        with ui.expansion("Control Panel", icon="tune").props("default-opened")\
            .classes("w-full bg-zinc-900/80 border border-zinc-800 rounded-lg nanohound-card"):
            with ui.card().classes("w-full bg-transparent border-0 shadow-none"):
                status_label = ui.label("Awaiting SharpHound upload...").classes("text-white")
                registry["status_label"] = status_label

    return registry


def create_session_browser(load_callback: Callable[[str], None], delete_callback: Callable[[str], bool] | None = None) -> Callable[[], None]:
    """Create a Workspace History card and return an async update function.

    `load_callback(path)` will be called when the user clicks Load for a session.
    """
    container = ui.column().classes("w-full gap-2")

    card = ui.card().classes("w-full bg-zinc-900/80 border border-zinc-800 rounded-lg p-4")
    with card:
        ui.label("Workspace History").classes("text-white")
        list_box = ui.column().classes("w-full gap-2")

    async def update_session_list() -> None:
        list_box.clear()
        try:
            sessions_dir = Path(est.SESSIONS_DIR)
            if not sessions_dir.exists():
                return
            files = sorted(sessions_dir.glob("*.hound"), key=lambda p: p.stat().st_mtime, reverse=True)
            for p in files:
                try:
                    b = await run.io_bound(p.read_bytes)
                    # attempt to decompress
                    try:
                        raw = gzip.decompress(b)
                    except Exception:
                        raw = b
                    data = json.loads(raw.decode("utf-8"))
                    summary = data.get("summary") or {}
                    created = data.get("created") or "?"
                except Exception:
                    log.exception("Failed to inspect session %s", str(p))
                    summary = {}
                    created = "?"

                with list_box:
                    with ui.row().classes("w-full items-center justify-between"):
                        ui.label(f"{p.name}").classes("text-sm text-white")
                        ui.label(f"{summary.get('nodes', '?')} nodes • {summary.get('edges', '?')} edges • owned: {summary.get('owned', '?')} • {created}").classes("text-xs text-gray-400")

                        def _on_load(path=str(p)):
                            try:
                                load_callback(path)
                            except Exception:
                                log.exception("Session load callback failed for %s", path)

                        ui.button("Load", on_click=lambda e, path=str(p): _on_load(path)).classes("bg-amber-600 text-white")
                        if delete_callback:
                            def _on_delete(path=str(p)):
                                try:
                                    ok = delete_callback(path)
                                    if ok:
                                        # refresh list asynchronously
                                        from nicegui import ui as _ui

                                        _ui.timer(0, update_session_list, active=False).active = True
                                except Exception:
                                    log.exception("Session delete callback failed for %s", path)

                            ui.button('🗑️', on_click=lambda e, path=str(p): _on_delete(path)).props("flat").classes("text-red-500")
        except Exception:
            log.exception("Failed to update session list")

    return update_session_list


def create_mission_progress_card() -> Callable[[], None]:
    """Create a Mission Progress card and return an async update function.

    The returned callable updates displayed counts (owned, pwnage, sessions).
    """
    card = ui.card().classes("w-full bg-zinc-900/80 border border-zinc-800 rounded-lg p-4")
    with card:
        ui.label("Mission Progress").classes("text-white")
        stats_row = ui.row().classes("w-full items-center gap-4")
        owned_label = ui.label("Owned: 0").classes("text-white")
        pwned_label = ui.label("Pwnage: 0").classes("text-white")
        sessions_label = ui.label("Sessions: 0").classes("text-white")

    async def _update() -> None:
        try:
            summary = {}
            if hasattr(est, "get_summary"):
                try:
                    summary = est.get_summary() or {}
                except Exception:
                    log.exception("get_summary() failed")

            nodes = int(summary.get("nodes", 0) or 0)
            owned = int(summary.get("owned", 0) or 0)

            sessions = 0
            try:
                sessions_dir = Path(est.SESSIONS_DIR)
                if sessions_dir.exists():
                    sessions = len(list(sessions_dir.glob("*.hound")))
            except Exception:
                log.exception("counting sessions failed")

            owned_label.set_text(f"Owned: {owned}")
            pwned_label.set_text(f"Pwnage: {max(0, nodes - owned)}")
            sessions_label.set_text(f"Sessions: {sessions}")
        except Exception:
            log.exception("Failed to update mission progress")

    return _update
