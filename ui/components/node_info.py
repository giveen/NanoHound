from __future__ import annotations

from typing import Any, Callable
from nicegui import ui, events


def create_node_info(
    tab_ref: Any,
    graph_engine: Any,
    loot_manager: Any,
    notes_store: Any,
    handlers: dict[str, Callable],
) -> Callable[[str], None]:
    """Create a Node Info `@ui.refreshable` attached to `tab_ref`.

    `handlers` must provide:
      - get_selected_node_id() -> str
      - set_selected_node_id(id: str) -> None
      - parse_identity_parts(node_id) -> tuple
      - mark_selected_node_owned()
      - add_loot_for_selected_node(password, ntlm_hash)
      - refresh_chart(manual_path=None, live_path=None)

    Returns: the refresh callable to invoke when a node should be shown.
    """

    @ui.refreshable
    def node_info_panel() -> None:
        with ui.tab_panel(tab_ref).classes("p-2"):
            # Header
            with ui.row().classes("w-full items-start gap-2 my-1"):
                node_type_badge = (
                    ui.label("?")
                    .classes("text-xs font-bold px-1.5 py-0.5 rounded uppercase tracking-widest shrink-0 mt-0.5")
                    .style("background:#374151;color:#d1d5db")
                )
                node_name_label = ui.label("No node selected").classes("text-white text-sm font-semibold break-all leading-snug")
            node_sid_label = ui.label("").classes("text-xs text-gray-400 font-mono break-all leading-tight mb-1")
            ui.separator().classes("bg-zinc-700 mb-1")

            def _make_info_section(title: str, icon: str):
                exp = ui.expansion(title, icon=icon).props("dark dense").classes(
                    "w-full bg-zinc-800/30 rounded border border-zinc-700/60 mb-0.5"
                )
                with exp:
                    cont = ui.column().classes("w-full gap-0 px-2 pb-2 max-h-56 overflow-y-auto")
                return exp, cont

            section_obj, obj_container = _make_info_section("Object Information", "info_outline")
            section_memberof, memberof_container = _make_info_section("Member Of", "group")
            section_members, members_container = _make_info_section("Members", "groups")
            section_admin, admin_container = _make_info_section("Local Admin Privileges", "shield")
            section_exec, exec_container = _make_info_section("Execution Privileges", "terminal")
            section_inbound, inbound_container = _make_info_section("Inbound Object Control", "login")
            section_outbound, outbound_container = _make_info_section("Outbound Object Control", "logout")

            for _s in (section_obj, section_memberof, section_members, section_admin, section_exec, section_inbound, section_outbound):
                _s.set_visibility(False)

            ui.separator().classes("bg-zinc-700 mt-1 mb-2")

            # Notes / quick loot
            selected_node_notes = ui.textarea("Notes", placeholder="Add node-specific notes here...").props("autogrow outlined dark").classes("w-full")

            def _save_selected_node_note(e: events.ValueChangeEventArguments) -> None:
                sid = handlers["get_selected_node_id"]()
                if sid:
                    notes_store.set_note(sid, e.value or "")
                    handlers["refresh_chart"](manual_path=[sid])

            selected_node_notes.on_value_change(_save_selected_node_note)

            with ui.column().classes("w-full gap-2 mt-2"):
                selected_node_pwd = ui.input("Password").props("type=password").classes("w-full")
                selected_node_hash = ui.input("NTLM hash").classes("w-full")

            def _quick_add_loot_from_details() -> None:
                handlers["add_loot_for_selected_node"](selected_node_pwd.value or "", selected_node_hash.value or "")
                selected_node_pwd.value = ""
                selected_node_hash.value = ""

            with ui.row().classes("w-full gap-2 mt-2"):
                ui.button("Mark Selected Owned", on_click=lambda: handlers["mark_selected_node_owned"]()).props("outline icon=check_circle").classes("w-full border-green-600 text-white")
                ui.button("Add Loot", on_click=lambda: _quick_add_loot_from_details()).props("outline icon=key").classes("w-full border-yellow-600 text-white")

            # Per-user explicit ownership action
            def _mark_current_as_owned() -> None:
                sid = handlers["get_selected_node_id"]()
                if sid:
                    # prefer explicit handler if provided
                    if "handle_mark_owned" in handlers:
                        try:
                            handlers["handle_mark_owned"](sid)
                        except Exception:
                            # fallback to mark_selected_node_owned
                            handlers["mark_selected_node_owned"]()
                    else:
                        handlers["mark_selected_node_owned"]()

            ui.button("Mark as Owned", on_click=lambda: _mark_current_as_owned()).classes("w-full bg-green-600 text-white mt-2")

            # Helpers and render logic
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

            CONTROL_RELS = {"Owns", "GenericAll", "CanWriteDacl", "WriteDacl", "CanWriteOwner", "WriteOwner", "CanGenericWrite", "GenericWrite"}

            TYPE_BADGE_STYLES = {
                "USER": "background:#1e3a5f;color:#93c5fd",
                "COMPUTER": "background:#14532d;color:#86efac",
                "GROUP": "background:#4a1d96;color:#c4b5fd",
            }

            def _fill_section(container: Any, items: list, fmt: Callable | None = None, limit: int = 60) -> None:
                container.clear()
                with container:
                    for item in items[:limit]:
                        text = fmt(item) if fmt else str(item[1])
                        ui.label(text).classes("text-xs text-gray-100 py-px leading-tight")
                    if len(items) > limit:
                        ui.label(f"\u2026and {len(items) - limit} more").classes("text-xs text-gray-500 italic")

            def _node_section_data(node_id: str) -> dict:
                G = graph_engine.graph
                memberof = []
                local_admin = []
                exec_privs = []
                outbound_ctrl = []
                members = []
                inbound_ctrl = []
                for nbr in G.successors(node_id):
                    rel = (G.get_edge_data(node_id, nbr) or {}).get("relationship", "")
                    name = G.nodes[nbr].get("name", nbr) if nbr in G.nodes else nbr
                    if rel == "MemberOf":
                        memberof.append((nbr, name))
                    elif rel == "AdminTo":
                        local_admin.append((nbr, name))
                    elif rel in ("CanRDP", "CanPSRemote"):
                        exec_privs.append((nbr, name, rel))
                    elif rel in CONTROL_RELS:
                        outbound_ctrl.append((nbr, name, rel))
                for nbr in G.predecessors(node_id):
                    rel = (G.get_edge_data(nbr, node_id) or {}).get("relationship", "")
                    name = G.nodes[nbr].get("name", nbr) if nbr in G.nodes else nbr
                    if rel == "MemberOf":
                        members.append((nbr, name))
                    elif rel in CONTROL_RELS:
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
                handlers["set_selected_node_id"](node_id)
                if node_id not in graph_engine.graph:
                    node_name_label.text = "No node selected"
                    node_type_badge.text = "?"
                    node_type_badge.style("background:#374151;color:#d1d5db")
                    node_sid_label.text = ""
                    for sec in (section_obj, section_memberof, section_members, section_admin, section_exec, section_inbound, section_outbound):
                        sec.set_visibility(False)
                    selected_node_notes.value = ""
                    return

                attrs = graph_engine.graph.nodes[node_id]
                node_name = str(attrs.get("name") or node_id)
                node_type = str(attrs.get("type", "entity")).upper()
                props = attrs.get("raw_properties") or {}
                principal, domain, username = handlers["parse_identity_parts"](node_id)
                owned = "yes" if bool(attrs.get("is_owned")) else "no"
                cred = loot_manager.get_credential(node_id) or loot_manager.get_credential(principal)
                has_loot = "yes" if cred else "no"
                has_note = "yes" if notes_store.has_note(node_id) else "no"

                node_name_label.text = node_name
                node_type_badge.text = node_type
                node_type_badge.style(TYPE_BADGE_STYLES.get(node_type, "background:#374151;color:#d1d5db"))
                node_sid_label.text = node_id

                obj_container.clear()
                with obj_container:
                    info_rows = [
                        ("Domain", domain or props.get("domain") or "-"),
                        ("Enabled", str(props.get("enabled", "-")).lower()),
                        ("Admin Count", "yes" if props.get("admincount") else "no"),
                        ("Kerberoastable", "yes" if attrs.get("is_kerberoastable") else "no"),
                        ("AS-REP Roast", "yes" if attrs.get("is_asrep_roastable") else "no"),
                        ("Last Logon", _fmt_ts(props.get("lastlogon") or props.get("lastlogontimestamp"))),
                        ("Pwd Last Set", _fmt_ts(props.get("pwdlastset") or attrs.get("pwdlastset"))),
                        ("Owned", owned),
                        ("Has Loot", has_loot),
                        ("Has Notes", has_note),
                        ("OS", props.get("operatingsystem") or "-"),
                        ("Description", props.get("description") or "-"),
                        ("Dist. Name", props.get("distinguishedname") or "-"),
                        ("Func. Level", str(props.get("functionallevel") or "-")),
                    ]
                    for key, val in info_rows:
                        if val and val != "-" and val != "no":
                            with ui.row().classes("w-full justify-between py-0.5 border-b border-zinc-700/40"):
                                ui.label(key).classes("text-xs text-gray-400 shrink-0 w-28")
                                ui.label(str(val)).classes("text-xs text-gray-100 text-right break-all")
                section_obj.set_visibility(True)

                sd = _node_section_data(node_id)
                _fill_section(memberof_container, sd["memberof"]) ; section_memberof.text = f"Member Of ({len(sd['memberof'])})" ; section_memberof.set_visibility(bool(sd["memberof"]))
                _fill_section(members_container, sd["members"]) ; section_members.text = f"Members ({len(sd['members'])})" ; section_members.set_visibility(bool(sd["members"]))
                _fill_section(admin_container, sd["local_admin"]) ; section_admin.text = f"Local Admin ({len(sd['local_admin'])})" ; section_admin.set_visibility(bool(sd["local_admin"]))
                _fill_section(exec_container, sd["exec_privs"], fmt=lambda r: f"{r[1]} ({r[2]})") ; section_exec.text = f"Exec Privs ({len(sd['exec_privs'])})" ; section_exec.set_visibility(bool(sd["exec_privs"]))
                _fill_section(inbound_container, sd["inbound"], fmt=lambda r: f"{r[1]} ({r[2]})") ; section_inbound.text = f"Inbound Control ({len(sd['inbound'])})" ; section_inbound.set_visibility(bool(sd["inbound"]))
                _fill_section(outbound_container, sd["outbound"], fmt=lambda r: f"{r[1]} ({r[2]})") ; section_outbound.text = f"Outbound Control ({len(sd['outbound'])})" ; section_outbound.set_visibility(bool(sd["outbound"]))

            # Expose updater
            return_node_update = node_info_panel.refresh
            return return_node_update

    # Render the panel once synchronously so the UI elements exist during
    # initial assembly. Returning the `refresh` method allows callers to
    # request updates later without invoking background tasks before the
    # NiceGUI event loop is running.
    try:
        node_info_panel()
    except Exception:
        # If rendering fails during import-time layout assembly, ignore
        # — callers can still use the returned refresh method later.
        pass

    return node_info_panel.refresh
