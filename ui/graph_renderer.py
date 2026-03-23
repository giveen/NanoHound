"""ECharts graph rendering helpers.

This module provides functions to convert a NetworkX graph into ECharts
options. It imports engine state from `engine.state` to access the
graph, loot manager and notes store.
"""
from __future__ import annotations

from typing import Any
from engine import state as est
import networkx as nx


def _member_of_neighbors(graph: nx.Graph, node_ids: set[str]) -> set[str]:
    scoped_nodes = set(node_ids)
    neighbors: set[str] = set(scoped_nodes)
    for source, target, attrs in graph.edges(data=True):
        relation = str(attrs.get("raw_right") or attrs.get("relationship") or "")
        if relation != "MemberOf":
            continue
        if source in scoped_nodes:
            neighbors.add(target)
        if target in scoped_nodes:
            neighbors.add(source)
    return neighbors


def _owned_focus_neighborhood(graph: nx.Graph, node_id: str, max_out_hops: int = 2) -> set[str]:
    if node_id not in graph:
        return set()
    try:
        outward = set(nx.single_source_shortest_path_length(graph, node_id, cutoff=max_out_hops).keys())
    except Exception:
        outward = {node_id}
    inbound = {src for src, dst in graph.in_edges(node_id) if dst == node_id}
    return outward | inbound | {node_id}

NODE_TYPE_COLORS = {
    "user": "#22c55e",
    "computer": "#3b82f6",
    "group": "#eab308",
    "entity": "#94a3b8",
}


def build_chart_options(
    manual_path: list[str] | None = None,
    live_path: list[str] | None = None,
    filter_mode: str | None = None,
    focused_owned_node_id: str | None = None,
    hidden_edge_types: set[str] | None = None,
    max_nodes: int = 3000,
) -> dict[str, Any]:
    """Create ECharts options from the shared engine.state graph.

    This closely mirrors the original `_graph_to_echarts_data` logic but
    is contained here so UI rendering code is modular.
    """
    # Prefer engine.state singletons when available; fall back to UI-level
    # singletons exposed by `ui._app_impl` (refactor compatibility).
    try:
        graph = est.graph_engine.graph
        loot_manager = est.loot_manager
        notes_store = est.notes_store
    except Exception:
        try:
            from ui import _app_impl as impl

            graph = impl.graph_engine.graph
            loot_manager = impl.loot_manager
            notes_store = impl.notes_store
        except Exception:
            # Last resort: empty graph
            import networkx as _nx

            graph = _nx.DiGraph()
            loot_manager = None
            notes_store = None

    selected_filter = filter_mode or "all"
    highlighted_nodes_set = set((manual_path or []) + (live_path or []))
    highlighted_manual_edges = set(zip(manual_path or [], (manual_path or [])[1:]))
    highlighted_live_edges = set(zip(live_path or [], (live_path or [])[1:]))

    # resolve visible nodes based on filter_mode
    def _resolve_filtered_nodes(filter_mode: str) -> set[str]:
        all_nodes = {nid for nid, _ in graph.nodes(data=True)}
        if filter_mode == "all":
            return all_nodes

        if filter_mode == "kerberoastable":
            principals = {
                nid
                for nid, attrs in graph.nodes(data=True)
                if attrs.get("type") == "user" and bool(attrs.get("is_kerberoastable"))
            }
            return _member_of_neighbors(graph, principals)

        if filter_mode == "asrep_roastable":
            principals = {
                nid
                for nid, attrs in graph.nodes(data=True)
                if attrs.get("type") == "user" and bool(attrs.get("is_asrep_roastable"))
            }
            return _member_of_neighbors(graph, principals)

        if filter_mode == "owned":
            principals = {
                nid
                for nid, attrs in graph.nodes(data=True)
                if bool(attrs.get("is_owned"))
            }
            return _member_of_neighbors(graph, principals)

        if filter_mode == "high_value":
            principals = {
                nid
                for nid, attrs in graph.nodes(data=True)
                if bool(attrs.get("high_value")) or bool(attrs.get("has_sensitive_desc"))
            }
            return _member_of_neighbors(graph, principals)

        return all_nodes

    # collect nodes to include
    included_nodes = _resolve_filtered_nodes(filter_mode or "all")
    if focused_owned_node_id and focused_owned_node_id in graph:
        focus_nodes = _owned_focus_neighborhood(graph, focused_owned_node_id)
        included_nodes = (included_nodes & focus_nodes) if (filter_mode or "all") != "all" else focus_nodes
        included_nodes.add(focused_owned_node_id)

    graph_nodes = [(nid, attrs) for nid, attrs in graph.nodes(data=True) if nid in included_nodes]
    graph_nodes = graph_nodes[:max_nodes]
    included = {nid for nid, _ in graph_nodes}

    nodes: list[dict[str, Any]] = []
    for node_id, attrs in graph_nodes:
        node_type = str(attrs.get("type", "entity")).lower()
        node_color = NODE_TYPE_COLORS.get(node_type, NODE_TYPE_COLORS["entity"])
        display_name = str(attrs.get("name", node_id))

        is_kerberoastable = bool(attrs.get("is_kerberoastable"))
        is_asrep_roastable = bool(attrs.get("is_asrep_roastable"))

        symbol = "circle"
        shadow_blur = 0
        shadow_color = "transparent"

        _props = attrs.get("raw_properties") or {}
        _enabled_val = attrs.get("enabled", _props.get("enabled", True))
        if isinstance(_enabled_val, str):
            enabled = _enabled_val.lower() not in ("false", "0", "no")
        else:
            enabled = bool(_enabled_val)

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

        if node_id in highlighted_nodes_set:
            node_color = "#ef4444"
            shadow_blur = max(shadow_blur, 20)
            shadow_color = "rgba(239, 68, 68, 0.98)"

        if not enabled:
            display_name = f"🚫 {display_name}"

        # Protected Users detection (keep original heuristic)
        is_restricted = False
        try:
            for s, t, ed in graph.out_edges(node_id, data=True):
                if str(ed.get("relationship") or ed.get("raw_right") or "") != "MemberOf":
                    continue
                group_attrs = graph.nodes.get(t, {}) or {}
                rawg = group_attrs.get("raw_properties") or {}
                sid = str(rawg.get("objectSid") or rawg.get("ObjectSid") or rawg.get("sid") or rawg.get("SID") or "")
                gname = str(group_attrs.get("name", "")).casefold()
                if sid.upper().endswith("-525") or "protected users" in gname or gname == "protectedusers":
                    is_restricted = True
                    break
        except Exception:
            is_restricted = False

        if is_restricted:
            display_name = f"🛡️ {display_name}"

        # Loot check
        _node_ad_name = str(attrs.get("name", ""))
        _node_sam = _node_ad_name.split("@")[0].split("\\")[-1]
        has_loot = (
            loot_manager.get_credential(node_id) is not None
            or loot_manager.get_credential(_node_ad_name) is not None
            or (bool(_node_sam) and loot_manager.get_credential(_node_sam) is not None)
        )
        border_color = "transparent"
        border_width = 0
        if has_loot:
            display_name = f"🔐 {display_name}"
            border_color = "#ef4444"
            border_width = 3

        # Notes
        try:
            if notes_store.has_note(node_id):
                display_name = f"📄 {display_name}"
                if border_width == 0:
                    border_color = "#6366f1"
                    border_width = 2
        except Exception:
            pass

        # Owned
        if bool(attrs.get("is_owned")):
            display_name = f"✅ {display_name}"
            border_color = "#22c55e"
            border_width = max(border_width, 4)
            shadow_blur = max(shadow_blur, 20)
            shadow_color = "rgba(34, 197, 94, 0.80)"

        # Silver ticket candidate
        if attrs.get("silver_ticket_candidate"):
            display_name = f"🎯 {display_name}"
            border_color = "#f59e0b"
            border_width = max(border_width, 3)

        if attrs.get("has_sensitive_desc") or attrs.get("high_value"):
            display_name = f"🗒️ {display_name}"
            border_color = border_color or "#f97316"
            border_width = max(border_width, 3)

        if attrs.get("stale_admin"):
            display_name = f"🕰️ {display_name}"
            border_color = "#ef4444"
            border_width = max(border_width, 5)
            shadow_blur = max(shadow_blur, 30)
            shadow_color = "rgba(239, 68, 68, 0.95)"

        if attrs.get("unconstraineddelegation") or attrs.get("unconstrainedDelegation"):
            display_name = f"🩵 {display_name}"
            border_color = "#06b6d4"
            border_width = max(border_width, 4)
            shadow_blur = max(shadow_blur, 28)
            shadow_color = "rgba(6, 182, 212, 0.85)"

        if attrs.get("relay_candidate") or attrs.get("smb_signing_disabled"):
            display_name = f"🔁 {display_name}"
            border_color = "#0ea5e9"
            border_width = max(border_width, 4)
            shadow_blur = max(shadow_blur, 20)
            shadow_color = "rgba(14, 165, 233, 0.85)"

        if attrs.get("trustedtoauth") or attrs.get("trustedToAuth"):
            display_name = f"⚠️ {display_name}"
            border_color = "#dc2626"
            border_width = max(border_width, 5)
            shadow_blur = max(shadow_blur, 30)
            shadow_color = "rgba(220, 38, 38, 0.9)"

        if focused_owned_node_id and node_id == focused_owned_node_id:
            border_color = "#06b6d4"
            border_width = max(border_width, 5)
            shadow_blur = max(shadow_blur, 28)
            shadow_color = "rgba(6, 182, 212, 0.95)"

        nodes.append(
            {
                "id": node_id,
                "name": display_name,
                "symbol": symbol,
                "symbolSize": 16 if node_id in highlighted_nodes_set else 10,
                "itemStyle": {
                    "color": node_color,
                    "shadowBlur": shadow_blur,
                    "shadowColor": shadow_color,
                    "borderColor": border_color,
                    "borderWidth": border_width,
                    **({"opacity": 0.3} if not enabled else {}),
                },
                "value": node_type,
                "category": node_type.capitalize(),
            }
        )

    links: list[dict[str, Any]] = []
    for source, target, attrs in graph.edges(data=True):
        if source not in included or target not in included:
            continue

        edge_label = str(attrs.get("raw_right") or attrs.get("relationship") or "")
        if hidden_edge_types and edge_label in hidden_edge_types:
            continue

        is_live_path_edge = (source, target) in highlighted_live_edges
        is_manual_path_edge = (source, target) in highlighted_manual_edges

        # network unreachable and tier violation logic preserved
        network_unreachable = bool(attrs.get("network_unreachable"))
        src_tier = graph.nodes.get(source, {}).get("tier")
        tgt_tier = graph.nodes.get(target, {}).get("tier")
        tier_violation = False
        try:
            if isinstance(src_tier, (int, float)) and isinstance(tgt_tier, (int, float)) and src_tier < tgt_tier:
                tier_violation = True
        except Exception:
            tier_violation = False

        line_style = {"curveness": 0.1, "opacity": 0.95}
        visual_style = attrs.get("visual_style")
        if visual_style == "dashed_gray":
            line_style = {"type": "dashed", "color": "#9ca3af", "opacity": 0.7}
        if network_unreachable:
            line_style = {"color": "#374151", "opacity": 0.25}
        if tier_violation:
            line_style = {"color": "#ef4444", "width": 2.5}

        links.append(
            {
                "source": source,
                "target": target,
                "label": {"show": True, "formatter": edge_label, "color": "#ffffff"},
                "lineStyle": line_style,
                "emphasis": {"lineStyle": {"width": 3}},
                "tooltip": {"show": True},
            }
        )

    node_count = len(nodes)
    large_mode = node_count > 500
    if large_mode:
        # reduce expensive visuals
        for n in nodes:
            try:
                n["itemStyle"]["shadowBlur"] = 0
                n["itemStyle"]["shadowColor"] = "transparent"
                n["symbolSize"] = 8
            except Exception:
                pass

    categories = [
        {"name": "User"},
        {"name": "Computer"},
        {"name": "Group"},
        {"name": "Entity"},
    ]

    legend = {"data": ["Forest Trust"], "textStyle": {"color": "#ffffff"}}

    if node_count > 500:
        force_cfg = {
            "repulsion": 600,
            "edgeLength": 70,
            "gravity": 0.06,
            "layoutAnimation": False,
            "initLayout": "force",
        }
        label_cfg = {"show": False}
    else:
        force_cfg = {
            "repulsion": 1200,
            "edgeLength": 90,
            "gravity": 0.08,
            "layoutAnimation": True,
            "initLayout": "force",
        }
        label_cfg = {"show": True, "color": "#ffffff", "fontSize": 10}

    return {
        "backgroundColor": "#09090b",
        "tooltip": {"trigger": "item"},
        "legend": legend,
        "series": [
            {
                "type": "graph",
                "layout": "force",
                "roam": True,
                "draggable": True,
                "force": force_cfg,
                "categories": categories,
                "label": label_cfg,
                "edgeLabel": {"show": True, "color": "#ffffff", "fontSize": 9, "formatter": "{c}"},
                "lineStyle": {"curveness": 0.1, "opacity": 0.95},
                "data": nodes,
                "links": links,
            }
        ],
    }
