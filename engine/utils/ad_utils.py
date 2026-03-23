from __future__ import annotations

from typing import Any
from dataclasses import dataclass
from typing import Optional
import logging

log = logging.getLogger("nanohound.utils.ad")


def sam_from_name(value: str, placeholder: str = "<TARGET_USER>") -> str:
    raw = str(value or "").strip()
    if not raw:
        return placeholder
    if "\\" in raw:
        raw = raw.split("\\", maxsplit=1)[1]
    if "@" in raw:
        raw = raw.split("@", maxsplit=1)[0]
    return raw or placeholder


def node_sam(node: Any, placeholder: str = "<TARGET_USER>") -> str:
    """Return a SAMAccountName-like short name from a NodeContext or dict."""
    for key in ("samaccountname", "SamAccountName", "name", "Name"):
        val = _lookup_node_value(node, key)
        if val:
            return sam_from_name(str(val), placeholder)
    return sam_from_name(_node_name(node), placeholder)


def node_dn(node: Any, placeholder: str = "<TARGET_DN>") -> str:
    val = _lookup_node_value(node, "distinguishedname", "DistinguishedName", "dn", "DN")
    if val:
        return str(val).strip()
    name_fallback = _node_name(node)
    if name_fallback:
        return name_fallback
    return placeholder


def node_hostname(node: Any, placeholder: str = "<TARGET_HOST>") -> str:
    for key in (
        "dnshostname",
        "dNSHostName",
        "dnsname",
        "DNSName",
        "hostname",
        "HostName",
        "computername",
        "ComputerName",
        "name",
        "Name",
    ):
        val = _lookup_node_value(node, key)
        if val:
            text = str(val).strip().rstrip("$")
            if text:
                return text

    raw_name = _node_name(node).strip().rstrip("$")
    if raw_name:
        return raw_name
    return placeholder


def node_sid(node: Any, placeholder: str = "<TARGET_SID>") -> str:
    candidate = str(getattr(node, "id", None) or (node.get("id") if isinstance(node, dict) else "") or "").strip()
    if candidate.upper().startswith("S-"):
        return candidate
    sid_value = _lookup_node_value(node, "objectsid", "ObjectSid", "sid", "SID")
    if sid_value:
        sid_text = str(sid_value).strip()
        if sid_text.upper().startswith("S-"):
            return sid_text
    return placeholder


def sid_domain_component(sid: str, placeholder: str = "<SOURCE_DOMAIN_SID>") -> str:
    cleaned = str(sid or "").strip()
    if cleaned.upper().startswith("S-") and "-" in cleaned:
        parts = cleaned.split("-")
        if len(parts) > 4:
            return "-".join(parts[:-1])
    return placeholder


def sid_rid(sid: str, placeholder: str = "<RID>") -> str:
    cleaned = str(sid or "").strip()
    if cleaned.upper().startswith("S-") and "-" in cleaned:
        return cleaned.rsplit("-", maxsplit=1)[-1]
    return placeholder


def _node_name(node: Any) -> str:
    if node is None:
        return ""
    if isinstance(node, dict):
        return str(node.get("name") or "").strip()
    return str(getattr(node, "name", "") or "").strip()


def _lookup_node_value(node: Any, *names: str):
    """Lookup node attributes in dict or object with case-insensitive keys."""
    if node is None:
        return None
    # If node is dict-like
    if isinstance(node, dict):
        normalized = {k.casefold(): v for k, v in node.items()}
        for name in names:
            v = normalized.get(name.casefold())
            if v not in (None, ""):
                return v
        return None
    # Fallback to attribute access
    for name in names:
        if hasattr(node, name):
            v = getattr(node, name)
            if v not in (None, ""):
                return v
        # try case-insensitive attr lookup in __dict__
        if hasattr(node, "__dict__"):
            for k, v in vars(node).items():
                if k.casefold() == name.casefold() and v not in (None, ""):
                    return v
    return None


def _list_node_values(node: Any, name: str) -> list:
    """Return a list of values for *name* on *node*.

    Handles dict/raw_properties lists and single values, and object attrs.
    Always returns a list (possibly empty).
    """
    if node is None:
        return []
    # dict-like lookup
    if isinstance(node, dict):
        normalized = {k.casefold(): v for k, v in node.items()}
        v = normalized.get(name.casefold())
        if v is None:
            # try raw_properties sub-dict
            raw = normalized.get("raw_properties") or {}
            if isinstance(raw, dict):
                v = raw.get(name) or raw.get(name.lower())
        if v is None:
            return []
        if isinstance(v, (list, tuple, set)):
            return list(v)
        return [v]

    # object attribute fallback
    v = _lookup_node_value(node, name)
    if v is None:
        # try raw_properties attr if present
        raw = getattr(node, "raw_properties", None)
        if isinstance(raw, dict):
            v = raw.get(name) or raw.get(name.lower())
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    return [v]


@dataclass
class NodeContext:
    id: str
    name: str
    node_type: str
    spn: str = ""
    domain: str = ""


def is_protected_user(graph_engine: Optional[Any], node: Any) -> bool:
    """Return True when the node is a member of Protected Users or marked restricted.

    This extracts and centralizes the legacy compatibility logic that used to live
    in the CommandOracle compatibility shims.
    """
    try:
        nid = getattr(node, "id", None) if not isinstance(node, dict) else node.get("id")
        if graph_engine and nid and hasattr(graph_engine, "graph"):
            attrs = graph_engine.graph.nodes.get(nid, {}) or {}
            if attrs.get("restricted") or attrs.get("is_protected") or attrs.get("protected"):
                return True

            for _, group_id, edata in graph_engine.graph.out_edges(nid, data=True):
                rel = str(edata.get("relationship") or edata.get("raw_right") or "").casefold()
                if rel != "memberof":
                    continue
                group_attrs = graph_engine.graph.nodes.get(group_id, {}) or {}
                raw = group_attrs.get("raw_properties") or {}
                sid = str(raw.get("objectSid") or raw.get("ObjectSid") or raw.get("sid") or raw.get("SID") or "")
                name = str(group_attrs.get("name", "")).casefold()
                if sid.upper().endswith("-525") or "protected users" in name or name == "protectedusers":
                    return True
    except Exception:
        log.exception("is_protected_user check failed")
    return False
