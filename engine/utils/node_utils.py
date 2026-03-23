from __future__ import annotations

from typing import Any, List
from engine.utils import ad_utils
import logging

log = logging.getLogger("nanohound.utils.node")


def infer_domain(source_node: Any, target_node: Any) -> str:
    for candidate in (getattr(source_node, "domain", None) if source_node else None, getattr(target_node, "domain", None) if target_node else None):
        if candidate:
            return candidate

    for candidate in (ad_utils._node_name(source_node), ad_utils._node_name(target_node)):
        if candidate and "@" in candidate:
            return candidate.split("@", maxsplit=1)[1].upper()

    for candidate in (ad_utils._node_name(source_node), ad_utils._node_name(target_node)):
        if candidate and "." in candidate:
            return ".".join(candidate.split(".")[1:]).upper()

    return "<DOMAIN>"


def infer_username(source_node: Any, loot_manager: Any | None = None) -> str:
    # Primary lookup: try loot_manager credentials if available
    try:
        if loot_manager:
            cred = loot_manager.get_credential(getattr(source_node, "id", None)) or loot_manager.get_credential(ad_utils._node_name(source_node))
            if cred and getattr(cred, "username", None):
                return cred.username
    except Exception:
        log.debug("Loot lookup failed in infer_username", exc_info=True)

    name = ad_utils._node_name(source_node)
    if "@" in name:
        return name.split("@", maxsplit=1)[0]
    return name or "<SOURCE_USER>"


def auth_flags(loot_manager: Any, source_node: Any) -> str:
    try:
        if not loot_manager:
            return ""
        flags = loot_manager.build_auth_flags(getattr(source_node, "id", None))
        if flags:
            return flags
        return loot_manager.build_auth_flags(ad_utils._node_name(source_node))
    except Exception:
        log.debug("build_auth_flags failed", exc_info=True)
        return ""


def get_credential_record(loot_manager: Any, graph_engine: Any, node: Any):
    # Primary lookup
    try:
        if loot_manager:
            cred = loot_manager.get_credential(getattr(node, "id", None)) or loot_manager.get_credential(ad_utils._node_name(node))
            if cred:
                return cred

        # Fallback: check for GPO-attached loot via graph_engine (best-effort)
        if graph_engine and getattr(node, "id", None) and node.id in graph_engine.graph:
            try:
                gpos = graph_engine.gpos_applying_to_node(node.id)
                for gpo_id in gpos:
                    gpo_attrs = graph_engine.graph.nodes.get(gpo_id, {}) or {}
                    gpo_loot = gpo_attrs.get("gpo_loot") or []
                    if gpo_loot:
                        first = gpo_loot[0]
                        return first
            except Exception:
                log.debug("gpo credential lookup failed", exc_info=True)
    except Exception:
        log.exception("get_credential_record failed for node %s", getattr(node, "id", None))
    return None


def get_node_attrs(graph_engine: Any, node: Any) -> dict:
    if not graph_engine or not getattr(node, "id", None) or node.id not in graph_engine.graph:
        return {}
    attrs = graph_engine.graph.nodes.get(node.id, {})
    return attrs if isinstance(attrs, dict) else {}


def is_protected_user(graph_engine: Any, node: Any) -> bool:
    attrs = get_node_attrs(graph_engine, node)
    if attrs.get("restricted") or attrs.get("is_protected") or attrs.get("protected"):
        return True

    if not graph_engine or not getattr(node, "id", None) or node.id not in graph_engine.graph:
        return False

    try:
        for _, group_id, edata in graph_engine.graph.out_edges(node.id, data=True):
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
        log.exception("is_protected_user failed for node %s", getattr(node, "id", None))
        return False

    return False


def get_raw_properties(graph_engine: Any, node: Any) -> dict:
    attrs = get_node_attrs(graph_engine, node)
    raw_properties = attrs.get("raw_properties")
    return raw_properties if isinstance(raw_properties, dict) else {}


def lookup_node_value(node: Any, *names: str):
    return ad_utils._lookup_node_value(node, *names)


def list_node_values(node: Any, *names: str) -> list:
    val = lookup_node_value(node, *names)
    if val is None:
        return []
    if isinstance(val, list):
        return [item for item in val if item not in (None, "")]
    return [val]


def normalize_reference(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("ObjectIdentifier", "ObjectId", "MemberId", "Name", "name"):
            candidate = value.get(key)
            if candidate:
                return str(candidate).strip().casefold()
        return ""
    return str(value or "").strip().casefold()


def password_for_node(loot_manager: Any, node: Any, placeholder: str = "<PASSWORD>") -> str:
    cred = get_credential_record(loot_manager, None, node)
    if cred and getattr(cred, "password", None):
        return cred.password
    return placeholder


def hash_for_node(loot_manager: Any, node: Any, placeholder: str = "<NTLM_HASH>") -> str:
    cred = get_credential_record(loot_manager, None, node)
    if cred and getattr(cred, "ntlm_hash", None):
        return cred.ntlm_hash
    return placeholder


def password_or_hash_for_node(loot_manager: Any, node: Any, placeholder: str = "<PASSWORD_OR_HASH>") -> str:
    cred = get_credential_record(loot_manager, None, node)
    if cred:
        if getattr(cred, "password", None):
            return cred.password
        if getattr(cred, "ntlm_hash", None):
            return cred.ntlm_hash
    return placeholder


def laps_password_for_node(loot_manager: Any, node: Any, placeholder: str = "<LAPS_PASSWORD>") -> str:
    cred = get_credential_record(loot_manager, None, node)
    if cred and getattr(cred, "laps_password", ""):
        return cred.laps_password
    return placeholder


def pfx_path_for_node(loot_manager: Any, node: Any, placeholder: str = "<TARGET>.pfx") -> str:
    cred = get_credential_record(loot_manager, None, node)
    if cred and getattr(cred, "pfx_path", ""):
        return cred.pfx_path
    return placeholder


def verify_session_version(data: dict) -> bool:
    """Return True if session `data` version matches the running app version."""
    try:
        from engine import state as est

        return isinstance(data, dict) and int(data.get("version", -1)) == int(est.SESSION_VERSION)
    except Exception:
        return False
