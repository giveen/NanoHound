from __future__ import annotations

from typing import Any
from engine.utils import ad_utils
import logging

log = logging.getLogger("nanohound.utils.pki")


def find_enterprise_ca_node(graph_engine: Any, source_node: Any, target_node: Any) -> Any | None:
    # Prefer explicit EnterpriseCA nodes among source/target
    for candidate in (target_node, source_node):
        if candidate and getattr(candidate, "node_type", "").casefold() == "enterpriseca" and getattr(candidate, "id", None):
            return candidate

    template_candidates = [
        candidate
        for candidate in (target_node, source_node)
        if candidate and getattr(candidate, "node_type", "").casefold() == "certtemplate" and (getattr(candidate, "id", None) or getattr(candidate, "name", None))
    ]
    if graph_engine:
        for template_node in template_candidates:
            target_refs = {
                normalize_reference(getattr(template_node, "id", None)),
                normalize_reference(getattr(template_node, "name", None)),
            }
            for node_id, attrs in graph_engine.graph.nodes(data=True):
                if str(attrs.get("type", "")).casefold() != "enterpriseca":
                    continue
                ca_context = type("N", (), {
                    "id": str(node_id),
                    "name": str(attrs.get("name", node_id)),
                    "node_type": str(attrs.get("type", "enterpriseca")),
                    "spn": str(attrs.get("spn", "")),
                    "domain": str(attrs.get("domain", "")),
                })
                for key in (
                    "EnabledCertTemplates",
                    "enabledcerttemplates",
                    "PublishedTemplates",
                    "publishedtemplates",
                    "CertificateTemplates",
                    "certificatetemplates",
                    "Templates",
                    "templates",
                ):
                    references = {normalize_reference(value) for value in ad_utils._list_node_values(ca_context, key)}
                    if references & target_refs:
                        return ca_context

        for node_id, attrs in graph_engine.graph.nodes(data=True):
            if str(attrs.get("type", "")).casefold() != "enterpriseca":
                continue
            return type("N", (), {
                "id": str(node_id),
                "name": str(attrs.get("name", node_id)),
                "node_type": str(attrs.get("type", "enterpriseca")),
                "spn": str(attrs.get("spn", "")),
                "domain": str(attrs.get("domain", "")),
            })

    return None


def resolve_ca_name(ca_node: Any, placeholder: str = "<CA-NAME>") -> str:
    if not ca_node:
        return placeholder
    for key in ("caname", "CAName", "displayname", "DisplayName"):
        value = ad_utils._lookup_node_value(ca_node, key)
        if value:
            return str(value).strip()
    return getattr(ca_node, "name", None) or placeholder


def resolve_ca_server(ca_node: Any, placeholder: str = "<CA-SERVER>") -> str:
    if not ca_node:
        return placeholder

    for key in (
        "dnshostname",
        "dNSHostName",
        "dnsname",
        "DNSName",
        "hostname",
        "HostName",
        "computername",
        "ComputerName",
        "machineaccount",
        "MachineAccount",
    ):
        value = ad_utils._lookup_node_value(ca_node, key)
        if value:
            return str(value).strip().rstrip("$")

    ca_name = getattr(ca_node, "name", "")
    if "\\" in ca_name:
        return ca_name.split("\\", maxsplit=1)[0].strip() or placeholder

    return placeholder


def normalize_reference(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("ObjectIdentifier", "ObjectId", "MemberId", "Name", "name"):
            candidate = value.get(key)
            if candidate:
                return str(candidate).strip().casefold()
        return ""
    return str(value or "").strip().casefold()
