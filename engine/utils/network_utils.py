from __future__ import annotations

import socket
from typing import Any
from .ad_utils import node_hostname, node_sam, _lookup_node_value


def _node_ip(node: Any, placeholder: str = "<TARGET_IP>") -> str:
    for key in ("ip_address", "ip", "ipaddress", "IPAddress", "ipv4", "IPv4"):
        value = _lookup_node_value(node, key)
        if value:
            text = str(value).strip()
            if text:
                return text
    return placeholder


def node_endpoint(node: Any, placeholder: str = "<TARGET_HOST>", prefer_ip: bool = False) -> str:
    if prefer_ip:
        ip = _node_ip(node, "")
        if ip:
            return ip
    return node_hostname(node, placeholder)


def find_dc_for_domain(domain: str, prefer_ip: bool = False) -> str | None:
    # Lightweight placeholder implementation: try DNS SRV lookup for _ldap._tcp.dc._msdcs.<domain>
    if not domain:
        return None
    try:
        # Use socket.getaddrinfo on the domain to at least return something usable
        # This is a best-effort helper; a full implementation could integrate with graph_engine
        infos = socket.getaddrinfo(domain, None)
        if infos:
            # Return the first canonical name or address
            return infos[0][4][0]
    except Exception:
        pass
    return None


def is_port_open(node: Any, port: int, timeout: float = 1.0) -> bool:
    """Attempt to connect to the node on the specified port. Resolves hostname/ip from the node."""
    host = node_endpoint(node)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False
