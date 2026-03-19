"""In-memory graph logic for NanoHound."""

from __future__ import annotations

from typing import Any

import networkx as nx


class NanoGraphEngine:
    """Maintain an AD relationship graph and expose pathfinding helpers."""

    PERMISSION_MAP = {
        "GenericAll": "Owns",
        "WriteDacl": "CanWriteDacl",
        "WriteOwner": "CanWriteOwner",
        "GenericWrite": "CanGenericWrite",
        "AddMember": "CanAddMember",
        "MemberOf": "MemberOf",
        "AllExtendedRights": "AllExtendedRights",
        "ForceChangePassword": "CanForceChangePassword",
    }

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()

    def clear(self) -> None:
        """Drop all nodes and edges."""
        self.graph.clear()

    def _extract_identifier(self, entry: dict[str, Any]) -> str | None:
        """Support common SharpHound identifier fields."""
        return (
            entry.get("ObjectIdentifier")
            or entry.get("ObjectId")
            or entry.get("MemberId")
            or entry.get("MemberSid")
            or entry.get("PrincipalSID")
            or entry.get("PrincipalObjectIdentifier")
            or entry.get("PrincipalObjectId")
        )

    def _entity_id(self, entity: dict[str, Any]) -> str | None:
        if entity.get("ObjectIdentifier"):
            return str(entity["ObjectIdentifier"])

        properties = entity.get("Properties", {})
        if isinstance(properties, dict):
            value = properties.get("objectsid") or properties.get("objectid")
            if value:
                return str(value)

        return None

    def _entity_name(self, entity: dict[str, Any]) -> str | None:
        properties = entity.get("Properties", {})
        if isinstance(properties, dict) and properties.get("name"):
            return str(properties["name"])
        return None

    def _to_bool(self, value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes"}
        return False

    def add_edge_from_ace(self, principal: str, target: str, right_name: str) -> None:
        """Translate an AD ACE right into a directed graph edge."""
        if not principal or not target:
            return

        relationship = self.PERMISSION_MAP.get(right_name, right_name or "UnknownRight")
        self.graph.add_edge(
            principal,
            target,
            relationship=relationship,
            raw_right=right_name,
        )

    def _attach_aces(self, entity: dict[str, Any], target_id: str) -> None:
        aces = entity.get("Aces", [])
        if not isinstance(aces, list):
            return

        for ace in aces:
            if not isinstance(ace, dict):
                continue

            principal = self._extract_identifier(ace)
            right_name = str(ace.get("RightName") or ace.get("AceType") or "UnknownRight")
            if principal:
                self.add_edge_from_ace(principal, target_id, right_name)

    def build_from_sharphound(self, data: dict[str, list[dict]]) -> None:
        """Build graph nodes and edges from parsed SharpHound datasets."""
        self.clear()

        for dataset in ("users", "computers", "groups"):
            for entity in data.get(dataset, []):
                if not isinstance(entity, dict):
                    continue

                entity_id = self._entity_id(entity)
                if not entity_id:
                    continue

                node_attrs: dict[str, Any] = {
                    "type": dataset[:-1],
                    "name": self._entity_name(entity) or entity_id,
                }

                if dataset == "users":
                    is_kerberoastable = self._to_bool(entity.get("is_kerberoastable") or entity.get("hasspn"))
                    is_asrep_roastable = self._to_bool(
                        entity.get("is_asrep_roastable") or entity.get("dontreqpreauth"),
                    )
                    node_attrs.update(
                        {
                            "hasspn": is_kerberoastable,
                            "dontreqpreauth": is_asrep_roastable,
                            "pwdlastset": entity.get("pwdlastset"),
                            "is_kerberoastable": is_kerberoastable,
                            "is_asrep_roastable": is_asrep_roastable,
                            "is_roastable": is_kerberoastable or is_asrep_roastable,
                        },
                    )

                self.graph.add_node(entity_id, **node_attrs)
                self._attach_aces(entity, entity_id)

                if dataset != "groups":
                    continue

                members = entity.get("Members", [])
                if not isinstance(members, list):
                    continue

                for member in members:
                    if not isinstance(member, dict):
                        continue
                    member_id = self._extract_identifier(member)
                    if not member_id:
                        continue

                    self.graph.add_edge(
                        member_id,
                        entity_id,
                        relationship="MemberOf",
                        raw_right="MemberOf",
                    )

    def _resolve_node(self, candidate: str) -> str | None:
        if candidate in self.graph:
            return candidate

        lowered = candidate.casefold()
        for node_id, attrs in self.graph.nodes(data=True):
            node_name = str(attrs.get("name", "")).casefold()
            if node_name == lowered:
                return str(node_id)

        return None

    def find_shortest_path(self, source: str, target: str) -> list[str] | None:
        """Return the shortest directed path, or None when not connected."""
        source_id = self._resolve_node(source)
        target_id = self._resolve_node(target)
        if not source_id or not target_id:
            return None

        try:
            return nx.shortest_path(self.graph, source=source_id, target=target_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None
