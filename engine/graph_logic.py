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

    # Lower is better/easier during live-path calculation.
    EDGE_WEIGHT_MAP = {
        "MemberOf": 0,
        "GenericAll": 1,
        "Owns": 1,
        "WriteDacl": 2,
        "CanWriteDacl": 2,
        "WriteOwner": 2,
        "CanWriteOwner": 2,
        "GenericWrite": 2,
        "CanGenericWrite": 2,
        "AddMember": 2,
        "CanAddMember": 2,
        "AllExtendedRights": 2,
        "CanForceChangePassword": 2,
        "ForceChangePassword": 2,
    }

    # Preferred right label when multiple rights exist on the same directed edge.
    EDGE_DISPLAY_PRIORITY = [
        "DCSync",
        "ForceChangePassword",
        "CanForceChangePassword",
        "GenericAll",
        "Owns",
        "WriteDacl",
        "CanWriteDacl",
        "WriteOwner",
        "CanWriteOwner",
        "GenericWrite",
        "CanGenericWrite",
        "AddMember",
        "CanAddMember",
        "AllExtendedRights",
        "MemberOf",
    ]

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

        normalized_right = right_name or "UnknownRight"

        edge = self.graph.get_edge_data(principal, target)
        if edge:
            existing_rights = set(edge.get("raw_rights") or [])
            existing_raw = str(edge.get("raw_right", "")).strip()
            if existing_raw:
                existing_rights.add(existing_raw)
            existing_rights.add(normalized_right)

            preferred_raw_right = self._preferred_right(existing_rights)
            preferred_relationship = self.PERMISSION_MAP.get(
                preferred_raw_right,
                preferred_raw_right or "UnknownRight",
            )

            min_weight = min(
                int(
                    self.EDGE_WEIGHT_MAP.get(
                        right,
                        self.EDGE_WEIGHT_MAP.get(
                            str(self.PERMISSION_MAP.get(right, right) or right),
                            3,
                        ),
                    )
                )
                for right in existing_rights
            )

            self.graph.add_edge(
                principal,
                target,
                relationship=preferred_relationship,
                raw_right=preferred_raw_right,
                raw_rights=self._sorted_rights(existing_rights),
                weight=min_weight,
            )
            return

        relationship = self.PERMISSION_MAP.get(normalized_right, normalized_right)
        weight = self.EDGE_WEIGHT_MAP.get(
            normalized_right,
            self.EDGE_WEIGHT_MAP.get(relationship, 3),
        )
        self.graph.add_edge(
            principal,
            target,
            relationship=relationship,
            raw_right=normalized_right,
            raw_rights=[normalized_right],
            weight=weight,
        )

    def _preferred_right(self, rights: set[str]) -> str:
        """Choose a stable display right when multiple rights exist on one edge."""
        if not rights:
            return "UnknownRight"

        by_priority = {name: idx for idx, name in enumerate(self.EDGE_DISPLAY_PRIORITY)}
        return min(
            rights,
            key=lambda right: (by_priority.get(right, len(self.EDGE_DISPLAY_PRIORITY)), right),
        )

    def _sorted_rights(self, rights: set[str]) -> list[str]:
        """Sort rights by display priority for deterministic UI output."""
        by_priority = {name: idx for idx, name in enumerate(self.EDGE_DISPLAY_PRIORITY)}
        return sorted(
            rights,
            key=lambda right: (by_priority.get(right, len(self.EDGE_DISPLAY_PRIORITY)), right),
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
                        weight=self.EDGE_WEIGHT_MAP["MemberOf"],
                    )

    def _normalize_object_name(self, name: str) -> str:
        r"""Extract the clean RDN (relative distinguished name) from an AD object name.
        
        Handles formats like:
        - DOMAIN ADMINS
        - DOMAIN ADMINS@FOREST.LOCAL
        - DOMAIN\DOMAIN ADMINS
        - CN=Domain Admins,OU=...
        """
        name = name.strip()
        
        # Remove leading DOMAIN\ or FOREST\ prefixes
        if "\\" in name:
            name = name.split("\\", maxsplit=1)[-1].strip()
        
        # Remove trailing @domain suffix
        if "@" in name:
            name = name.split("@", maxsplit=1)[0].strip()
        
        # Handle CN= LDAP format
        if name.upper().startswith("CN="):
            name = name[3:].split(",", maxsplit=1)[0].strip()
        
        return name.casefold()

    def _is_target_group(self, node_id: str, target_group: str) -> bool:
        """Match a node against a target group name, handling various AD naming formats."""
        attrs = self.graph.nodes[node_id]
        if str(attrs.get("type", "")).casefold() != "group":
            return False

        target_normalized = self._normalize_object_name(target_group)
        if not target_normalized:
            return False

        node_name = str(attrs.get("name", ""))
        node_normalized = self._normalize_object_name(node_name)
        
        # Direct match after normalization
        if node_normalized == target_normalized:
            return True
        
        # For "DOMAIN ADMINS", also match substring (e.g., contains "domain admin")
        # This helps catch variations like "DOMAIN ADMINS@..." or "DOMAIN\DOMAIN ADMINS"
        target_parts = target_normalized.split()
        if len(target_parts) > 0:
            # Check if all significant words are in the normalized node name
            return all(part in node_normalized for part in target_parts)
        
        return False

    def get_shortest_path_from_owned(self, target_group: str = "DOMAIN ADMINS") -> list[str] | None:
        """Return the easiest weighted path from any owned node to a target group.

        Uses multi-source Dijkstra so every owned node acts as a starting beachhead.
        """
        owned_sources = [
            str(node_id)
            for node_id, attrs in self.graph.nodes(data=True)
            if bool(attrs.get("is_owned"))
        ]
        if not owned_sources:
            return None

        target_nodes = [
            str(node_id)
            for node_id in self.graph.nodes
            if self._is_target_group(str(node_id), target_group)
        ]
        if not target_nodes:
            return None

        try:
            paths = nx.multi_source_dijkstra_path(
                self.graph,
                sources=owned_sources,
                weight="weight",
            )
        except (nx.NetworkXNoPath, nx.NodeNotFound, ValueError):
            return None

        best_path: list[str] | None = None
        best_cost: float | None = None
        for target in target_nodes:
            path = paths.get(target)
            if not path:
                continue

            cost = 0.0
            for src, dst in zip(path, path[1:]):
                edge = self.graph.get_edge_data(src, dst) or {}
                cost += float(edge.get("weight", 1))

            if best_cost is None or cost < best_cost:
                best_cost = cost
                best_path = [str(node) for node in path]

        return best_path

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
