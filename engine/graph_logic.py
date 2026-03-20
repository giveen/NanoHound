"""In-memory graph logic for NanoHound."""

from __future__ import annotations

from typing import Any

import networkx as nx


class NanoGraphEngine:
    """Maintain an AD relationship graph and expose pathfinding helpers."""

    PERMISSION_MAP = {
        "DCSync": "DCSync",
        "GetChanges": "GetChanges",
        "GetChangesAll": "GetChangesAll",
        "GetChangesInFilteredSet": "GetChangesInFilteredSet",
        "DS-Replication-Get-Changes": "GetChanges",
        "DS-Replication-Get-Changes-All": "GetChangesAll",
        "DS-Replication-Get-Changes-In-Filtered-Set": "GetChangesInFilteredSet",
        "Contains": "Contains",
        "CrossForestTrust": "CrossForestTrust",
        "DCFor": "DCFor",
        "DelegatedEnrollmentAgent": "DelegatedEnrollmentAgent",
        "DumpSMSAPassword": "DumpSMSAPassword",
        "DumpSMsaPassword": "DumpSMSAPassword",
        "DumpSmsaPassword": "DumpSMSAPassword",
        "Enroll": "Enroll",
        "Certificate-Enrollment": "Enroll",
        "EnrollOnBehalfOf": "EnrollOnBehalfOf",
        "GenericAll": "Owns",
        "WriteDacl": "CanWriteDacl",
        "WriteOwner": "CanWriteOwner",
        "GenericWrite": "CanGenericWrite",
        "AddMember": "CanAddMember",
        "AddMembers": "CanAddMember",
        "AddSelf": "AddSelf",
        "AdminTo": "AdminTo",
        "CanRDP": "CanRDP",
        "ClaimSpecialIdentity": "ClaimSpecialIdentity",
        "CoerceAndRelayNTLMToADCS": "CoerceAndRelayNTLMToADCS",
        "CoerceAndRelayNTLMToLDAP": "CoerceAndRelayNTLMToLDAP",
        "CoerceAndRelayNTLMToLDAPS": "CoerceAndRelayNTLMToLDAPS",
        "CoerceAndRelayNTLMToSMB": "CoerceAndRelayNTLMToSMB",
        "CoerceToTGT": "CoerceToTGT",
        "AddAllowedToAct": "AddAllowedToAct",
        "AllowedToAct": "AllowedToAct",
        "AllowedToDelegate": "AllowedToDelegate",
        "CanPSRemote": "CanPSRemote",
        "AddKeyCredentialLink": "AddKeyCredentialLink",
        "MemberOf": "MemberOf",
        "AllExtendedRights": "AllExtendedRights",
        "ForceChangePassword": "CanForceChangePassword",
        "ADCSESC1": "ADCSESC1",
        "ADCSESC3": "ADCSESC3",
        "ADCSESC4": "ADCSESC4",
        "ADCSESC6a": "ADCSESC6a",
        "ADCSESC6A": "ADCSESC6a",
        "ADCSESC6b": "ADCSESC6b",
        "ADCSESC6B": "ADCSESC6b",
        "ADCSESC9a": "ADCSESC9a",
        "ADCSESC9A": "ADCSESC9a",
        "ADCSESC9b": "ADCSESC9b",
        "ADCSESC9B": "ADCSESC9b",
        "ADCSESC10a": "ADCSESC10a",
        "ADCSESC10b": "ADCSESC10b",
        "ADCSESC13": "ADCSESC13",
    }

    # Lower is better/easier during live-path calculation.
    EDGE_WEIGHT_MAP = {
        "MemberOf": 0,
        "DCSync": 1,
        "GetChanges": 2,
        "GetChangesAll": 2,
        "GetChangesInFilteredSet": 2,
        "Contains": 3,
        "CrossForestTrust": 3,
        "DCFor": 1,
        "DelegatedEnrollmentAgent": 3,
        "DumpSMSAPassword": 2,
        "Enroll": 2,
        "EnrollOnBehalfOf": 2,
        "GenericAll": 1,
        "Owns": 1,
        "WriteDacl": 2,
        "CanWriteDacl": 2,
        "WriteOwner": 2,
        "CanWriteOwner": 2,
        "GenericWrite": 2,
        "CanGenericWrite": 2,
        "AddMember": 2,
        "AddMembers": 2,
        "AddSelf": 2,
        "AdminTo": 1,
        "CanRDP": 2,
        "ClaimSpecialIdentity": 2,
        "CoerceAndRelayNTLMToADCS": 1,
        "CoerceAndRelayNTLMToLDAP": 1,
        "CoerceAndRelayNTLMToLDAPS": 1,
        "CoerceAndRelayNTLMToSMB": 1,
        "CoerceToTGT": 1,
        "CanAddMember": 2,
        "AddAllowedToAct": 2,
        "AllowedToAct": 2,
        "AllowedToDelegate": 2,
        "CanPSRemote": 2,
        "AddKeyCredentialLink": 2,
        "AllExtendedRights": 2,
        "CanForceChangePassword": 2,
        "ForceChangePassword": 2,
        "ADCSESC1": 1,
        "ADCSESC3": 1,
        "ADCSESC4": 1,
        "ADCSESC6a": 1,
        "ADCSESC6A": 1,
        "ADCSESC6b": 1,
        "ADCSESC6B": 1,
        "ADCSESC9a": 1,
        "ADCSESC9A": 1,
        "ADCSESC9b": 1,
        "ADCSESC9B": 1,
        "ADCSESC10a": 1,
        "ADCSESC10b": 1,
        "ADCSESC13": 1,
    }

    # Preferred right label when multiple rights exist on the same directed edge.
    EDGE_DISPLAY_PRIORITY = [
        "DCSync",
        "GetChanges",
        "GetChangesAll",
        "GetChangesInFilteredSet",
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
        "AddKeyCredentialLink",
        "AdminTo",
        "CanRDP",
        "ClaimSpecialIdentity",
        "CoerceAndRelayNTLMToADCS",
        "CoerceAndRelayNTLMToLDAP",
        "CoerceAndRelayNTLMToLDAPS",
        "CoerceAndRelayNTLMToSMB",
        "CoerceToTGT",
        "AddAllowedToAct",
        "AllowedToAct",
        "AllowedToDelegate",
        "CanPSRemote",
        "AddSelf",
        "AddMember",
        "AddMembers",
        "CanAddMember",
        "AllExtendedRights",
        "Enroll",
        "ADCSESC1",
        "ADCSESC3",
        "ADCSESC4",
        "ADCSESC6a",
        "ADCSESC6A",
        "ADCSESC6b",
        "ADCSESC6B",
        "ADCSESC9a",
        "ADCSESC9A",
        "ADCSESC9b",
        "ADCSESC9B",
        "ADCSESC10a",
        "ADCSESC10b",
        "ADCSESC13",
        "EnrollOnBehalfOf",
        "DumpSMSAPassword",
        "DelegatedEnrollmentAgent",
        "DCFor",
        "CrossForestTrust",
        "Contains",
        "MemberOf",
    ]

    DATASET_NODE_TYPE_MAP = {
        "users": "user",
        "computers": "computer",
        "groups": "group",
        "domains": "domain",
        "ous": "ou",
        "gpos": "gpo",
        "containers": "container",
        "certtemplates": "certtemplate",
        "enterprisecas": "enterpriseca",
        "rootcas": "rootca",
        "aiacas": "aiaca",
        "ntauthstores": "ntauthstore",
        "issuancepolicies": "issuancepolicy",
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

        normalized_right = right_name or "UnknownRight"

        edge = self.graph.get_edge_data(principal, target)
        if edge:
            existing_rights = set(edge.get("raw_rights") or [])
            existing_raw = str(edge.get("raw_right", "")).strip()
            if existing_raw:
                existing_rights.add(existing_raw)
            existing_rights.add(normalized_right)

            if self._has_dcsync_combo(existing_rights):
                existing_rights.add("DCSync")

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
        if self._has_dcsync_combo({normalized_right}):
            relationship = "DCSync"
            normalized_right = "DCSync"
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

    def _normalize_right_name(self, right: str) -> str:
        return right.casefold().replace("-", "").replace("_", "").replace(" ", "")

    def _has_dcsync_combo(self, rights: set[str]) -> bool:
        normalized = {self._normalize_right_name(str(right)) for right in rights if str(right).strip()}
        has_get_changes = "getchanges" in normalized or "dsreplicationgetchanges" in normalized
        has_get_changes_all = "getchangesall" in normalized or "dsreplicationgetchangesall" in normalized
        return has_get_changes and has_get_changes_all

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

    def _entity_properties(self, entity: dict[str, Any]) -> dict[str, Any]:
        properties = entity.get("Properties", {})
        if isinstance(properties, dict):
            return properties
        return {}

    def _property_lookup(self, entity: dict[str, Any], *names: str) -> Any:
        properties = self._entity_properties(entity)
        normalized_names = {name.casefold() for name in names}

        for container in (entity, properties):
            for key, value in container.items():
                if str(key).casefold() in normalized_names:
                    return value

        return None

    def _property_list(self, entity: dict[str, Any], *names: str) -> list[str]:
        value = self._property_lookup(entity, *names)
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str):
            cleaned = value.strip()
            return [cleaned] if cleaned else []
        return []

    def _property_number(self, entity: dict[str, Any], *names: str) -> float | None:
        value = self._property_lookup(entity, *names)
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            cleaned = value.strip()
            if not cleaned:
                return None
            try:
                return float(cleaned)
            except ValueError:
                return None
        return None

    def _is_enrollment_agent_template(self, entity: dict[str, Any]) -> bool:
        eku_values = {
            value.casefold()
            for value in self._property_list(
                entity,
                "effectiveekus",
                "EffectiveEKUs",
                "applicationpolicies",
                "ApplicationPolicies",
                "certificateapplicationpolicy",
                "CertificateApplicationPolicy",
            )
        }
        return any(
            eku in eku_values
            for eku in ("1.3.6.1.4.1.311.20.2.1", "2.5.29.37.0")
        )

    def _template_allows_on_behalf_of(self, entity: dict[str, Any]) -> bool:
        schema_version = self._property_number(entity, "schemaversion", "SchemaVersion")
        authorized_signatures = self._property_number(
            entity,
            "authorizedsignatures",
            "AuthorizedSignatures",
        )

        if schema_version is not None and schema_version <= 1:
            return True
        return (authorized_signatures or 0) > 0

    def _normalize_template_reference(self, value: Any) -> str:
        if isinstance(value, dict):
            candidate = self._extract_identifier(value) or value.get("Name") or value.get("name")
        else:
            candidate = value

        return str(candidate or "").strip().casefold()

    def _resolve_published_template_ids(self, data: dict[str, list[dict[str, Any]]]) -> set[str]:
        reference_sets: set[str] = set()
        for ca in data.get("enterprisecas", []):
            if not isinstance(ca, dict):
                continue

            for key in (
                "EnabledCertTemplates",
                "enabledcerttemplates",
                "PublishedTemplates",
                "publishedtemplates",
                "CertificateTemplates",
                "certificatetemplates",
                "Templates",
                "templates",
            ):
                for value in self._property_list(ca, key):
                    normalized = self._normalize_template_reference(value)
                    if normalized:
                        reference_sets.add(normalized)

                raw_value = self._property_lookup(ca, key)
                if isinstance(raw_value, list):
                    for item in raw_value:
                        normalized = self._normalize_template_reference(item)
                        if normalized:
                            reference_sets.add(normalized)

        if not reference_sets:
            return set()

        published: set[str] = set()
        for template in data.get("certtemplates", []):
            if not isinstance(template, dict):
                continue

            template_id = self._entity_id(template)
            template_name = self._entity_name(template)
            if not template_id:
                continue

            candidates = {
                str(template_id).casefold(),
                str(template_name or "").casefold(),
            }
            if candidates & reference_sets:
                published.add(str(template_id))

        return published

    def _attach_enroll_on_behalf_of_edges(self, data: dict[str, list[dict[str, Any]]]) -> None:
        published_template_ids = self._resolve_published_template_ids(data)
        templates = [
            entity
            for entity in data.get("certtemplates", [])
            if isinstance(entity, dict)
        ]

        for source_template in templates:
            source_id = self._entity_id(source_template)
            if not source_id or source_id not in self.graph:
                continue
            if published_template_ids and source_id not in published_template_ids:
                continue
            if not self._is_enrollment_agent_template(source_template):
                continue

            for target_template in templates:
                target_id = self._entity_id(target_template)
                if not target_id or target_id not in self.graph or target_id == source_id:
                    continue
                if published_template_ids and target_id not in published_template_ids:
                    continue
                if not self._template_allows_on_behalf_of(target_template):
                    continue

                self.add_edge_from_ace(source_id, target_id, "EnrollOnBehalfOf")

    def _attach_contains_edges(self, data: dict[str, list[dict[str, Any]]]) -> None:
        for dataset in ("domains", "ous", "containers", "computers"):
            for entity in data.get(dataset, []):
                if not isinstance(entity, dict):
                    continue

                source_id = self._entity_id(entity)
                if not source_id or source_id not in self.graph:
                    continue

                child_objects = entity.get("ChildObjects", [])
                if not isinstance(child_objects, list):
                    continue

                for child in child_objects:
                    if not isinstance(child, dict):
                        continue
                    child_id = self._extract_identifier(child)
                    if not child_id:
                        continue
                    if child_id in self.graph:
                        self.add_edge_from_ace(source_id, child_id, "Contains")

    def _resolve_domain_by_name(self, domain_name: str) -> str | None:
        candidate = domain_name.casefold().strip()
        if not candidate:
            return None

        for node_id, attrs in self.graph.nodes(data=True):
            if str(attrs.get("type", "")).casefold() != "domain":
                continue
            if str(attrs.get("name", "")).casefold() == candidate:
                return str(node_id)

        return None

    def _attach_cross_forest_trust_edges(self, data: dict[str, list[dict[str, Any]]]) -> None:
        for domain in data.get("domains", []):
            if not isinstance(domain, dict):
                continue

            source_domain_id = self._entity_id(domain)
            if not source_domain_id or source_domain_id not in self.graph:
                continue

            trusts = domain.get("Trusts", [])
            if not isinstance(trusts, list):
                continue

            for trust in trusts:
                if not isinstance(trust, dict):
                    continue

                target_domain_id = (
                    trust.get("TargetDomainSid")
                    or trust.get("TargetSid")
                    or trust.get("TrustPartnerSid")
                )
                target_domain_name = (
                    trust.get("TargetDomainName")
                    or trust.get("TargetDomain")
                    or trust.get("TrustPartner")
                )

                if target_domain_name and not target_domain_id:
                    target_domain_id = self._resolve_domain_by_name(str(target_domain_name))

                if not target_domain_id:
                    continue

                target_domain_id = str(target_domain_id)
                if target_domain_id not in self.graph:
                    self.graph.add_node(
                        target_domain_id,
                        type="domain",
                        name=str(target_domain_name or target_domain_id),
                    )

                self.add_edge_from_ace(source_domain_id, target_domain_id, "CrossForestTrust")

    def _attach_dcfor_edges(self, data: dict[str, list[dict[str, Any]]]) -> None:
        known_domain_ids = {
            self._entity_id(domain)
            for domain in data.get("domains", [])
            if isinstance(domain, dict)
        }
        known_domain_ids.discard(None)

        for computer in data.get("computers", []):
            if not isinstance(computer, dict):
                continue

            computer_id = self._entity_id(computer)
            if not computer_id or computer_id not in self.graph:
                continue

            primary_group_sid = str(computer.get("PrimaryGroupSID") or "").strip()
            if not primary_group_sid.endswith("-516"):
                continue

            properties = computer.get("Properties", {})
            domain_sid = ""
            if isinstance(properties, dict):
                domain_sid = str(properties.get("domainsid") or "").strip()

            if not domain_sid and primary_group_sid:
                domain_sid = primary_group_sid[: -len("-516")]

            if not domain_sid:
                continue

            if domain_sid not in known_domain_ids and domain_sid not in self.graph:
                continue

            if domain_sid not in self.graph:
                self.graph.add_node(domain_sid, type="domain", name=domain_sid)

            self.add_edge_from_ace(computer_id, domain_sid, "DCFor")

    def find_dc_for_domain(self, domain_name: str | None) -> str | None:
        """Find a Domain Controller hostname for the given domain name.
        
        Returns the computer name of any DC found for this domain, or None.
        DC computers have a 'DCFor' edge to a domain node, or are identified by
        having PrimaryGroupSID ending in -516 (Domain Controllers group).
        """
        if not domain_name:
            return None
        
        domain_name_normalized = str(domain_name).casefold().strip()
        
        # First pass: look for computers with DCFor edges to this domain
        for dc_id, domain_id in self.graph.edges():
            edge_data = self.graph.get_edge_data(dc_id, domain_id)
            if edge_data and edge_data.get("relationship") == "DCFor":
                # Check if target domain matches our query
                domain_attrs = self.graph.nodes.get(domain_id, {})
                domain_display = str(domain_attrs.get("name", "")).casefold()
                if domain_display == domain_name_normalized or domain_id == domain_name_normalized:
                    dc_attrs = self.graph.nodes.get(dc_id, {})
                    dc_name = dc_attrs.get("name")
                    if dc_name:
                        return str(dc_name)
        
        # Second pass: heuristic - look for computers matching the domain in their name
        for node_id, attrs in self.graph.nodes(data=True):
            if attrs.get("type") != "computer":
                continue
            node_name = str(attrs.get("name", "")).casefold()
            # If computer name starts with domain prefix (DOMAIN-DC01), it's likely a DC
            if domain_name_normalized and node_name.startswith(domain_name_normalized.split(".")[0]):
                return str(attrs.get("name"))
        
        # Third pass: return any computer node as fallback
        for node_id, attrs in self.graph.nodes(data=True):
            if attrs.get("type") == "computer":
                return str(attrs.get("name"))

    def build_from_sharphound(self, data: dict[str, list[dict]]) -> None:
        """Build graph nodes and edges from parsed SharpHound datasets."""
        self.clear()

        ordered_datasets = [
            dataset
            for dataset in self.DATASET_NODE_TYPE_MAP
            if dataset in data
        ]
        for dataset in ordered_datasets:
            for entity in data.get(dataset, []):
                if not isinstance(entity, dict):
                    continue

                entity_id = self._entity_id(entity)
                if not entity_id:
                    continue

                node_attrs: dict[str, Any] = {
                    "type": self.DATASET_NODE_TYPE_MAP.get(dataset, dataset.rstrip("s")),
                    "name": self._entity_name(entity) or entity_id,
                    "raw_properties": entity.get("Properties") or {},
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

        self._attach_contains_edges(data)
        self._attach_cross_forest_trust_edges(data)
        self._attach_dcfor_edges(data)
        self._attach_enroll_on_behalf_of_edges(data)

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
