"""SharpHound data ingestion helpers."""

from __future__ import annotations

import json
from pathlib import Path
from zipfile import ZipFile


class SharpHoundIngestor:
    """Load SharpHound v4/v5 JSON datasets from zip archives or loose files."""

    TARGET_FILES = {
        "users.json": "users",
        "computers.json": "computers",
        "groups.json": "groups",
        "domains.json": "domains",
        "ous.json": "ous",
        "gpos.json": "gpos",
        "containers.json": "containers",
        "certtemplates.json": "certtemplates",
        "enterprisecas.json": "enterprisecas",
        "rootcas.json": "rootcas",
        "aiacas.json": "aiacas",
        "ntauthstores.json": "ntauthstores",
        "issuancepolicies.json": "issuancepolicies",
    }

    @classmethod
    def empty_parsed(cls) -> dict[str, list[dict]]:
        """Return a zeroed parsed-datasets container for all supported keys."""
        return {
            dataset: []
            for dataset in sorted(set(cls.TARGET_FILES.values()))
        }

    @classmethod
    def classify_filename(cls, filename: str) -> str | None:
        """Map a filename to a known dataset key."""
        normalized = Path(filename).name.lower()
        direct = cls.TARGET_FILES.get(normalized)
        if direct is not None:
            return direct

        # SharpHound commonly prefixes export files with timestamps.
        for target_filename, dataset in cls.TARGET_FILES.items():
            if normalized.endswith(target_filename):
                return dataset

        return None

    def _normalize_payload(self, payload: object) -> list[dict]:
        """Return the list of entities regardless of SharpHound wrapper format."""
        if isinstance(payload, dict):
            data = payload.get("data", [])
        elif isinstance(payload, list):
            data = payload
        else:
            data = []

        return [item for item in data if isinstance(item, dict)]

    def _to_bool(self, value: object) -> bool:
        """Convert common SharpHound JSON truthy values into bool."""
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes"}
        return False

    def _extract_user_attack_primitives(self, user_obj: dict) -> dict:
        """Extract roast-related primitives from a SharpHound user object."""
        properties = user_obj.get("Properties", {})
        if not isinstance(properties, dict):
            properties = {}

        has_spn = self._to_bool(properties.get("hasspn"))
        dontreqpreauth = self._to_bool(properties.get("dontreqpreauth"))
        pwdlastset = properties.get("pwdlastset")

        # Keep hot-path lookups top-level for graph enrichment and filtering.
        user_obj["hasspn"] = has_spn
        user_obj["dontreqpreauth"] = dontreqpreauth
        user_obj["pwdlastset"] = pwdlastset
        user_obj["is_kerberoastable"] = has_spn
        user_obj["is_asrep_roastable"] = dontreqpreauth

        return user_obj

    def _extract_dataset_primitives(self, dataset: str, entries: list[dict]) -> list[dict]:
        """Apply dataset-specific extraction logic while preserving original structure."""
        if dataset != "users":
            return entries
        return [self._extract_user_attack_primitives(entry) for entry in entries]

    def _merge_entries(self, existing: list[dict], incoming: list[dict]) -> list[dict]:
        """Merge dataset rows while keeping stable order and de-duplicating by identifier."""
        merged = list(existing)
        seen_ids = {
            str(entry.get("ObjectIdentifier") or entry.get("ObjectId") or "").strip()
            for entry in merged
            if isinstance(entry, dict)
        }

        for entry in incoming:
            if not isinstance(entry, dict):
                continue

            entry_id = str(entry.get("ObjectIdentifier") or entry.get("ObjectId") or "").strip()
            if entry_id and entry_id in seen_ids:
                continue

            merged.append(entry)
            if entry_id:
                seen_ids.add(entry_id)

        return merged

    def parse_json_file(self, file_path: str | Path, dataset: str | None = None) -> list[dict]:
        """Parse a single SharpHound JSON file into a list of objects."""
        with Path(file_path).open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        entries = self._normalize_payload(payload)
        inferred_dataset = dataset or self.classify_filename(Path(file_path).name) or ""
        return self._extract_dataset_primitives(inferred_dataset, entries)

    def unzip_and_parse(self, archive_path: str | Path) -> dict[str, list[dict]]:
        """Extract and parse relevant SharpHound files from a zip archive."""
        parsed = self.empty_parsed()

        with ZipFile(archive_path, "r") as archive:
            for info in archive.infolist():
                dataset = self.classify_filename(info.filename)
                if dataset is None:
                    continue

                with archive.open(info, "r") as raw_file:
                    payload = json.load(raw_file)
                entries = self._normalize_payload(payload)
                normalized = self._extract_dataset_primitives(dataset, entries)
                parsed[dataset] = self._merge_entries(parsed[dataset], normalized)

        return parsed

    def ingest_path(self, path: str | Path) -> dict[str, list[dict]]:
        """Ingest either a zip archive or a directory of SharpHound files."""
        input_path = Path(path)
        if input_path.suffix.lower() == ".zip":
            return self.unzip_and_parse(input_path)

        parsed = self.empty_parsed()

        if input_path.is_file() and input_path.suffix.lower() == ".json":
            dataset = self.classify_filename(input_path.name)
            if dataset is not None:
                parsed[dataset] = self.parse_json_file(input_path, dataset=dataset)
            return parsed

        if input_path.is_dir():
            for candidate in sorted(input_path.glob("*.json")):
                dataset = self.classify_filename(candidate.name)
                if dataset is None:
                    continue

                entries = self.parse_json_file(candidate, dataset=dataset)
                parsed[dataset] = self._merge_entries(parsed[dataset], entries)

        return parsed
