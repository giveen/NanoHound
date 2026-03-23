"""UI helper utilities (docs mapping and URL builder).

Centralized place for UI-facing doc slug overrides and URL generation.
"""
from __future__ import annotations

EDGE_DOC_SLUG_OVERRIDES: dict[str, str] = {
    "CanConfigureRBCD": "rbcd",
    "WriteGPLink": "gp-link",
}

DOC_BASE = "https://bloodhound.specterops.io/resources/edges"


def edge_doc_url(edge_type: str) -> str | None:
    if not edge_type:
        return None
    slug = EDGE_DOC_SLUG_OVERRIDES.get(edge_type)
    if not slug:
        # Convert CamelCase/mixed tokens into kebab-case, preserving acronym groups.
        import re

        step1 = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1-\2", edge_type)
        step2 = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", step1)
        slug = step2.replace("_", "-").replace(" ", "-").lower()
    return f"{DOC_BASE}/{slug}"
