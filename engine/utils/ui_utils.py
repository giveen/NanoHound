"""UI / documentation helpers for command providers.

Provides a small mapping for edge->doc slug overrides and an
`edge_doc_url` helper that providers or the UI can call to build a
help/documentation URL for an edge type.
"""
from __future__ import annotations

from typing import Optional

# Small override map extracted from legacy monolith; providers can extend
# or replace this mapping as needed.
EDGE_DOC_SLUG_OVERRIDES: dict[str, str] = {
    # Example: "ESC2": "pki-enroll-controlled-san-upn",
}

DOC_BASE = "https://docs.nanohound.local/edges"


def edge_doc_url(edge_type: str) -> Optional[str]:
    """Return a documentation URL for the given edge_type, or None.

    - If an override exists in `EDGE_DOC_SLUG_OVERRIDES`, that slug is used.
    - Otherwise, a conservative slug is generated from the edge_type.
    """
    if not edge_type:
        return None
    slug = EDGE_DOC_SLUG_OVERRIDES.get(edge_type)
    if not slug:
        slug = str(edge_type).strip().lower().replace(" ", "-")
    return f"{DOC_BASE}/{slug}"
