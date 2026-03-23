from __future__ import annotations

from typing import Any
from engine.commands import CommandProvider

# EDGE_DOC_SLUG_OVERRIDES maps internal edge names to doc slugs when they differ
EDGE_DOC_SLUG_OVERRIDES: dict[str, str] = {
    "CanConfigureRBCD": "rbcd",
    "WriteGPLink": "gp-link",
}


def edge_doc_url(edge_type: str) -> str | None:
    slug = EDGE_DOC_SLUG_OVERRIDES.get(edge_type, edge_type).lower()
    return f"https://nanohound.docs.example.com/edges/{slug}"


def build_pathway_context(path_edges: list[tuple[str, str, str]]) -> str:
    """Build a concise textual pathway context from edges.

    path_edges: list of (edge, source_id, target_id)
    """
    lines = ["# Pathway Context"]
    for edge, src, tgt in path_edges:
        lines.append(f"- {edge}: {src} -> {tgt}")
    return "\n".join(lines)


def get_node_recon_guidance(node: dict[str, Any]) -> str:
    """Simple recon guidance generator for a given node dictionary."""
    name = node.get("name") or "<NODE>"
    node_type = node.get("type") or "entity"
    lines = [f"# Recon guidance for {name} ({node_type})"]
    if node_type == "computer":
        lines.append("- Run nmap for open services: nmap -sS -p- <HOST>")
        lines.append("- Check SMB signing and version: smbclient -L <HOST>")
    if node_type == "user":
        lines.append("- Enumerate membership: Get-ADPrincipalGroupMembership <USER>")
        lines.append("- Check lastLogonTimestamp/pwdLastSet attributes")
    return "\n".join(lines)


def generate_markdown_report(path_nodes: list[str], graph: Any, oracle: Any) -> str:
    """Generate a step-by-step markdown attack path report.

    - `path_nodes`: ordered list of node ids (source -> ... -> target)
    - `graph`: networkx graph instance
    - `oracle`: CommandOracle instance exposing `get_command(edge, src_node, tgt_node)`
    """
    lines: list[str] = ["# Attack Path Report", ""]
    # attempt to access notes store if available
    try:
        from engine import state as _est

        notes = getattr(_est, "notes_store", None)
    except Exception:
        notes = None

    for idx in range(len(path_nodes) - 1):
        src = path_nodes[idx]
        tgt = path_nodes[idx + 1]
        edge_data = {}
        try:
            # networkx single edge or multiedge
            ed = graph.get_edge_data(src, tgt) or {}
            if isinstance(ed, dict):
                # pick first entry if multigraph dict
                if "0" in ed and isinstance(ed["0"], dict):
                    edge_data = ed.get("0")
                else:
                    # when single edge stored as dict
                    edge_data = ed
        except Exception:
            edge_data = {}

        edge_type = str(edge_data.get("relationship") or edge_data.get("raw_right") or "unknown")
        src_node = graph.nodes.get(src, {})
        tgt_node = graph.nodes.get(tgt, {})

        lines.append(f"## Step {idx + 1}: {src_node.get('name', src)} -> {tgt_node.get('name', tgt)} via {edge_type}")

        # recommended command(s)
        try:
            cmds = oracle.get_command(edge_type, src_node, tgt_node, None)
            if cmds:
                for title, cmd in cmds:
                    lines.append(f"**{title}**")
                    lines.append("```bash")
                    lines.append(cmd)
                    lines.append("```")
            else:
                lines.append("*No recommended command available*")
        except Exception:
            lines.append("*Failed to generate recommended command*")

        # any manual notes
        try:
            src_note = notes.get_note(src) if notes else None
            tgt_note = notes.get_note(tgt) if notes else None
            if src_note:
                lines.append(f"**Note ({src_node.get('name', src)}):**")
                # Wrap free-form notes in a fenced code block to avoid breaking Markdown tables/layout
                lines.append("```text")
                lines.append(src_note)
                lines.append("```")
            if tgt_note:
                lines.append(f"**Note ({tgt_node.get('name', tgt)}):**")
                lines.append("```text")
                lines.append(tgt_note)
                lines.append("```")
        except Exception:
            pass

        lines.append("")

    return "\n".join(lines)


# Register minimal recon provider to expose functions to callers
@CommandProvider.register("recon")
def generate(source: dict, target: dict, domain: str | None = None, creds: dict | None = None, network_context: dict | None = None):
    # This provider isn't a traditional edge handler; it's a util to expose recon functions
    return [("Node Recon", get_node_recon_guidance(source or {})), ("Pathway Context", build_pathway_context(creds.get("path_edges", []) if creds else []))]
