"""Command provider registry and CommandOracle facade.

Providers register with `@CommandProvider.register("key")` and must
implement `generate(source: dict, target: dict, ctx: dict) -> list[tuple[str,str]]`.

This module exposes `EDGE_MAP` mapping bloodhound-style edge keys to
provider registration keys and a convenience `get_command(edge_type, ...)`
function that looks up the provider and returns generated commands.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Tuple, Any
import logging
import importlib
from pathlib import Path
from engine.utils import ad_utils, network_utils
from engine.utils import node_utils, pki_utils

log = logging.getLogger("nanohound.commands.provider")

ProviderFunc = Callable[[dict, dict, str, dict, dict], List[Tuple[str, str]]]


# Note: legacy `NodeContext` and protection-check logic were moved to
# `engine.utils.ad_utils` as part of removing compatibility shims.


class CommandProvider:
    _registry: Dict[str, Any] = {}
    # Utilities exposed to providers (convenience namespace)
    utils = type("_Utils", (), {})()


    @classmethod
    def register(cls, name: str):
        def _dec(fn: Any):
            cls._registry[name] = fn
            return fn

        return _dec

    @classmethod
    def get(cls, name: str) -> Any | None:
        return cls._registry.get(name)


# Map BloodHound edge keys (normalized) to provider registration keys.
# Extend this mapping to include all edges and their provider modules.
EDGE_MAP: dict[str, str] = {
    # AD-standard provider
    "DCSync": "ad_standard",
    "GetChanges": "ad_standard",
    "GetChangesAll": "ad_standard",
    "GetChangesInFilteredSet": "ad_standard",
    "SyncLAPSPassword": "ad_standard",
    "SyncedToADUser": "ad_standard",
    "SyncedToEntraUser": "ad_standard",
    "ReadGMSAPassword": "ad_standard",
    "ReadLAPSPassword": "ad_standard",
    "PublishedTo": "ad_standard",
    "Contains": "ad_standard",
    "MemberOf": "ad_standard",
    "HasSession": "ad_standard",
    "AdminTo": "ad_standard",
    "CanRDP": "ad_standard",
    "GenericWrite": "ad_standard",
    "GenericAll": "ad_standard",
    "AllExtendedRights": "ad_standard",

    # Delegation-related
    "CanConfigureRBCD": "delegation",
    "AllowedToDelegate": "delegation",
    "RBCD": "delegation",
    "AllowedToAuth": "delegation",

    # PKI/ADCS edges
    "ESC1": "pki",
    "ESC2": "pki",
    "ESC3": "pki",
    "ESC4": "pki",
    "ESC5": "pki",
    "ESC6": "pki",
    "ESC7": "pki",
    "ESC8": "pki",
    "ESC9": "pki",
    "ESC10": "pki",
    "ESC11": "pki",
    "ESC12": "pki",
    "ESC13": "pki",

    # GPO abuse
    "GPLink": "gpo_abuse",
    "GPPPassword": "gpo_abuse",
    # Miscellaneous legacy edges
    "SQLAdmin": "misc_exploits",
    "ExecuteDCOM": "misc_exploits",
    "DumpSMSAPassword": "misc_exploits",
}


def _discover_providers():
    """Auto-import all provider modules in the engine.commands package so
    they can register themselves via `@CommandProvider.register`.
    """
    pkg_dir = Path(__file__).parent
    for p in pkg_dir.glob("*.py"):
        if p.name in ("__init__.py", "commands.py") or p.name.startswith("_"):
            continue
        mod_name = f"engine.commands.{p.stem}"
        try:
            importlib.import_module(mod_name)
        except Exception:
            log.debug("Failed to import provider module %s", mod_name, exc_info=True)


# Attach utility modules to CommandProvider.utils for provider convenience
try:
    CommandProvider.utils.ad = ad_utils
    CommandProvider.utils.network = network_utils
    CommandProvider.utils.node = node_utils
    CommandProvider.utils.pki = pki_utils
except Exception:
    log.debug("Failed to attach utils to CommandProvider", exc_info=True)


_discover_providers()


def get_command(edge_type: str, source: dict, target: dict, creds: dict | None = None) -> List[Tuple[str, str]]:
    """Lookup provider for the given edge_type and call its generate function.

    - `edge_type` : BloodHound edge name
    - `source`/`target` : node dicts
    - `creds` : optional context dict passed to provider
    """
    creds = creds or {}
    provider_key = EDGE_MAP.get(edge_type)
    if not provider_key:
        log.debug("No provider mapped for edge_type=%s", edge_type)
        return []

    # Ensure provider module is imported (in case discovery missed it)
    try:
        if provider_key not in CommandProvider._registry:
            importlib.import_module(f"engine.commands.{provider_key}")
    except Exception:
        log.debug("Could not import provider module engine.commands.%s", provider_key, exc_info=True)

    provider = CommandProvider.get(provider_key)
    if not provider:
        log.debug("Provider %s not registered for edge_type=%s", provider_key, edge_type)
        return []

    # Derive domain and network context for provider interface
    domain = source.get("domain") or target.get("domain") or creds.get("domain") if isinstance(creds, dict) else "<DOMAIN>"
    network_context = creds.get("network_context") if isinstance(creds, dict) else {}

    try:
        # Ensure the provider sees the edge type in the creds context
        call_creds = dict(creds) if isinstance(creds, dict) else {}
        call_creds.setdefault("edge", edge_type)
        # Providers may be simple callables or classes exposing `generate`
        if callable(provider):
            return provider(source, target, domain, call_creds, network_context or {})
        if hasattr(provider, "generate") and callable(getattr(provider, "generate")):
            return provider.generate(source, target, domain, call_creds, network_context or {})
        log.debug("Provider %s has no callable interface", provider_key)
        return []
    except Exception:
        log.exception("Provider %s failed for edge=%s", provider_key, edge_type)
        return []


class CommandOracle:
    """Lightweight facade used by the UI/backends to generate commands.

    This wraps `get_command` but preserves the old constructor signature so
    existing imports remain compatible.
    """

    def __init__(self, loot_manager=None, graph_engine=None):
        self.loot_manager = loot_manager
        self.graph_engine = graph_engine
        # No legacy monolith fallback — this oracle uses the modular providers only.

    def get_command(self, edge_type: str, source: dict, target: dict, creds: dict | None = None) -> List[Tuple[str, str]]:
        return get_command(edge_type, source, target, creds)

    # Compatibility layer: mirror legacy CommandOracle API expected by app.py
    def get_exploit_command(self, edge_type: str, source_node: dict, target_node: dict) -> str:
        # Prefer modular providers first (new canonical source)
        try:
            cmds = get_command(edge_type, source_node, target_node, None)
            if cmds:
                return "\n\n".join(f"# {t}\n{c}" for t, c in cmds)
        except Exception:
            log.exception("Provider get_command failed for edge=%s", edge_type)

        # If providers yielded nothing, attempt lightweight suppression logic
        # for Protected Users to mimic legacy monolith behavior when the
        # legacy oracle cannot be loaded.
        try:
            pt_h_prone = {
                "CanRDP",
                "CanPSRemote",
                "CoerceAndRelayNTLMToADCS",
                "CoerceAndRelayNTLMToLDAP",
                "CoerceAndRelayNTLMToLDAPS",
                "CoerceAndRelayNTLMToSMB",
                "CoerceToTGT",
                "GenericAll",
                "GenericWrite",
                "AllExtendedRights",
                "CoerceAndRelayNTLMToADCS",
            }
            if ad_utils.is_protected_user(self.graph_engine, target_node) and (edge_type in pt_h_prone):
                return (
                    "# Protected Users: NTLM hash relay / pass-the-hash is ineffective\n"
                    "# These principals are protected; avoid suggesting PtH/overpass flows.\n"
                    "# Suggested alternatives: interactive authentication (RDP/console), certificate-based auth (PKINIT), or modifying group membership via an administrative account."
                )
        except Exception:
            pass

        return "# No exploit command available"

    def get_edge_documentation_url(self, edge_type: str) -> str | None:
        # Providers or UI helpers should supply documentation links; none available here.
        return None

    def get_kerberoast_command(self, target_node: dict) -> str:
        cmds = get_command("Kerberoast", target_node, target_node, None)
        return cmds[0][1] if cmds else ""

    def is_exploitation_edge(self, edge_type: str) -> bool:
        # Conservative behavior: exploitation edges are those we have providers for.
        return edge_type in EDGE_MAP and EDGE_MAP.get(edge_type) is not None

    def build_pathway_context(self, path_edges: list[tuple[str, str, str]]) -> str:
        return "# Pathway context unavailable"

    def get_node_recon_guidance(self, node: dict) -> str:
        return "# Node recon guidance unavailable"

    # NOTE: compatibility protection checks live in engine.utils.ad_utils.is_protected_user

    # No __getattr__ delegation — legacy monolith removed.
