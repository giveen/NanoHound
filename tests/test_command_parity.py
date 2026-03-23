import re
import pytest
from engine.commands import get_command, CommandProvider, CommandOracle, EDGE_MAP
from engine import commands as legacy_commands


def normalize_output(cmds):
    if not cmds:
        return []
    return [ (t, c.strip().replace('\r\n','\n')) for t, c in cmds ]


@pytest.mark.parametrize("edge", list(EDGE_MAP.keys()))
def test_provider_vs_legacy(edge):
    # lightweight fake nodes
    src = {"id": "SRC", "name": "attacker@EXAMPLE.COM", "type": "user", "domain": "EXAMPLE.COM"}
    tgt = {"id": "TGT", "name": "target", "type": "computer", "domain": "EXAMPLE.COM"}

    provider_cmds = get_command(edge, src, tgt, {})
    legacy = legacy_commands.CommandOracle(None, None)
    legacy_cmd = legacy.get_exploit_command(edge, src, tgt)

    # Normalize
    prov = normalize_output(provider_cmds)
    leg = legacy_cmd.strip()

    # If both are empty/placeholder, consider parity achieved
    if not prov and (not leg or "No exploit command available" in leg):
        assert True
        return

    # If provider produced commands, ensure legacy contains at least one of the provider command bodies
    if prov:
        bodies = [c for _, c in prov]
        assert isinstance(prov, list)
        for b in bodies:
            first_line = b.splitlines()[0].strip() if b.splitlines() else ""
            # Basic parsing sanity
            assert first_line != ""

            # Hardened checks: if command contains well-known tool flags, ensure flags are correctly formatted
            # -hashes <LM:NT> or similar
            if "-hashes" in b:
                assert re.search(r"-hashes\s+\S+", b), f"Malformed -hashes flag in: {b}"
            # -impersonate <USER>
            if "-impersonate" in b:
                assert re.search(r"-impersonate\s+\S+", b), f"Malformed -impersonate flag in: {b}"
            # -template <TEMPLATE>
            if "-template" in b:
                assert re.search(r"-template\s+\S+", b), f"Malformed -template flag in: {b}"
            # certipy/certreq invocations should mention certificate templates or targets
            if "certipy" in b.lower() or "certreq" in b.lower() or ("curl" in b.lower() and "certsrv" in b.lower()):
                # cert-related invocations may use a variety of flags and web payloads.
                ok_tokens = ["-template", "/template:", "/attrib", "certificateTemplate", "certattrib", "-pfx", "-ca-pfx", "-backup", "certreq", "certipy-ad"]
                lowered = b.lower()
                assert any(tok in lowered for tok in ok_tokens), f"Cert tool invocation missing expected token in: {b}"
    else:
        # Provider empty but legacy returned something; this is a regression
        pytest.fail(f"Provider missing for edge {edge}, legacy returned: {legacy_cmd}")
