"""Loot management for discovered credentials and tickets."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re


HASH_LINE_RE = re.compile(
    r"^(?P<identity>(?:(?P<domain>[^\\/:\s]+)\\)?(?P<user>[^:]+)):(?P<rid>\d+):"
    r"(?P<lm>[0-9a-fA-F]{32}):(?P<ntlm>[0-9a-fA-F]{32}):",
)
PASSWORD_LINE_RE = re.compile(
    r"^(?:(?P<domain>[^\\/:\s]+)\\)?(?P<user>[A-Za-z0-9._$-]+):(?P<password>[^:\s].+)$",
)


@dataclass
class CredentialRecord:
    """Credential material tied to a principal identity."""

    principal: str
    username: str = ""
    domain: str = ""
    password: str = ""
    ntlm_hash: str = ""
    kerberos_ticket: str = ""
    source: str = "manual"

    @property
    def key(self) -> str:
        return self.principal.strip().casefold()


class LootManager:
    """In-memory credential store indexed by SID or username."""

    def __init__(self) -> None:
        self._records: dict[str, CredentialRecord] = {}

    def _normalize(self, value: str) -> str:
        return value.strip().casefold()

    def _normalize_principal(self, identity: str) -> set[str]:
        """Generate all normalized forms of a principal (SID, DOMAIN\\USER, USER@DOMAIN, etc.)."""
        normalized = self._normalize(identity)
        variants = {normalized}
        
        # Handle DOMAIN\USER format
        if "\\" in identity:
            domain, user = identity.split("\\", maxsplit=1)
            variants.add(self._normalize(user))
            variants.add(self._normalize(f"{domain}\\{user}"))
        
        # Handle USER@DOMAIN format -> convert to DOMAIN\USER
        if "@" in identity and "\\" not in identity:
            user, domain = identity.split("@", maxsplit=1)
            variants.add(self._normalize(user))
            variants.add(self._normalize(f"{domain}\\{user}"))
            variants.add(normalized)  # Keep original @ format too
        
        return variants

    def clear(self) -> None:
        """Remove all credential entries from the in-memory store."""
        self._records.clear()

    def upsert_credential(
        self,
        principal: str,
        username: str = "",
        domain: str = "",
        password: str = "",
        ntlm_hash: str = "",
        kerberos_ticket: str = "",
        source: str = "manual",
    ) -> CredentialRecord:
        """Create or update a credential entry."""
        cleaned_principal = principal.strip()
        if not cleaned_principal:
            raise ValueError("principal is required")

        key = self._normalize(cleaned_principal)
        existing = self._records.get(key)
        record = CredentialRecord(
            principal=cleaned_principal,
            username=(username or (existing.username if existing else "")).strip(),
            domain=(domain or (existing.domain if existing else "")).strip(),
            password=(password or (existing.password if existing else "")).strip(),
            ntlm_hash=(ntlm_hash or (existing.ntlm_hash if existing else "")).strip(),
            kerberos_ticket=(
                kerberos_ticket or (existing.kerberos_ticket if existing else "")
            ).strip(),
            source=(source or (existing.source if existing else "manual")).strip(),
        )
        self._records[key] = record
        return record

    def get_credential(self, identity: str) -> CredentialRecord | None:
        """Retrieve credential material by SID, username, or DOMAIN\\username or USER@DOMAIN."""
        if not identity:
            return None

        # Get all normalized variants of the search identity
        search_variants = self._normalize_principal(identity)
        
        # Check if any variant matches a stored record key
        for variant in search_variants:
            if variant in self._records:
                return self._records[variant]

        # Check if any variant matches parts of stored records
        for record in self._records.values():
            username = record.username.casefold()
            principal = record.principal.casefold()
            domain_user = f"{record.domain}\\{record.username}".casefold().strip("\\")
            record_variants = {username, principal, domain_user}
            
            # Check for any overlap between search variants and record variants
            if search_variants & record_variants:
                return record

        return None

    def all_credentials(self) -> list[dict[str, str]]:
        """Return all credential entries as UI-ready dictionaries."""
        rows = [asdict(record) for record in self._records.values()]
        rows.sort(key=lambda row: row["principal"].casefold())
        return rows

    def import_secrets_text(self, text: str) -> int:
        """Import credentials from secretsdump/cme grepable output."""
        imported = 0

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            hash_match = HASH_LINE_RE.match(line)
            if hash_match:
                domain = (hash_match.group("domain") or "").strip()
                username = hash_match.group("user").strip()
                principal = f"{domain}\\{username}".strip("\\")
                ntlm_hash = hash_match.group("ntlm").lower()
                self.upsert_credential(
                    principal=principal,
                    username=username,
                    domain=domain,
                    ntlm_hash=ntlm_hash,
                    source="import:hashdump",
                )
                imported += 1
                continue

            pwd_match = PASSWORD_LINE_RE.match(line)
            if pwd_match and "$" not in (pwd_match.group("user") or ""):
                domain = (pwd_match.group("domain") or "").strip()
                username = pwd_match.group("user").strip()
                password = pwd_match.group("password").strip()
                if password and len(password) < 256:
                    principal = f"{domain}\\{username}".strip("\\")
                    self.upsert_credential(
                        principal=principal,
                        username=username,
                        domain=domain,
                        password=password,
                        source="import:plaintext",
                    )
                    imported += 1

        return imported

    def build_auth_flags(self, identity: str) -> str:
        """Build Impacket-compatible authentication flags for an identity."""
        record = self.get_credential(identity)
        if record is None:
            return ""

        if record.ntlm_hash:
            return f"-hashes :{record.ntlm_hash}"
        if record.password:
            return f"-password '{record.password}'"
        if record.kerberos_ticket:
            return "-k -no-pass"
        return ""
