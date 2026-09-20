"""Privacy-preserving identity tokenization with authenticated encryption."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from cryptography.fernet import Fernet, InvalidToken

MINIMUM_HMAC_KEY_BYTES = 32
MAXIMUM_KEY_ID_LENGTH = 64
MINIMUM_PURPOSE_LENGTH = 5
MINIMUM_IDENTITY_LENGTH = 3
MAXIMUM_IDENTITY_LENGTH = 320


class IdentityType(StrEnum):
    EMAIL = "email"
    PHONE = "phone"
    GOVERNMENT_ID = "government_id"
    BANK_ACCOUNT = "bank_account"
    EXTERNAL_CUSTOMER_ID = "external_customer_id"


class VaultAccessError(PermissionError):
    """Raised when identity access is forbidden or cannot be authenticated."""


@dataclass(frozen=True, slots=True)
class IdentityRecord:
    token: str
    tenant_id: str
    identity_type: IdentityType
    ciphertext: str
    key_id: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class VaultPolicy:
    encryption_keys: Mapping[str, bytes]
    active_key_id: str
    hmac_key: bytes
    namespace: str = "aegisgraph"
    allow_detokenization: bool = False
    purpose_required: bool = True

    def __post_init__(self) -> None:
        if self.active_key_id not in self.encryption_keys:
            raise ValueError("active_key_id does not exist in encryption_keys")
        if len(self.hmac_key) < MINIMUM_HMAC_KEY_BYTES:
            raise ValueError("hmac_key must contain at least 32 bytes")
        if not self.namespace.strip():
            raise ValueError("namespace cannot be blank")
        for key_id, key in self.encryption_keys.items():
            if not key_id or len(key_id) > MAXIMUM_KEY_ID_LENGTH:
                raise ValueError("encryption key IDs must contain 1-64 characters")
            try:
                Fernet(key)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"encryption key {key_id!r} is not a valid Fernet key") from exc


AuditHook = Callable[[str, Mapping[str, object]], None]


class IdentityVault:
    """Create stable non-reversible tokens while keeping raw identity encrypted."""

    def __init__(self, policy: VaultPolicy, audit_hook: AuditHook | None = None) -> None:
        self._policy = policy
        self._audit_hook = audit_hook
        self._fernets = {key_id: Fernet(key) for key_id, key in policy.encryption_keys.items()}

    def protect(
        self, tenant_id: str, identity_type: IdentityType, raw_value: str
    ) -> IdentityRecord:
        normalized = self._normalize(identity_type, raw_value)
        self._validate_tenant(tenant_id)
        token = self._token(tenant_id, identity_type, normalized)
        payload = json.dumps(
            {
                "tenant_id": tenant_id,
                "identity_type": identity_type.value,
                "value": normalized,
                "token": token,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        key_id = self._policy.active_key_id
        ciphertext = self._fernets[key_id].encrypt(payload).decode("ascii")
        record = IdentityRecord(
            token=token,
            tenant_id=tenant_id,
            identity_type=identity_type,
            ciphertext=ciphertext,
            key_id=key_id,
            created_at=datetime.now(UTC),
        )
        self._audit("identity.protected", tenant_id, identity_type, token)
        return record

    def reveal(self, record: IdentityRecord, *, tenant_id: str, purpose: str) -> str:
        """Decrypt only when policy, tenant, purpose, and ciphertext binding all pass."""
        if not self._policy.allow_detokenization:
            raise VaultAccessError("identity detokenization is disabled")
        if record.tenant_id != tenant_id:
            raise VaultAccessError("cross-tenant identity access denied")
        if self._policy.purpose_required and len(purpose.strip()) < MINIMUM_PURPOSE_LENGTH:
            raise VaultAccessError("a specific access purpose is required")
        fernet = self._fernets.get(record.key_id)
        if fernet is None:
            raise VaultAccessError("identity encryption key is unavailable")
        try:
            payload = json.loads(fernet.decrypt(record.ciphertext.encode("ascii")).decode())
        except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultAccessError("identity ciphertext authentication failed") from exc
        expected = self._token(tenant_id, record.identity_type, str(payload.get("value", "")))
        bindings_valid = (
            payload.get("tenant_id") == tenant_id
            and payload.get("identity_type") == record.identity_type.value
            and payload.get("token") == record.token
            and hmac.compare_digest(expected, record.token)
        )
        if not bindings_valid:
            raise VaultAccessError("identity record binding validation failed")
        self._audit(
            "identity.revealed",
            tenant_id,
            record.identity_type,
            record.token,
            extra={"purpose_sha256": hashlib.sha256(purpose.strip().encode()).hexdigest()},
        )
        return str(payload["value"])

    def rotate(self, record: IdentityRecord, *, tenant_id: str, purpose: str) -> IdentityRecord:
        """Re-encrypt a record with the active key without changing its stable token."""
        raw_value = self.reveal(record, tenant_id=tenant_id, purpose=purpose)
        rotated = self.protect(tenant_id, record.identity_type, raw_value)
        if not hmac.compare_digest(rotated.token, record.token):
            raise RuntimeError("identity token changed during key rotation")
        return rotated

    def _token(self, tenant_id: str, identity_type: IdentityType, value: str) -> str:
        message = f"{self._policy.namespace}\x1f{tenant_id}\x1f{identity_type.value}\x1f{value}"
        digest = hmac.new(self._policy.hmac_key, message.encode(), hashlib.sha256).digest()
        return "agt_" + base64.urlsafe_b64encode(digest).decode().rstrip("=")

    @staticmethod
    def _normalize(identity_type: IdentityType, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).strip()
        if identity_type is IdentityType.EMAIL:
            normalized = normalized.casefold()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
                raise ValueError("email identity is invalid")
        elif identity_type is IdentityType.PHONE:
            normalized = "+" + re.sub(r"\D", "", normalized)
            if not re.fullmatch(r"\+[1-9]\d{7,14}", normalized):
                raise ValueError("phone identity must be in international format")
        elif not MINIMUM_IDENTITY_LENGTH <= len(normalized) <= MAXIMUM_IDENTITY_LENGTH:
            raise ValueError("identity value length is invalid")
        return normalized

    @staticmethod
    def _validate_tenant(tenant_id: str) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,63}", tenant_id):
            raise ValueError("tenant_id format is invalid")

    def _audit(
        self,
        action: str,
        tenant_id: str,
        identity_type: IdentityType,
        token: str,
        *,
        extra: Mapping[str, object] | None = None,
    ) -> None:
        if self._audit_hook is not None:
            self._audit_hook(
                action,
                {
                    "tenant_id": tenant_id,
                    "identity_type": identity_type.value,
                    "token_suffix": token[-8:],
                    **(extra or {}),
                },
            )
