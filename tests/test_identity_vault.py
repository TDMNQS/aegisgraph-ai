"""Tests for stable tokenization, access policy, encryption, and key rotation."""

from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.fernet import Fernet

from app.services.identity_vault import (
    IdentityType,
    IdentityVault,
    VaultAccessError,
    VaultPolicy,
)


def _policy(*, allow: bool, active: str = "v1") -> VaultPolicy:
    return VaultPolicy(
        encryption_keys={"v1": Fernet.generate_key(), "v2": Fernet.generate_key()},
        active_key_id=active,
        hmac_key=b"independent-test-hmac-key-32-bytes-minimum",
        namespace="test",
        allow_detokenization=allow,
    )


def test_token_is_stable_but_ciphertext_is_randomized() -> None:
    vault = IdentityVault(_policy(allow=True))
    first = vault.protect("demo-bank", IdentityType.EMAIL, " Analyst@Example.COM ")
    second = vault.protect("demo-bank", IdentityType.EMAIL, "analyst@example.com")

    assert first.token == second.token
    assert first.ciphertext != second.ciphertext
    assert "analyst@example.com" not in first.ciphertext
    assert vault.reveal(first, tenant_id="demo-bank", purpose="fraud investigation") == (
        "analyst@example.com"
    )


def test_detokenization_is_disabled_by_default() -> None:
    vault = IdentityVault(_policy(allow=False))
    record = vault.protect("demo-bank", IdentityType.PHONE, "+91 98765 43210")

    with pytest.raises(VaultAccessError, match="disabled"):
        vault.reveal(record, tenant_id="demo-bank", purpose="support request")


def test_cross_tenant_and_tampered_ciphertext_are_rejected() -> None:
    vault = IdentityVault(_policy(allow=True))
    record = vault.protect("demo-bank", IdentityType.BANK_ACCOUNT, "ACCT-00991")

    with pytest.raises(VaultAccessError, match="cross-tenant"):
        vault.reveal(record, tenant_id="other-bank", purpose="fraud investigation")

    tampered = replace(record, ciphertext=record.ciphertext[:-3] + "abc")
    with pytest.raises(VaultAccessError, match="authentication"):
        vault.reveal(tampered, tenant_id="demo-bank", purpose="fraud investigation")


def test_audit_hook_never_receives_raw_identity() -> None:
    observed: list[tuple[str, dict[str, object]]] = []
    vault = IdentityVault(
        _policy(allow=True),
        audit_hook=lambda action, metadata: observed.append((action, dict(metadata))),
    )
    vault.protect("demo-bank", IdentityType.GOVERNMENT_ID, "ID-SECRET-991")

    serialized = repr(observed)
    assert "ID-SECRET-991" not in serialized
    assert observed[0][0] == "identity.protected"
