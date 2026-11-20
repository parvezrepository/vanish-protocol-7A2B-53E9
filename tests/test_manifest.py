"""Tests for Manifest serialization and CBOR compliance."""

import pytest
from vanish.constants import ExpiryPolicy
from vanish.crypto import compute_sha256
from vanish.exceptions import PayloadIntegrityError
from vanish.manifest import Manifest


def test_manifest_creation_and_cbor_roundtrip() -> None:
    payload = b"Hello VANISH Protocol Research Paper"
    issued_at = 1700000000
    expires_at = 1700003600

    manifest = Manifest.create(
        payload_bytes=payload,
        original_name="test.txt",
        issued_at=issued_at,
        expires_at=expires_at,
        expiry_policy=ExpiryPolicy.SECURE_SHRED,
        issuer="TEST-AUTHORITY",
        custom_metadata={"classification": "RESTRICTED"},
    )

    cbor_bytes = manifest.to_cbor()
    assert isinstance(cbor_bytes, bytes)

    reconstructed = Manifest.from_cbor(cbor_bytes)
    assert reconstructed.protocol == "VANISH/1.0"
    assert reconstructed.original_name == "test.txt"
    assert reconstructed.mime_type == "text/plain"
    assert reconstructed.issued_at == issued_at
    assert reconstructed.expires_at == expires_at
    assert reconstructed.expiry_policy == int(ExpiryPolicy.SECURE_SHRED)
    assert reconstructed.issuer == "TEST-AUTHORITY"
    assert reconstructed.custom_metadata == {"classification": "RESTRICTED"}
    assert reconstructed.payload_hash == compute_sha256(payload)


def test_manifest_invalid_expiry_timestamp() -> None:
    payload = b"Data"
    # expires_at <= issued_at must be rejected
    with pytest.raises(ValueError):
        Manifest.create(
            payload_bytes=payload,
            original_name="invalid.txt",
            issued_at=1000,
            expires_at=999,
        )


def test_manifest_payload_integrity_check() -> None:
    payload = b"Original accurate content"
    manifest = Manifest.create(
        payload_bytes=payload,
        original_name="doc.txt",
        issued_at=100,
        expires_at=200,
    )

    # Valid payload
    manifest.verify_payload_integrity(payload)

    # Tampered payload must raise PayloadIntegrityError
    with pytest.raises(PayloadIntegrityError):
        manifest.verify_payload_integrity(b"Altered content")


def test_manifest_remaining_seconds_and_expiration() -> None:
    manifest = Manifest.create(
        payload_bytes=b"data",
        original_name="data.bin",
        issued_at=1000,
        expires_at=2000,
    )

    assert manifest.remaining_seconds(current_time=1500) == 500
    assert not manifest.is_expired(current_time=1500)

    assert manifest.remaining_seconds(current_time=2000) == 0
    assert manifest.is_expired(current_time=2000)

    assert manifest.remaining_seconds(current_time=2500) == -500
    assert manifest.is_expired(current_time=2500)
