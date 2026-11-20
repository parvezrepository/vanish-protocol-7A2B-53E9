"""Manifest representation and canonical CBOR serialization for VANISH.

The Manifest encapsulates the file identity, cryptographic hashes, lifecycle timestamps,
and expiration policies.
"""

from __future__ import annotations

import mimetypes
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import cbor2

from vanish.constants import ExpiryPolicy
from vanish.crypto import compute_sha256
from vanish.exceptions import PayloadIntegrityError

MANIFEST_PROTOCOL_STRING = "VANISH/1.0"


@dataclass(frozen=True)
class Manifest:
    """Immutable representation of a signed VANISH manifest policy."""

    protocol: str
    file_id: str
    original_name: str
    mime_type: str
    payload_hash: bytes
    issued_at: int
    expires_at: int
    expiry_policy: int = int(ExpiryPolicy.AUTO_UNLINK)
    issuer: str = "VANISH-CLI"
    max_open_count: int | None = None
    custom_metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        payload_bytes: bytes,
        original_name: str,
        issued_at: int,
        expires_at: int,
        mime_type: str | None = None,
        file_id: str | None = None,
        expiry_policy: ExpiryPolicy = ExpiryPolicy.AUTO_UNLINK,
        issuer: str = "VANISH-CLI",
        max_open_count: int | None = None,
        custom_metadata: dict[str, Any] | None = None,
    ) -> Manifest:
        """Create a new Manifest instance with auto-computed payload hash and MIME type."""
        if expires_at <= issued_at:
            raise ValueError(
                f"expires_at ({expires_at}) must be strictly greater than issued_at ({issued_at})"
            )

        computed_hash = compute_sha256(payload_bytes)

        if not mime_type:
            guessed, _ = mimetypes.guess_type(original_name)
            mime_type = guessed or "application/octet-stream"

        assigned_id = file_id or str(uuid.uuid4())

        return cls(
            protocol=MANIFEST_PROTOCOL_STRING,
            file_id=assigned_id,
            original_name=original_name,
            mime_type=mime_type,
            payload_hash=computed_hash,
            issued_at=issued_at,
            expires_at=expires_at,
            expiry_policy=int(expiry_policy),
            issuer=issuer,
            max_open_count=max_open_count,
            custom_metadata=custom_metadata or {},
        )

    def to_cbor(self) -> bytes:
        """Serialize manifest to canonical CBOR bytes (RFC 8949).

        Canonical sorting ensures deterministic byte output, required for
        tamper-proof digital signatures.
        """
        data = {
            "protocol": self.protocol,
            "file_id": self.file_id,
            "original_name": self.original_name,
            "mime_type": self.mime_type,
            "payload_hash": self.payload_hash,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "expiry_policy": self.expiry_policy,
            "issuer": self.issuer,
            "max_open_count": self.max_open_count,
            "custom_metadata": self.custom_metadata,
        }
        # canonical=True ensures map keys are sorted deterministically
        return cbor2.dumps(data, canonical=True)

    @classmethod
    def from_cbor(cls, cbor_bytes: bytes) -> Manifest:
        """Deserialize and validate a canonical CBOR-encoded manifest."""
        data = cbor2.loads(cbor_bytes)
        if not isinstance(data, dict):
            raise ValueError("Manifest CBOR root must be a map/dictionary")

        required_keys = (
            "protocol",
            "file_id",
            "original_name",
            "mime_type",
            "payload_hash",
            "issued_at",
            "expires_at",
        )
        for key in required_keys:
            if key not in data:
                raise ValueError(f"Missing required manifest field: '{key}'")

        if data["protocol"] != MANIFEST_PROTOCOL_STRING:
            raise ValueError(
                f"Unsupported protocol version: expected {MANIFEST_PROTOCOL_STRING}, got {data['protocol']}"
            )

        return cls(
            protocol=str(data["protocol"]),
            file_id=str(data["file_id"]),
            original_name=str(data["original_name"]),
            mime_type=str(data["mime_type"]),
            payload_hash=bytes(data["payload_hash"]),
            issued_at=int(data["issued_at"]),
            expires_at=int(data["expires_at"]),
            expiry_policy=int(data.get("expiry_policy", ExpiryPolicy.AUTO_UNLINK)),
            issuer=str(data.get("issuer", "UNKNOWN")),
            max_open_count=data.get("max_open_count"),
            custom_metadata=data.get("custom_metadata", {}),
        )

    def verify_payload_integrity(self, payload_bytes: bytes) -> None:
        """Verify that the payload SHA-256 matches the manifest commitment.

        Raises:
            PayloadIntegrityError: If calculated hash does not match committed hash.
        """
        calculated_hash = compute_sha256(payload_bytes)
        if calculated_hash != self.payload_hash:
            raise PayloadIntegrityError(
                "Payload integrity check failed: digest mismatch",
                details=f"expected={self.payload_hash.hex()}, computed={calculated_hash.hex()}",
            )

    def remaining_seconds(self, current_time: int) -> int:
        """Compute remaining valid lifetime in seconds. Returns negative value if expired."""
        return self.expires_at - current_time

    def is_expired(self, current_time: int) -> bool:
        """Check if file has passed expiration timestamp."""
        return current_time >= self.expires_at
