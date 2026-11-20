"""Binary container format parser and serializer for .vfile files."""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.asymmetric import ed25519

from vanish.constants import (
    CONTAINER_MAGIC,
    ED25519_PUBLIC_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
    FIXED_HEADER_SIZE,
    FLAG_ENCRYPTED,
    FLAG_MONOTONIC_REQ,
    FLAG_ONE_TIME_READ,
    FLAG_SECURE_SHRED,
    PROTOCOL_VERSION,
)
from vanish.crypto import (
    compute_sha256,
    decrypt_payload_aes_gcm,
    encrypt_payload_aes_gcm,
    public_key_from_raw_bytes,
    public_key_to_raw_bytes,
    sign_digest,
    verify_signature,
)
from vanish.exceptions import (
    ContainerFormatError,
    SignatureVerificationError,
)
from vanish.manifest import Manifest
from vanish.time_checker import TimeChecker

# Header format string (Big-Endian):
# 4s (magic: VAN1)
# H (version: uint16)
# H (flags: uint16)
# I (manifest_len: uint32)
# Q (payload_len: uint64)
# H (sig_len: uint16)
# H (pubkey_len: uint16)
# H (nonce_len: uint16)
# 6s (reserved: 6 bytes)
# Total = 4 + 2 + 2 + 4 + 8 + 2 + 2 + 2 + 6 = 32 bytes
HEADER_STRUCT_FORMAT = ">4sHHIQHHH6s"


@dataclass
class ContainerHeader:
    """Fixed-size 32-byte binary container header."""

    magic: bytes
    version: int
    flags: int
    manifest_len: int
    payload_len: int
    sig_len: int
    pubkey_len: int
    nonce_len: int
    reserved: bytes = b"\x00" * 6

    def pack(self) -> bytes:
        """Pack header fields into canonical 32-byte struct."""
        return struct.pack(
            HEADER_STRUCT_FORMAT,
            self.magic,
            self.version,
            self.flags,
            self.manifest_len,
            self.payload_len,
            self.sig_len,
            self.pubkey_len,
            self.nonce_len,
            self.reserved,
        )

    @classmethod
    def unpack(cls, data: bytes) -> ContainerHeader:
        """Parse 32-byte binary header, performing strict field validation."""
        if len(data) != FIXED_HEADER_SIZE:
            raise ContainerFormatError(
                f"Invalid header size: expected {FIXED_HEADER_SIZE} bytes, got {len(data)}"
            )

        magic, version, flags, manifest_len, payload_len, sig_len, pubkey_len, nonce_len, reserved = (
            struct.unpack(HEADER_STRUCT_FORMAT, data)
        )

        if magic != CONTAINER_MAGIC:
            raise ContainerFormatError(
                f"Invalid magic bytes: expected {CONTAINER_MAGIC!r}, got {magic!r}"
            )

        if version != PROTOCOL_VERSION:
            raise ContainerFormatError(
                f"Unsupported container version {version} (expected {PROTOCOL_VERSION})"
            )

        return cls(
            magic=magic,
            version=version,
            flags=flags,
            manifest_len=manifest_len,
            payload_len=payload_len,
            sig_len=sig_len,
            pubkey_len=pubkey_len,
            nonce_len=nonce_len,
            reserved=reserved,
        )


class VanishContainer:
    """Represents a complete in-memory or on-disk .vfile container."""

    def __init__(
        self,
        header: ContainerHeader,
        manifest: Manifest,
        payload: bytes,
        signature: bytes,
        public_key_bytes: bytes,
        nonce: bytes = b"",
    ) -> None:
        self.header = header
        self.manifest = manifest
        self.payload = payload
        self.signature = signature
        self.public_key_bytes = public_key_bytes
        self.nonce = nonce

    @property
    def is_encrypted(self) -> bool:
        """Check if container payload is encrypted."""
        return bool(self.header.flags & FLAG_ENCRYPTED)

    @property
    def requires_monotonic(self) -> bool:
        """Check if monotonic clock verification is mandated."""
        return bool(self.header.flags & FLAG_MONOTONIC_REQ)

    @property
    def requires_secure_shred(self) -> bool:
        """Check if secure disk overwriting is mandated upon expiration."""
        return bool(self.header.flags & FLAG_SECURE_SHRED)

    @property
    def is_one_time_read(self) -> bool:
        """Check if container must self-destruct immediately after first read."""
        return bool(self.header.flags & FLAG_ONE_TIME_READ)

    def compute_signing_digest(self) -> bytes:
        """Calculate the cryptographic signing preimage digest.

        Binds the full 32-byte container header (including version, flags, and dimensions),
        the embedded public key, the nonce, the canonical CBOR manifest bytes,
        and the SHA-256 hash of the payload.
        """
        raw_header = self.header.pack()
        manifest_bytes = self.manifest.to_cbor()
        payload_hash = compute_sha256(self.payload)

        hasher = io.BytesIO()
        hasher.write(raw_header)
        hasher.write(self.public_key_bytes)
        hasher.write(self.nonce)
        hasher.write(manifest_bytes)
        hasher.write(payload_hash)
        return compute_sha256(hasher.getvalue())

    def serialize(self) -> bytes:
        """Serialize the entire container into binary .vfile representation."""
        buf = io.BytesIO()
        # 1. Header (32 bytes)
        buf.write(self.header.pack())
        # 2. Public Key
        buf.write(self.public_key_bytes)
        # 3. Nonce
        buf.write(self.nonce)
        # 4. Digital Signature
        buf.write(self.signature)
        # 5. Manifest (CBOR)
        buf.write(self.manifest.to_cbor())
        # 6. Payload
        buf.write(self.payload)
        return buf.getvalue()

    def save_to_file(self, path: Path | str) -> None:
        """Write binary container to disk atomically."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temp_target = target.with_suffix(".vtmp")
        temp_target.write_bytes(self.serialize())
        temp_target.replace(target)

    @classmethod
    def read_from_stream(cls, stream: BinaryIO) -> VanishContainer:
        """Parse a container from an open binary file stream."""
        header_bytes = stream.read(FIXED_HEADER_SIZE)
        if len(header_bytes) < FIXED_HEADER_SIZE:
            raise ContainerFormatError("Stream truncated while reading container header")

        header = ContainerHeader.unpack(header_bytes)

        # Read Public Key
        pubkey_bytes = stream.read(header.pubkey_len)
        if len(pubkey_bytes) != header.pubkey_len:
            raise ContainerFormatError("Truncated public key segment")

        # Read Nonce
        nonce_bytes = stream.read(header.nonce_len)
        if len(nonce_bytes) != header.nonce_len:
            raise ContainerFormatError("Truncated nonce segment")

        # Read Signature
        sig_bytes = stream.read(header.sig_len)
        if len(sig_bytes) != header.sig_len:
            raise ContainerFormatError("Truncated signature segment")

        # Read Manifest
        manifest_raw = stream.read(header.manifest_len)
        if len(manifest_raw) != header.manifest_len:
            raise ContainerFormatError("Truncated manifest segment")

        try:
            manifest = Manifest.from_cbor(manifest_raw)
        except Exception as exc:
            raise ContainerFormatError(f"Corrupt manifest: {exc}") from exc

        # Read Payload
        payload_bytes = stream.read(header.payload_len)
        if len(payload_bytes) != header.payload_len:
            raise ContainerFormatError(
                f"Truncated payload segment: expected {header.payload_len}, got {len(payload_bytes)}"
            )

        return cls(
            header=header,
            manifest=manifest,
            payload=payload_bytes,
            signature=sig_bytes,
            public_key_bytes=pubkey_bytes,
            nonce=nonce_bytes,
        )

    @classmethod
    def load_from_file(cls, path: Path | str) -> VanishContainer:
        """Load and parse container from file path."""
        target = Path(path)
        if not target.is_file():
            raise FileNotFoundError(f"Container file not found: {target}")
        with open(target, "rb") as f:
            return cls.read_from_stream(f)

    def verify_authenticity(
        self,
        trusted_public_key: ed25519.Ed25519PublicKey | None = None,
    ) -> None:
        """Verify the digital signature of the container.

        If trusted_public_key is provided, verifies that the embedded signature matches it.
        Otherwise, verifies using the embedded public key within the container.
        """
        if trusted_public_key is not None:
            pubkey = trusted_public_key
        else:
            if not self.public_key_bytes:
                raise SignatureVerificationError("Container lacks embedded public key and none provided")
            pubkey = public_key_from_raw_bytes(self.public_key_bytes)

        digest = self.compute_signing_digest()
        verify_signature(pubkey, self.signature, digest)

    def extract_plaintext_payload(
        self,
        aes_key: bytes | None = None,
        time_checker: TimeChecker | None = None,
        current_time: int | None = None,
    ) -> bytes:
        """Validate expiry, decrypt if needed, verify payload hash, and return original payload.

        Raises:
            ExpiredFileError: If file lifetime has elapsed.
            SignatureVerificationError: If container is forged.
            PayloadIntegrityError: If payload hash doesn't match manifest.
            DecryptionError: If encrypted payload fails AEAD authentication.
        """
        checker = time_checker or TimeChecker()
        checker.validate_expiry(
            issued_at=self.manifest.issued_at,
            expires_at=self.manifest.expires_at,
            current_time=current_time,
            require_monotonic_check=self.requires_monotonic,
        )

        # Decrypt if container is encrypted
        if self.is_encrypted:
            if aes_key is None:
                raise ValueError("Payload is encrypted but no AES decryption key was provided")
            associated_data = self.manifest.payload_hash
            raw_payload = decrypt_payload_aes_gcm(
                key=aes_key,
                nonce=self.nonce,
                ciphertext=self.payload,
                associated_data=associated_data,
            )
        else:
            raw_payload = self.payload

        # Verify payload integrity hash
        self.manifest.verify_payload_integrity(raw_payload)
        return raw_payload
