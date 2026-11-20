"""High-level orchestration engine for VANISH operations."""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from vanish.constants import (
    AES_GCM_NONCE_SIZE,
    ED25519_PUBLIC_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
    FIXED_HEADER_SIZE,
    FLAG_ENCRYPTED,
    FLAG_MONOTONIC_REQ,
    FLAG_NONE,
    FLAG_ONE_TIME_READ,
    FLAG_SECURE_SHRED,
    PROTOCOL_VERSION,
    ExpiryPolicy,
)
from vanish.container import ContainerHeader, VanishContainer
from vanish.crypto import (
    compute_sha256,
    encrypt_payload_aes_gcm,
    generate_aes_key,
    generate_nonce,
    public_key_to_raw_bytes,
    sign_digest,
)
from vanish.manifest import Manifest
from vanish.time_checker import TimeChecker

logger = logging.getLogger(__name__)


class VanishEngine:
    """Core interface for packing, unpacking, verifying, and shredding VANISH containers."""

    def __init__(self, time_checker: TimeChecker | None = None) -> None:
        self.time_checker = time_checker or TimeChecker()

    def pack_file(
        self,
        input_path: Path | str,
        output_path: Path | str,
        private_key: ed25519.Ed25519PrivateKey,
        ttl_seconds: int,
        expiry_policy: ExpiryPolicy = ExpiryPolicy.AUTO_UNLINK,
        encrypt: bool = False,
        aes_key: bytes | None = None,
        require_monotonic: bool = True,
        one_time_read: bool = False,
        issuer_name: str = "VANISH-CLI",
        custom_metadata: dict[str, Any] | None = None,
    ) -> tuple[VanishContainer, bytes | None]:
        """Pack an arbitrary file into a signed, self-expiring .vfile container.

        Returns:
            Tuple of (VanishContainer, aes_key_used_or_None)
        """
        source = Path(input_path)
        if not source.is_file():
            raise FileNotFoundError(f"Source file not found: {source}")

        payload_bytes = source.read_bytes()
        now = self.time_checker.get_current_time()
        expires_at = now + ttl_seconds

        # 1. Create Manifest
        manifest = Manifest.create(
            payload_bytes=payload_bytes,
            original_name=source.name,
            issued_at=now,
            expires_at=expires_at,
            expiry_policy=expiry_policy,
            issuer=issuer_name,
            custom_metadata=custom_metadata,
        )
        manifest_bytes = manifest.to_cbor()

        # 2. Determine container flags
        flags = FLAG_NONE
        if encrypt:
            flags |= FLAG_ENCRYPTED
        if require_monotonic:
            flags |= FLAG_MONOTONIC_REQ
        if expiry_policy == ExpiryPolicy.SECURE_SHRED:
            flags |= FLAG_SECURE_SHRED
        if one_time_read:
            flags |= FLAG_ONE_TIME_READ

        # 3. Handle payload encryption if requested
        nonce = b""
        actual_key = None
        if encrypt:
            actual_key = aes_key or generate_aes_key()
            nonce = generate_nonce()
            # Bind manifest's payload_hash as AEAD associated data
            container_payload = encrypt_payload_aes_gcm(
                key=actual_key,
                nonce=nonce,
                plaintext=payload_bytes,
                associated_data=manifest.payload_hash,
            )
        else:
            container_payload = payload_bytes

        # 4. Prepare Public Key
        public_key = private_key.public_key()
        pubkey_bytes = public_key_to_raw_bytes(public_key)

        # 5. Assemble provisional header for signature calculation
        header = ContainerHeader(
            magic=b"VAN1",
            version=PROTOCOL_VERSION,
            flags=flags,
            manifest_len=len(manifest_bytes),
            payload_len=len(container_payload),
            sig_len=ED25519_SIGNATURE_SIZE,
            pubkey_len=len(pubkey_bytes),
            nonce_len=len(nonce),
        )

        provisional_container = VanishContainer(
            header=header,
            manifest=manifest,
            payload=container_payload,
            signature=b"\x00" * ED25519_SIGNATURE_SIZE,
            public_key_bytes=pubkey_bytes,
            nonce=nonce,
        )

        # 6. Calculate digest & generate Ed25519 signature
        signing_digest = provisional_container.compute_signing_digest()
        signature = sign_digest(private_key, signing_digest)
        provisional_container.signature = signature

        # 7. Write to output file
        out_file = Path(output_path)
        provisional_container.save_to_file(out_file)

        return provisional_container, actual_key

    def inspect_container(self, container_path: Path | str) -> dict[str, Any]:
        """Inspect a container's manifest and headers without extracting payload."""
        container = VanishContainer.load_from_file(container_path)
        now = self.time_checker.get_current_time()
        m = container.manifest

        return {
            "file_id": m.file_id,
            "original_name": m.original_name,
            "mime_type": m.mime_type,
            "issued_at": m.issued_at,
            "expires_at": m.expires_at,
            "remaining_seconds": m.remaining_seconds(now),
            "is_expired": m.is_expired(now),
            "expiry_policy": ExpiryPolicy(m.expiry_policy).name,
            "issuer": m.issuer,
            "is_encrypted": container.is_encrypted,
            "requires_monotonic": container.requires_monotonic,
            "requires_secure_shred": container.requires_secure_shred,
            "is_one_time_read": container.is_one_time_read,
            "payload_size_bytes": container.header.payload_len,
            "payload_sha256": m.payload_hash.hex(),
            "custom_metadata": m.custom_metadata,
        }

    def verify_container(
        self,
        container_path: Path | str,
        public_key: ed25519.Ed25519PublicKey | None = None,
    ) -> VanishContainer:
        """Verify the signature and format of a container. Returns the container on success."""
        container = VanishContainer.load_from_file(container_path)
        container.verify_authenticity(public_key)
        return container

    def unpack_file(
        self,
        container_path: Path | str,
        output_dir: Path | str,
        public_key: ed25519.Ed25519PublicKey | None = None,
        aes_key: bytes | None = None,
        enforce_expiry: bool = True,
    ) -> Path:
        """Verify authenticity, enforce expiry, unpack payload, and save to output directory.

        If the container has FLAG_ONE_TIME_READ set, the container on disk will be shredded
        immediately after successful unpacking.
        """
        container_file = Path(container_path)
        container = self.verify_container(container_file, public_key)

        now = self.time_checker.get_current_time()
        if enforce_expiry:
            self.time_checker.validate_expiry(
                issued_at=container.manifest.issued_at,
                expires_at=container.manifest.expires_at,
                current_time=now,
                require_monotonic_check=container.requires_monotonic,
            )

        plaintext = container.extract_plaintext_payload(
            aes_key=aes_key,
            time_checker=self.time_checker,
            current_time=now,
        )

        out_path = Path(output_dir) / container.manifest.original_name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(plaintext)

        # Handle one-time-read burn policy
        if container.is_one_time_read:
            logger.info("Container is marked ONE_TIME_READ; destroying container %s", container_file)
            self.shred_file(container_file)

        return out_path

    @staticmethod
    def shred_file(path: Path | str, passes: int = 1) -> None:
        """Securely overwrite a file on disk before unlinking."""
        target = Path(path)
        if not target.exists():
            return

        try:
            length = target.stat().st_size
            if length > 0:
                with open(target, "r+b") as f:
                    for _ in range(passes):
                        f.seek(0)
                        f.write(os.urandom(length))
                        f.flush()
                        os.fsync(f.fileno())
            target.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Error shredding %s: %s", target, exc)
            target.unlink(missing_ok=True)
