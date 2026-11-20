"""Cryptographic operations for the VANISH protocol.

Implements Ed25519 digital signatures (RFC 8032), SHA-256 cryptographic digests,
and AES-256-GCM authenticated envelope encryption (NIST SP 800-38D).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vanish.constants import (
    AES_GCM_KEY_SIZE,
    AES_GCM_NONCE_SIZE,
    ED25519_PRIVATE_KEY_SIZE,
    ED25519_PUBLIC_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
    SHA256_DIGEST_SIZE,
)
from vanish.exceptions import DecryptionError, SignatureVerificationError


def generate_ed25519_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 private/public keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def private_key_to_raw_bytes(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Export an Ed25519 private key as 32 raw seed bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_raw_bytes(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Export an Ed25519 public key as 32 raw bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_from_raw_bytes(raw_bytes: bytes) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from 32 raw seed bytes."""
    if len(raw_bytes) != ED25519_PRIVATE_KEY_SIZE:
        raise ValueError(
            f"Expected {ED25519_PRIVATE_KEY_SIZE} bytes for Ed25519 private key, got {len(raw_bytes)}"
        )
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)


def public_key_from_raw_bytes(raw_bytes: bytes) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from 32 raw bytes."""
    if len(raw_bytes) != ED25519_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"Expected {ED25519_PUBLIC_KEY_SIZE} bytes for Ed25519 public key, got {len(raw_bytes)}"
        )
    return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)


def save_keypair_files(
    private_key: ed25519.Ed25519PrivateKey,
    out_dir: Path | str,
    prefix: str = "vanish_issuer",
) -> tuple[Path, Path]:
    """Persist Ed25519 keypair to disk with standard PEM encoding."""
    target_dir = Path(out_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    priv_path = target_dir / f"{prefix}_private.pem"
    pub_path = target_dir / f"{prefix}_public.pem"

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


def load_private_key_file(path: Path | str) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM or raw 32-byte file."""
    data = Path(path).read_bytes()
    if len(data) == ED25519_PRIVATE_KEY_SIZE:
        return private_key_from_raw_bytes(data)
    loaded = serialization.load_pem_private_key(data, password=None)
    if not isinstance(loaded, ed25519.Ed25519PrivateKey):
        raise TypeError(f"Key in {path} is not an Ed25519 private key")
    return loaded


def load_public_key_file(path: Path | str) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM or raw 32-byte file."""
    data = Path(path).read_bytes()
    if len(data) == ED25519_PUBLIC_KEY_SIZE:
        return public_key_from_raw_bytes(data)
    loaded = serialization.load_pem_public_key(data)
    if not isinstance(loaded, ed25519.Ed25519PublicKey):
        raise TypeError(f"Key in {path} is not an Ed25519 public key")
    return loaded


def sign_digest(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign an arbitrary byte sequence using Ed25519. Returns a 64-byte signature."""
    sig = private_key.sign(message)
    if len(sig) != ED25519_SIGNATURE_SIZE:
        raise ValueError(f"Unexpected signature size: {len(sig)}")
    return sig


def verify_signature(
    public_key: ed25519.Ed25519PublicKey,
    signature: bytes,
    message: bytes,
) -> None:
    """Verify an Ed25519 signature over message bytes.

    Raises:
        SignatureVerificationError: If verification fails.
    """
    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise SignatureVerificationError(
            f"Invalid signature length: expected {ED25519_SIGNATURE_SIZE}, got {len(signature)}"
        )
    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise SignatureVerificationError("Ed25519 signature verification failed") from exc


def compute_sha256(data: bytes) -> bytes:
    """Compute the 32-byte SHA-256 digest of data bytes."""
    return hashlib.sha256(data).digest()


def compute_sha256_stream(file_obj: BinaryIO, chunk_size: int = 65536) -> bytes:
    """Compute SHA-256 digest streaming through a file object without loading it all into memory."""
    hasher = hashlib.sha256()
    while chunk := file_obj.read(chunk_size):
        hasher.update(chunk)
    return hasher.digest()


def generate_aes_key() -> bytes:
    """Generate a cryptographically secure 256-bit AES key."""
    return os.urandom(AES_GCM_KEY_SIZE)


def generate_nonce() -> bytes:
    """Generate a standard 96-bit (12-byte) nonce for AES-GCM."""
    return os.urandom(AES_GCM_NONCE_SIZE)


def encrypt_payload_aes_gcm(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """Encrypt payload using AES-256-GCM AEAD.

    Returns the ciphertext with authentication tag appended.
    """
    if len(key) != AES_GCM_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_GCM_KEY_SIZE} bytes")
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError(f"Nonce must be {AES_GCM_NONCE_SIZE} bytes")
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, associated_data)


def decrypt_payload_aes_gcm(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt payload using AES-256-GCM AEAD.

    Raises:
        DecryptionError: If decryption or authentication tag verification fails.
    """
    if len(key) != AES_GCM_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_GCM_KEY_SIZE} bytes")
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError(f"Nonce must be {AES_GCM_NONCE_SIZE} bytes")
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception as exc:
        raise DecryptionError("AES-GCM decryption failed: ciphertext corrupt or key invalid") from exc
