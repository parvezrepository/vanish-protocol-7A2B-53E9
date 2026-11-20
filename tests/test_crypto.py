"""Tests for cryptographic primitives."""

import tempfile
from pathlib import Path
import pytest

from vanish.crypto import (
    compute_sha256,
    decrypt_payload_aes_gcm,
    encrypt_payload_aes_gcm,
    generate_aes_key,
    generate_ed25519_keypair,
    generate_nonce,
    load_private_key_file,
    load_public_key_file,
    private_key_from_raw_bytes,
    private_key_to_raw_bytes,
    public_key_from_raw_bytes,
    public_key_to_raw_bytes,
    save_keypair_files,
    sign_digest,
    verify_signature,
)
from vanish.exceptions import DecryptionError, SignatureVerificationError


def test_ed25519_raw_serialization_roundtrip() -> None:
    priv, pub = generate_ed25519_keypair()
    priv_raw = private_key_to_raw_bytes(priv)
    pub_raw = public_key_to_raw_bytes(pub)

    assert len(priv_raw) == 32
    assert len(pub_raw) == 32

    reconstructed_priv = private_key_from_raw_bytes(priv_raw)
    reconstructed_pub = public_key_from_raw_bytes(pub_raw)

    message = b"Cryptographic verification payload"
    sig = sign_digest(reconstructed_priv, message)
    verify_signature(reconstructed_pub, sig, message)


def test_ed25519_pem_file_persistence() -> None:
    priv, pub = generate_ed25519_keypair()
    with tempfile.TemporaryDirectory() as tmp_dir:
        priv_path, pub_path = save_keypair_files(priv, tmp_dir, prefix="test_issuer")
        assert priv_path.exists()
        assert pub_path.exists()

        loaded_priv = load_private_key_file(priv_path)
        loaded_pub = load_public_key_file(pub_path)

        msg = b"Persistence test vector"
        sig = sign_digest(loaded_priv, msg)
        verify_signature(loaded_pub, sig, msg)


def test_signature_verification_rejection() -> None:
    priv1, pub1 = generate_ed25519_keypair()
    priv2, pub2 = generate_ed25519_keypair()

    message = b"Original authentic message"
    sig = sign_digest(priv1, message)

    # Valid with correct key
    verify_signature(pub1, sig, message)

    # Must fail with wrong public key
    with pytest.raises(SignatureVerificationError):
        verify_signature(pub2, sig, message)

    # Must fail with altered message
    with pytest.raises(SignatureVerificationError):
        verify_signature(pub1, sig, b"Tampered message")


def test_aes_gcm_encryption_roundtrip() -> None:
    key = generate_aes_key()
    nonce = generate_nonce()
    plaintext = b"Top secret classified payload document bytes"
    aad = compute_sha256(plaintext)

    ciphertext = encrypt_payload_aes_gcm(key, nonce, plaintext, associated_data=aad)
    assert ciphertext != plaintext

    decrypted = decrypt_payload_aes_gcm(key, nonce, ciphertext, associated_data=aad)
    assert decrypted == plaintext


def test_aes_gcm_tamper_detection() -> None:
    key = generate_aes_key()
    nonce = generate_nonce()
    plaintext = b"Sample data"
    aad = b"bound_metadata"

    ciphertext = encrypt_payload_aes_gcm(key, nonce, plaintext, associated_data=aad)

    # Tampering with ciphertext byte
    corrupt_ct = bytearray(ciphertext)
    corrupt_ct[0] ^= 0xFF

    with pytest.raises(DecryptionError):
        decrypt_payload_aes_gcm(key, nonce, bytes(corrupt_ct), associated_data=aad)

    # Tampering with associated data
    with pytest.raises(DecryptionError):
        decrypt_payload_aes_gcm(key, nonce, ciphertext, associated_data=b"wrong_metadata")
