"""Tests for VanishContainer binary format and serialization."""

import io
import struct
import pytest
from vanish.constants import CONTAINER_MAGIC, FIXED_HEADER_SIZE, PROTOCOL_VERSION
from vanish.container import ContainerHeader, VanishContainer
from vanish.crypto import generate_ed25519_keypair, public_key_to_raw_bytes, sign_digest
from vanish.exceptions import ContainerFormatError, SignatureVerificationError
from vanish.manifest import Manifest


def test_container_header_pack_unpack() -> None:
    header = ContainerHeader(
        magic=CONTAINER_MAGIC,
        version=PROTOCOL_VERSION,
        flags=0x0001,
        manifest_len=256,
        payload_len=1024,
        sig_len=64,
        pubkey_len=32,
        nonce_len=12,
    )
    packed = header.pack()
    assert len(packed) == FIXED_HEADER_SIZE

    unpacked = ContainerHeader.unpack(packed)
    assert unpacked.magic == CONTAINER_MAGIC
    assert unpacked.version == PROTOCOL_VERSION
    assert unpacked.flags == 0x0001
    assert unpacked.manifest_len == 256
    assert unpacked.payload_len == 1024
    assert unpacked.sig_len == 64
    assert unpacked.pubkey_len == 32
    assert unpacked.nonce_len == 12


def test_container_header_invalid_magic() -> None:
    bad_header = b"BAD1" + b"\x00" * 28
    with pytest.raises(ContainerFormatError, match="Invalid magic"):
        ContainerHeader.unpack(bad_header)


def test_container_header_invalid_version() -> None:
    # Set version to 999
    bad_header = struct.pack(">4sHHIQHHH6s", b"VAN1", 999, 0, 10, 20, 64, 32, 0, b"\x00" * 6)
    with pytest.raises(ContainerFormatError, match="Unsupported container version"):
        ContainerHeader.unpack(bad_header)


def test_container_roundtrip_serialization() -> None:
    priv, pub = generate_ed25519_keypair()
    pub_bytes = public_key_to_raw_bytes(pub)
    payload = b"Sample unencrypted research text"

    manifest = Manifest.create(
        payload_bytes=payload,
        original_name="sample.txt",
        issued_at=1000,
        expires_at=2000,
    )
    manifest_bytes = manifest.to_cbor()

    header = ContainerHeader(
        magic=CONTAINER_MAGIC,
        version=PROTOCOL_VERSION,
        flags=0,
        manifest_len=len(manifest_bytes),
        payload_len=len(payload),
        sig_len=64,
        pubkey_len=len(pub_bytes),
        nonce_len=0,
    )

    container = VanishContainer(
        header=header,
        manifest=manifest,
        payload=payload,
        signature=b"\x00" * 64,
        public_key_bytes=pub_bytes,
        nonce=b"",
    )

    digest = container.compute_signing_digest()
    container.signature = sign_digest(priv, digest)

    serialized = container.serialize()
    assert len(serialized) > FIXED_HEADER_SIZE

    # Deserialize from stream
    stream = io.BytesIO(serialized)
    loaded = VanishContainer.read_from_stream(stream)

    assert loaded.header.manifest_len == len(manifest_bytes)
    assert loaded.header.payload_len == len(payload)
    assert loaded.manifest.original_name == "sample.txt"
    assert loaded.payload == payload

    # Authenticity check must succeed
    loaded.verify_authenticity()


def test_container_detects_signature_forgery() -> None:
    priv, pub = generate_ed25519_keypair()
    pub_bytes = public_key_to_raw_bytes(pub)
    payload = b"Genuine data"

    manifest = Manifest.create(
        payload_bytes=payload,
        original_name="test.txt",
        issued_at=100,
        expires_at=200,
    )
    header = ContainerHeader(
        magic=CONTAINER_MAGIC,
        version=PROTOCOL_VERSION,
        flags=0,
        manifest_len=len(manifest.to_cbor()),
        payload_len=len(payload),
        sig_len=64,
        pubkey_len=len(pub_bytes),
        nonce_len=0,
    )

    container = VanishContainer(
        header=header,
        manifest=manifest,
        payload=payload,
        signature=b"\x00" * 64,
        public_key_bytes=pub_bytes,
        nonce=b"",
    )
    digest = container.compute_signing_digest()
    container.signature = sign_digest(priv, digest)

    # Tampering with payload
    container.payload = b"Malicious data"

    with pytest.raises(SignatureVerificationError):
        container.verify_authenticity()
