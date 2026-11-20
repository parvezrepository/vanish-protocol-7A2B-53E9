"""Tests for VanishEngine end-to-end workflows."""

import tempfile
from pathlib import Path
import pytest

from vanish.constants import ExpiryPolicy
from vanish.crypto import generate_ed25519_keypair
from vanish.engine import VanishEngine
from vanish.exceptions import ExpiredFileError, SignatureVerificationError


def test_engine_pack_inspect_and_unpack_roundtrip() -> None:
    priv, pub = generate_ed25519_keypair()
    engine = VanishEngine()

    with tempfile.TemporaryDirectory() as tmp_dir:
        input_file = Path(tmp_dir) / "report.pdf"
        output_container = Path(tmp_dir) / "report.pdf.vfile"
        extract_dir = Path(tmp_dir) / "extracted"

        original_data = b"%PDF-1.4 Mock confidential report data for research"
        input_file.write_bytes(original_data)

        # Pack with 1 hour TTL
        container, aes_key = engine.pack_file(
            input_path=input_file,
            output_path=output_container,
            private_key=priv,
            ttl_seconds=3600,
            expiry_policy=ExpiryPolicy.AUTO_UNLINK,
            encrypt=False,
            issuer_name="RESEARCH_LAB_01",
        )
        assert aes_key is None
        assert output_container.exists()

        # Inspect
        info = engine.inspect_container(output_container)
        assert info["original_name"] == "report.pdf"
        assert info["mime_type"] == "application/pdf"
        assert not info["is_expired"]
        assert info["issuer"] == "RESEARCH_LAB_01"
        assert not info["is_encrypted"]

        # Verify
        verified = engine.verify_container(output_container, pub)
        assert verified.manifest.original_name == "report.pdf"

        # Unpack
        extracted_file = engine.unpack_file(
            container_path=output_container,
            output_dir=extract_dir,
            public_key=pub,
        )
        assert extracted_file.exists()
        assert extracted_file.read_bytes() == original_data


def test_engine_encrypted_pack_and_unpack() -> None:
    priv, pub = generate_ed25519_keypair()
    engine = VanishEngine()

    with tempfile.TemporaryDirectory() as tmp_dir:
        input_file = Path(tmp_dir) / "secret.docx"
        output_container = Path(tmp_dir) / "secret.vfile"
        extract_dir = Path(tmp_dir) / "extracted"

        secret_data = b"Highly sensitive classified research equations."
        input_file.write_bytes(secret_data)

        # Pack with AES encryption
        container, aes_key = engine.pack_file(
            input_path=input_file,
            output_path=output_container,
            private_key=priv,
            ttl_seconds=600,
            encrypt=True,
        )
        assert aes_key is not None
        assert len(aes_key) == 32

        # Verify inspection shows encrypted
        info = engine.inspect_container(output_container)
        assert info["is_encrypted"] is True

        # Unpacking without AES key must fail
        with pytest.raises(ValueError, match="no AES decryption key"):
            engine.unpack_file(
                container_path=output_container,
                output_dir=extract_dir,
                public_key=pub,
                aes_key=None,
            )

        # Unpacking with valid AES key succeeds
        extracted = engine.unpack_file(
            container_path=output_container,
            output_dir=extract_dir,
            public_key=pub,
            aes_key=aes_key,
        )
        assert extracted.read_bytes() == secret_data


def test_engine_expired_file_rejection() -> None:
    priv, pub = generate_ed25519_keypair()
    engine = VanishEngine()

    with tempfile.TemporaryDirectory() as tmp_dir:
        input_file = Path(tmp_dir) / "temp.txt"
        output_container = Path(tmp_dir) / "temp.vfile"
        extract_dir = Path(tmp_dir) / "extracted"

        input_file.write_bytes(b"Expires immediately")

        # Pack with 1 second TTL
        container, _ = engine.pack_file(
            input_path=input_file,
            output_path=output_container,
            private_key=priv,
            ttl_seconds=1,
        )

        # Fast forward time checker to simulate expiration
        engine.time_checker.get_current_time = lambda: container.manifest.expires_at + 100

        with pytest.raises(ExpiredFileError):
            engine.unpack_file(
                container_path=output_container,
                output_dir=extract_dir,
                public_key=pub,
            )


def test_engine_one_time_read_burns_container() -> None:
    priv, pub = generate_ed25519_keypair()
    engine = VanishEngine()

    with tempfile.TemporaryDirectory() as tmp_dir:
        input_file = Path(tmp_dir) / "ephemeral.txt"
        output_container = Path(tmp_dir) / "ephemeral.vfile"
        extract_dir = Path(tmp_dir) / "extracted"

        content = b"Burn after reading immediately"
        input_file.write_bytes(content)

        engine.pack_file(
            input_path=input_file,
            output_path=output_container,
            private_key=priv,
            ttl_seconds=3600,
            one_time_read=True,
        )
        assert output_container.exists()

        extracted = engine.unpack_file(
            container_path=output_container,
            output_dir=extract_dir,
            public_key=pub,
        )
        assert extracted.read_bytes() == content
        # Container must have been destroyed
        assert not output_container.exists()
