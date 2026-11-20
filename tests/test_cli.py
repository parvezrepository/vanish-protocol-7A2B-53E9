"""Tests for the CLI interface."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_vanish_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Helper to execute the vanish CLI entrypoint."""
    cmd = [sys.executable, "-m", "vanish.cli", *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def test_cli_keygen_and_pack_inspect_verify_unpack_flow() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        keys_dir = tmp_path / "keys"
        doc_path = tmp_path / "research_notes.txt"
        vfile_path = tmp_path / "research_notes.vfile"
        extract_dir = tmp_path / "extracted"

        doc_path.write_text("Confidential algorithm pseudocode and proofs.", encoding="utf-8")

        # 1. Keygen
        res_key = run_vanish_cli("keygen", "--out-dir", str(keys_dir), "--prefix", "lab_root")
        assert res_key.returncode == 0
        priv_key = keys_dir / "lab_root_private.pem"
        pub_key = keys_dir / "lab_root_public.pem"
        assert priv_key.exists()
        assert pub_key.exists()

        # 2. Pack
        res_pack = run_vanish_cli(
            "pack",
            "--input", str(doc_path),
            "--ttl", "1h",
            "--private-key", str(priv_key),
            "--output", str(vfile_path),
            "--policy", "secure_shred",
            "--issuer", "RESEARCH_DEPT_A",
        )
        assert res_pack.returncode == 0
        assert vfile_path.exists()

        # 3. Inspect (JSON)
        res_inspect = run_vanish_cli("inspect", "--file", str(vfile_path), "--json")
        assert res_inspect.returncode == 0
        info = json.loads(res_inspect.stdout)
        assert info["original_name"] == "research_notes.txt"
        assert info["issuer"] == "RESEARCH_DEPT_A"
        assert info["expiry_policy"] == "SECURE_SHRED"
        assert not info["is_expired"]

        # 4. Verify
        res_verify = run_vanish_cli("verify", "--file", str(vfile_path), "--public-key", str(pub_key))
        assert res_verify.returncode == 0
        assert "VALID" in res_verify.stdout

        # 5. Unpack
        res_unpack = run_vanish_cli(
            "unpack",
            "--file", str(vfile_path),
            "--out-dir", str(extract_dir),
            "--public-key", str(pub_key),
        )
        assert res_unpack.returncode == 0
        extracted_doc = extract_dir / "research_notes.txt"
        assert extracted_doc.exists()
        assert extracted_doc.read_text(encoding="utf-8") == "Confidential algorithm pseudocode and proofs."


def test_cli_purge_command() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        keys_dir = tmp_path / "keys"

        # Generate keys
        run_vanish_cli("keygen", "--out-dir", str(keys_dir))
        priv_key = keys_dir / "issuer_private.pem"

        # Create active file (TTL 10m)
        f_active = tmp_path / "active.txt"
        f_active.write_text("active", encoding="utf-8")
        vf_active = tmp_path / "active.vfile"
        run_vanish_cli("pack", "-i", str(f_active), "-t", "10m", "-k", str(priv_key), "-o", str(vf_active))

        # Create already-expired file (TTL 1s, sleep or fast-forward)
        f_exp = tmp_path / "expired.txt"
        f_exp.write_text("expired", encoding="utf-8")
        vf_exp = tmp_path / "expired.vfile"
        run_vanish_cli("pack", "-i", str(f_exp), "-t", "1s", "-k", str(priv_key), "-o", str(vf_exp), "--policy", "secure_shred")

        # Manually tamper or wait for expiration: 1s TTL expires quickly
        import time
        time.sleep(1.2)

        # Run purge
        res_purge = run_vanish_cli("purge", "--dir", str(tmp_path))
        assert res_purge.returncode == 0
        assert "1 expired container(s) removed" in res_purge.stdout

        assert vf_active.exists()
        assert not vf_exp.exists()
