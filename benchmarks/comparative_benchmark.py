"""Comparative baseline benchmarking script for VANISH.

Evaluates VANISH against established container and encryption formats:
1. Standard ZIP Archive (.zip)
2. GZIP Tarball (.tar.gz)
3. Authenticated AES-256-GCM Raw Container
4. VANISH (.vfile) Signed & Encrypted

Measures framing byte overhead, creation latency, and extraction latency.
Generates comparative figures for the paper.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from vanish.constants import ExpiryPolicy
from vanish.crypto import generate_aes_key, generate_ed25519_keypair, generate_nonce, encrypt_payload_aes_gcm, decrypt_payload_aes_gcm
from vanish.engine import VanishEngine


def run_comparative_benchmarks(payload_size_bytes: int = 1024 * 1024, iterations: int = 10) -> dict[str, dict[str, float]]:
    priv, pub = generate_ed25519_keypair()
    engine = VanishEngine()
    payload = os.urandom(payload_size_bytes)

    results: dict[str, dict[str, float]] = {}

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        raw_file = tmp_path / "payload.bin"
        raw_file.write_bytes(payload)

        # Baseline 1: Standard ZIP
        zip_path = tmp_path / "test.zip"
        t_create = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
                zf.write(raw_file, arcname="payload.bin")
            t_create.append((time.perf_counter() - t0) * 1000.0)

        t_extract = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            with zipfile.ZipFile(zip_path, "r") as zf:
                _ = zf.read("payload.bin")
            t_extract.append((time.perf_counter() - t0) * 1000.0)

        results["Standard ZIP"] = {
            "framing_overhead_bytes": zip_path.stat().st_size - payload_size_bytes,
            "creation_ms": float(np.mean(t_create)),
            "extraction_ms": float(np.mean(t_extract)),
        }

        # Baseline 2: TAR GZIP
        tar_path = tmp_path / "test.tar.gz"
        t_create = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            with tarfile.open(tar_path, "w:gz") as tf:
                tf.add(raw_file, arcname="payload.bin")
            t_create.append((time.perf_counter() - t0) * 1000.0)

        t_extract = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            with tarfile.open(tar_path, "r:gz") as tf:
                f = tf.extractfile("payload.bin")
                _ = f.read() if f else None
            t_extract.append((time.perf_counter() - t0) * 1000.0)

        results["TAR.GZ"] = {
            "framing_overhead_bytes": tar_path.stat().st_size - payload_size_bytes,
            "creation_ms": float(np.mean(t_create)),
            "extraction_ms": float(np.mean(t_extract)),
        }

        # Baseline 3: Raw AES-256-GCM AEAD
        raw_enc_path = tmp_path / "test.aead"
        key = generate_aes_key()
        nonce = generate_nonce()
        t_create = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            ct = encrypt_payload_aes_gcm(key, nonce, payload)
            raw_enc_path.write_bytes(nonce + ct)
            t_create.append((time.perf_counter() - t0) * 1000.0)

        t_extract = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            data = raw_enc_path.read_bytes()
            extracted_nonce = data[:12]
            extracted_ct = data[12:]
            _ = decrypt_payload_aes_gcm(key, extracted_nonce, extracted_ct)
            t_extract.append((time.perf_counter() - t0) * 1000.0)

        results["Raw AES-256-GCM"] = {
            "framing_overhead_bytes": raw_enc_path.stat().st_size - payload_size_bytes,
            "creation_ms": float(np.mean(t_create)),
            "extraction_ms": float(np.mean(t_extract)),
        }

        # Candidate: VANISH Protocol (.vfile) - Signed & Encrypted
        vfile_path = tmp_path / "test.vfile"
        t_create = []
        keys = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            _, k = engine.pack_file(
                input_path=raw_file,
                output_path=vfile_path,
                private_key=priv,
                ttl_seconds=3600,
                encrypt=True,
                expiry_policy=ExpiryPolicy.SECURE_SHRED,
            )
            t_create.append((time.perf_counter() - t0) * 1000.0)
            keys.append(k)

        t_extract = []
        extract_dir = tmp_path / "extracted_vanish"
        extract_dir.mkdir(exist_ok=True)
        for _ in range(iterations):
            t0 = time.perf_counter()
            engine.unpack_file(
                container_path=vfile_path,
                output_dir=extract_dir,
                public_key=pub,
                aes_key=keys[-1],
            )
            t_extract.append((time.perf_counter() - t0) * 1000.0)

        results["VANISH (.vfile)"] = {
            "framing_overhead_bytes": vfile_path.stat().st_size - payload_size_bytes,
            "creation_ms": float(np.mean(t_create)),
            "extraction_ms": float(np.mean(t_extract)),
        }

    return results


def plot_comparative_barchart(results: dict[str, dict[str, float]], out_path: Path) -> None:
    systems = list(results.keys())
    creation_times = [results[s]["creation_ms"] for s in systems]
    extraction_times = [results[s]["extraction_ms"] for s in systems]

    x = np.arange(len(systems))
    width = 0.35

    plt.figure(figsize=(7.5, 4.2))
    plt.bar(x - width / 2, creation_times, width, label="Packaging / Creation Latency", color="#3b528b", edgecolor="black")
    plt.bar(x + width / 2, extraction_times, width, label="Unpacking / Verification Latency", color="#5dc863", edgecolor="black")

    plt.ylabel("Execution Latency (ms) for 1MB Payload", fontsize=11, fontweight="bold")
    plt.title("Comparative Performance: VANISH vs Established Containers", fontsize=12, fontweight="bold")
    plt.xticks(x, systems, fontsize=10, fontweight="bold")
    plt.legend(frameon=True, fontsize=10)
    plt.grid(axis="y", ls="--", alpha=0.5)
    plt.tight_layout()

    plt.savefig(out_path.with_suffix(".png"), dpi=300)
    plt.savefig(out_path.with_suffix(".pdf"))
    plt.close()


def main() -> None:
    print("[*] Running Comparative Baseline Benchmarking (1MB payload)...")
    results = run_comparative_benchmarks(payload_size_bytes=1024 * 1024, iterations=10)
    
    fig_dir = Path("paper/figures")
    fig_dir.mkdir(parents=True, exist_ok=True)
    out_fig = fig_dir / "fig_comparative_baseline"

    print("[*] Generating comparative baseline plot...")
    plot_comparative_barchart(results, out_fig)

    out_json = Path("benchmarks/results/comparative_data.json")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("[+] Comparative benchmark complete:")
    for sys_name, metrics in results.items():
        print(f"    - {sys_name:18}: Overhead={metrics['framing_overhead_bytes']}B, Create={metrics['creation_ms']:.2f}ms, Extract={metrics['extraction_ms']:.2f}ms")
    print(f"[+] Output: {out_fig.with_suffix('.pdf')}")


if __name__ == "__main__":
    main()
