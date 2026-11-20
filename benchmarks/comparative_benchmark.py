"""Comparative baseline benchmarking script for VANISH.

Evaluates VANISH against established container and encryption formats (all uncompressed):
1. Raw AES-256-GCM (Cryptographic primitive lower bound)
2. Standard TAR (Uncompressed filesystem container)
3. Signed Encrypted Envelope (Ed25519 + AES-256-GCM authenticated envelope)
4. VANISH (.vfile) Signed, Encrypted, CBOR Manifest & Policy
"""

from __future__ import annotations

import io
import json
import os
import tarfile
import tempfile
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from vanish.constants import ExpiryPolicy
from vanish.crypto import (
    compute_sha256,
    decrypt_payload_aes_gcm,
    encrypt_payload_aes_gcm,
    generate_aes_key,
    generate_ed25519_keypair,
    generate_nonce,
    sign_digest,
    verify_signature,
)
from vanish.engine import VanishEngine

# IEEE Publication Typography & Visual Settings
plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["DejaVu Serif", "Times New Roman", "Computer Modern Roman"],
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.labelweight": "bold",
    "axes.titlesize": 11,
    "axes.titleweight": "bold",
    "xtick.labelsize": 9.5,
    "ytick.labelsize": 9.5,
    "legend.fontsize": 9,
    "figure.titlesize": 12,
})


def run_comparative_benchmarks(payload_size_bytes: int = 1024 * 1024, iterations: int = 10) -> dict[str, dict[str, float]]:
    priv, pub = generate_ed25519_keypair()
    engine = VanishEngine()
    payload = os.urandom(payload_size_bytes)

    results: dict[str, dict[str, float]] = {}

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        raw_file = tmp_path / "payload.bin"
        raw_file.write_bytes(payload)

        # Warm-up pass
        warm_vfile = tmp_path / "warm.vfile"
        _, wk = engine.pack_file(raw_file, warm_vfile, priv, ttl_seconds=3600, encrypt=True)
        warm_out = tmp_path / "warm_out"
        warm_out.mkdir(exist_ok=True)
        engine.unpack_file(warm_vfile, warm_out, pub, aes_key=wk)

        # Baseline 1: Raw AES-256-GCM AEAD (Pure crypto lower bound)
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

        # Baseline 2: Standard Uncompressed TAR (Pure container framing, no compression)
        tar_path = tmp_path / "test.tar"
        t_create = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            with tarfile.open(tar_path, "w") as tf:
                tf.add(raw_file, arcname="payload.bin")
            t_create.append((time.perf_counter() - t0) * 1000.0)

        t_extract = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            with tarfile.open(tar_path, "r") as tf:
                f = tf.extractfile("payload.bin")
                _ = f.read() if f else None
            t_extract.append((time.perf_counter() - t0) * 1000.0)

        results["Standard TAR"] = {
            "framing_overhead_bytes": tar_path.stat().st_size - payload_size_bytes,
            "creation_ms": float(np.mean(t_create)),
            "extraction_ms": float(np.mean(t_extract)),
        }

        # Baseline 3: Signed & Encrypted Envelope (Ed25519 signature + AES-256-GCM)
        env_path = tmp_path / "test.envelope"
        t_create = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            env_key = generate_aes_key()
            env_nonce = generate_nonce()
            ct = encrypt_payload_aes_gcm(env_key, env_nonce, payload)
            sig = sign_digest(priv, compute_sha256(payload))
            # Binary framing: 64B sig + 12B nonce + ct
            env_path.write_bytes(sig + env_nonce + ct)
            t_create.append((time.perf_counter() - t0) * 1000.0)

        t_extract = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            raw_env = env_path.read_bytes()
            extracted_sig = raw_env[:64]
            extracted_nonce = raw_env[64:76]
            extracted_ct = raw_env[76:]
            pt = decrypt_payload_aes_gcm(env_key, extracted_nonce, extracted_ct)
            verify_signature(pub, extracted_sig, compute_sha256(pt))
            t_extract.append((time.perf_counter() - t0) * 1000.0)

        results["Signed Envelope"] = {
            "framing_overhead_bytes": env_path.stat().st_size - payload_size_bytes,
            "creation_ms": float(np.mean(t_create)),
            "extraction_ms": float(np.mean(t_extract)),
        }

        # Candidate: VANISH Protocol (.vfile) - Signed, Encrypted & Policy Manifest
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

    fig, ax = plt.subplots(figsize=(7.2, 4.2), dpi=300)
    rects1 = ax.bar(x - width / 2, creation_times, width, label="Packaging / Creation Latency", color="#1b4f72", edgecolor="#154360", linewidth=0.9)
    rects2 = ax.bar(x + width / 2, extraction_times, width, label="Unpacking & Verification Latency", color="#196f3d", edgecolor="#145a32", linewidth=0.9)

    ax.set_ylabel("Execution Latency (ms)", fontsize=11, fontweight="bold")
    ax.set_title("Comparative Processing Latency for 1MB Payload (Uncompressed Baselines)", fontsize=11, fontweight="bold", pad=8)
    ax.set_xticks(x)
    ax.set_xticklabels(systems, fontsize=9.5, fontweight="bold")
    ax.legend(frameon=True, facecolor="white", edgecolor="#cccccc", framealpha=0.95, fontsize=9.5)
    ax.grid(axis="y", ls="--", color="#dcdcdc", alpha=0.8)

    max_val = max(max(creation_times), max(extraction_times))
    ax.set_ylim(0, max_val * 1.28)

    for bar in rects1:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.05, f"{yval:.2f}", ha="center", va="bottom", fontsize=8.5, fontweight="bold")

    for bar in rects2:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.05, f"{yval:.2f}", ha="center", va="bottom", fontsize=8.5, fontweight="bold")

    fig.tight_layout()
    fig.savefig(out_path.with_suffix(".png"), dpi=300)
    fig.savefig(out_path.with_suffix(".pdf"))
    plt.close()


def main() -> None:
    print("[*] Running Fair Comparative Baseline Benchmarking (1MB payload)...")
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
        print(f"    - {sys_name:24}: Overhead={metrics['framing_overhead_bytes']}B, Create={metrics['creation_ms']:.2f}ms, Extract={metrics['extraction_ms']:.2f}ms")
    print(f"[+] Output: {out_fig.with_suffix('.pdf')}")


if __name__ == "__main__":
    main()
