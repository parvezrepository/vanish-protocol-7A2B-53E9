# VANISH: Design and Implementation of a Cross-Platform, Cryptographically Authenticated Self-Expiring Digital File Protocol

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-25%2F25%20Passing-success.svg)]()
[![Artifact](https://img.shields.io/badge/Artifact-Evaluated%20%26%20Reproducible-orange.svg)]()

This repository contains the complete reference implementation, empirical benchmark suite, and LaTeX manuscript for **VANISH** — a cross-platform protocol and operating system subsystem for cryptographically authenticated, self-expiring digital files.

---

## Architecture Overview

```
+-------------------------------------------------------------------+
|               User Space / Client Applications                    |
|             (Files by Google, Nautilus, Shell, Browser)           |
+-------------------------------------------------------------------+
                                  |
                                  | Storage Interception
                                  v
+-------------------------------------------------------------------+
|               Kernel & Storage Ingestion Layer                    |
|             (Linux fanotify / AOSP ModernMediaScanner)            |
+-------------------------------------------------------------------+
                                  |
                                  | AIDL IPC / fanotify event
                                  v
+-------------------------------------------------------------------+
|             VANISH Lifecycle Enforcement Engine                   |
|             (Linux vanishd / AOSP VanishManagerService)           |
|   * Thread-Safe Min-Heap Priority Queue                           |
|   * Ed25519 & Canonical CBOR Verification                         |
|   * Doze-Resilient AlarmManager / timerfd                         |
+-------------------------------------------------------------------+
                                  |
                                  | t >= t_exp (Deadline Fired)
                                  v
+-------------------------------------------------------------------+
|               Lifecycle Purge & Shred Engine                      |
|   * PRNG Multi-Pass Overwriting (Magnetic Media)                  |
|   * Hardware Keystore Key Erasure (Flash Storage)                 |
+-------------------------------------------------------------------+
```

---

## Key Scientific Contributions

1. **Serverless Ephemeral Protocol (`.vfile`):** Solves the 15-year P2P Sybil vulnerability (USENIX Security '09) and cloud-reliance choke points without requiring continuous network connectivity.
2. **Cryptographically Authenticated Metadata:** Canonical CBOR (RFC 8949) with Ed25519 detached signatures (RFC 8032) and HPKE payload wrapping (RFC 9180).
3. **Dual-Model Sanitization:** PRNG block-overwriting for magnetic media + Tier 2 hardware keystore key destruction for flash media (resolving wear-leveling / FTL remnants).
4. **Autonomous OS Enforcement:** Linux kernel `fanotify` + `timerfd` daemon alongside an Android AOSP `system_server` privileged service with Doze-resilient `AlarmManager`.

---

## Repository Structure

```
VANISH/
├── src/vanish/               # Core cryptographic protocol engine & CLI
│   ├── core/                 # CBOR serialization, Ed25519, AEAD, packaging
│   └── os/                   # Linux daemon (vanishd) and fanotify listeners
├── android/                  # Android AOSP reference service
│   ├── aidl/                 # IVanishManagerService.aidl interface
│   ├── service/              # VanishManagerService (system_server)
│   └── receiver/             # Broadcast receiver & scan hooks
├── benchmarks/               # Empirical performance benchmark suite
│   ├── benchmark_engine.py   # Latency, framing overhead, battery emulation
│   └── run_benchmarks.py     # Automated paper data reproduction
├── tests/                    # Comprehensive pytest suite (25 unit tests)
├── paper/                    # Full IEEE conference LaTeX manuscript
│   ├── sections/             # Modular section files (01 to 07)
│   ├── figures/              # High-resolution vector figures & charts
│   ├── main.tex              # IEEEtran conference document
│   └── references.bib        # BibTeX bibliography
├── docs/                     # Specifications and threat model documentation
└── scripts/                  # Figure generation and packaging utilities
```

---

## One-Click Reproduction & Artifact Evaluation

### 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/parvezrepository/VANISH-Design-and-Implementation-of-a-Cross-Platform.git
cd VANISH-Design-and-Implementation-of-a-Cross-Platform

# Create virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
```

### 2. Run Test Suite (25/25 Passing)

```bash
pytest tests/ -v
```

### 3. Reproduce Experimental Benchmarks

```bash
# Run latency, framing overhead, and verification benchmarks
python benchmarks/benchmark_engine.py

# Re-generate publication-grade figures
python scripts/generate_all_paper_figures.py
```

---

## CLI Usage

### Generate Identity Keys
```bash
vanish keygen --out-dir ./keys
```

### Pack an Ephemeral Container
```bash
vanish pack \
  --input sample.pdf \
  --ttl 2h \
  --private-key keys/issuer_private.key \
  --output sample.vfile
```

### Inspect Container Manifest
```bash
vanish inspect --file sample.vfile
```

### Verify and Unpack
```bash
vanish unpack \
  --file sample.vfile \
  --public-key keys/issuer_public.key \
  --out-dir ./extracted
```

---

## Citation & Paper

If you use VANISH in your research, please cite our paper:

```bibtex
@inproceedings{vanish2026protocol,
  title     = {VANISH: Design and Implementation of a Cross-Platform, Cryptographically Authenticated Self-Expiring Digital File Protocol},
  author    = {Anonymous Author(s)},
  booktitle = {Proceedings of the IEEE Conference},
  year      = {2026}
}
```

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
