# VANISH: Universal Self-Expiring Digital File Protocol

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-25%2F25%20Passing-success.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Android%20AOSP-orange.svg)]()

**VANISH** is an open, cross-platform protocol and operating system subsystem for cryptographically authenticated, self-expiring digital files.

A `.vfile` container encapsulates any arbitrary file payload along with a canonical, tamper-evident manifest, recipient prekey encapsulation, and an Ed25519 digital signature. Native OS services intercept incoming containers, register expiration deadlines with kernel and framework schedulers, and enforce automated file unlinking and hardware-backed cryptographic key erasure upon expiration.

---

## Architectural Overview

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

## Core Capabilities

- **Format Agnostic:** Packages any arbitrary file format (PDFs, media files, executables, archives, spreadsheets) into a unified `.vfile` container.
- **Cryptographically Verifiable:** Manifests are encoded using Canonical CBOR (RFC 8949) and signed with Ed25519 (RFC 8032) to prevent unauthorized tampering of expiry times and policies.
- **Payload Integrity & Encryption:** Supports authenticated AES-256-GCM AEAD encryption with recipient prekey encapsulation (HPKE RFC 9180).
- **Dual Sanitization Model:** PRNG multi-pass block overwriting on magnetic/loopback storage, and Tier 2 hardware keystore key destruction for flash storage (eMMC/UFS/SSDs).
- **Autonomous OS Enforcement:** Desktop Linux systemd daemon (`vanishd`) using kernel `fanotify` and `timerfd`; Android AOSP framework service (`VanishManagerService`) with Doze-resilient `AlarmManager`.

---

## Repository Structure

```
VANISH/
├── src/vanish/               # Core cryptographic protocol engine & CLI
│   ├── core/                 # CBOR serialization, Ed25519, AEAD, packaging
│   └── os/                   # Linux daemon (vanishd) and fanotify listeners
├── android/                  # Android AOSP reference service
│   ├── aidl/                 # IVanishManager.aidl interface
│   ├── aosp/core/            # VanishManagerService (system_server)
│   ├── aosp/provider/        # MediaScanner integration hooks
│   ├── aosp/saf/             # VanishDocumentsProvider for Storage Access Framework
│   └── sepolicy/             # SELinux security policy (vanish.te)
├── benchmarks/               # Empirical performance benchmark suite
│   ├── benchmark_suite.py    # Latency, framing overhead, and throughput
│   └── comparative_benchmark.py # Comparative baseline vs standard containers
├── tests/                    # Comprehensive pytest suite (25 unit tests)
└── docs/                     # Protocol specifications, threat model, and CDDL schemas
```

---

## Quickstart

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/parvezrepository/vanish-protocol-7A2B-53E9.git
cd /vanish-protocol-7A2B-53E9

# Create virtual environment and install
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
```

### 2. Run Test Suite (25/25 Passing)

```bash
pytest tests/ -v
```

### 3. Generate Identity Keypair

```bash
vanish keygen --out-dir ./keys
```

### 4. Pack a Self-Expiring File

```bash
# Pack a file to expire in 2 hours
vanish pack \
  --input confidential.pdf \
  --ttl 2h \
  --private-key keys/issuer_private.key \
  --output confidential.vfile
```

### 5. Inspect Manifest Without Unpacking

```bash
vanish inspect --file confidential.vfile
```

### 6. Verify and Unpack

```bash
vanish unpack \
  --file confidential.vfile \
  --public-key keys/issuer_public.key \
  --out-dir ./extracted
```

---

## Running Benchmarks

```bash
python benchmarks/benchmark_suite.py
python benchmarks/comparative_benchmark.py
```

---

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
