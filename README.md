# VANISH: Universal Self-Expiring Digital File Protocol

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)

VANISH is a standardized cross-platform digital file protocol introducing cryptographically verifiable, time-bounded lifecycle management to arbitrary digital files.

A **VANISH** file (`.vfile`) carries its original payload along with a canonical, tamper-proof manifest and a digital signature. Compatible operating systems and applications interpret this manifest, track its lifecycle, and systematically purge or cryptographically revoke the managed local copy once the designated expiry policy is satisfied.

---

## Key Features

- **Format Agnostic:** Packages any arbitrary file format (PDFs, media files, executables, archives, spreadsheets) into a unified `.vfile` container.
- **Cryptographically Verifiable:** Manifests are encoded using canonical CBOR (RFC 8949) and signed with Ed25519 (RFC 8032) to prevent unauthorized tampering of expiry times and policies.
- **Payload Integrity:** Cryptographically binds payload SHA-256 hashes directly to the signed manifest.
- **Optional Envelope Encryption:** Supports AES-256-GCM AEAD payload encryption with ephemeral key management for cryptographic shredding.
- **Monotonic Time & Rollback Defense:** Incorporates clock integrity validation to thwart local time manipulation.
- **Clean Architecture:** Fully modularized Python reference engine (`vanish.core`) accompanied by a production CLI tool (`vanish`).

---

## Quickstart

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/parvez/vanish.git
cd vanish

# Create virtual environment and install
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
```

### 2. Generate Keypair

```bash
vanish keygen --out-dir ./keys
```

### 3. Pack a Self-Expiring File

```bash
# Pack a PDF to expire in 2 hours
vanish pack \
  --input confidential.pdf \
  --ttl 2h \
  --private-key keys/issuer_private.key \
  --output confidential.vfile
```

### 4. Inspect Manifest Without Unpacking

```bash
vanish inspect --file confidential.vfile
```

### 5. Verify & Unpack

```bash
vanish unpack \
  --file confidential.vfile \
  --public-key keys/issuer_public.key \
  --out-dir ./extracted
```

---

## Project Structure

- `src/vanish/` - Protocol engine, binary parser, cryptography, and CLI.
- `docs/` - Protocol specifications, threat model, and CDDL schemas.
- `tests/` - Comprehensive unit and integration test suite.
- `paper/` - Academic research paper LaTeX source.

---

## Research & Academic Context

For academic inquiries, architectural details, and comparison with historical DHT-based systems (e.g., USENIX Security 2009), please refer to [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
