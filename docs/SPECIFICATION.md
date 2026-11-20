# The VANISH Protocol Specification
## Version 1.0 (Draft-RFC)

**Abstract:**  
VANISH is a standardized cross-platform digital file protocol that introduces cryptographically verifiable, time-bounded lifecycle management to arbitrary digital files. A VANISH file (`.vfile`) encapsulates the original payload, a canonical tamper-evident manifest, and an asymmetric digital signature. Operating systems with native support detect this container, verify its policy, schedule its lifecycle, and systematically purge or cryptographically revoke the managed local copy upon policy satisfaction.

---

## 1. Introduction

Traditional file systems treat stored files as indefinite digital artifacts. Once a file is received, sender control terminates, leading to persistent data debt, compliance exposure, and accidental disclosure.

VANISH addresses this fundamental architectural omission by packaging arbitrary files into self-describing, self-verifying, time-bounded containers that can be recognized and enforced directly by operating system storage managers without requiring bespoke proprietary viewer applications.

---

## 2. Container Binary Format

A `.vfile` binary file consists of six sequential segments:

```
+-------------------------------------------------------------------+
| 1. Fixed Header (32 bytes, Big-Endian)                            |
+-------------------------------------------------------------------+
| 2. Public Key Segment (pubkey_len bytes)                          |
+-------------------------------------------------------------------+
| 3. Nonce / Initialization Vector (nonce_len bytes)                |
+-------------------------------------------------------------------+
| 4. Digital Signature Segment (sig_len bytes = 64 bytes)           |
+-------------------------------------------------------------------+
| 5. Canonical CBOR Manifest Segment (manifest_len bytes)           |
+-------------------------------------------------------------------+
| 6. Payload Segment (payload_len bytes)                            |
+-------------------------------------------------------------------+
```

### 2.1 Fixed Header Layout

| Offset (Bytes) | Field Name | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0x00 - 0x03` | `magic` | `char[4]` | 4 | Magic constant: `b"VAN1"` (`0x56 0x41 0x4E 0x31`) |
| `0x04 - 0x05` | `version` | `uint16_t` | 2 | Protocol version: `0x0001` |
| `0x06 - 0x07` | `flags` | `uint16_t` | 2 | Feature bitmask flags |
| `0x08 - 0x0B` | `manifest_len`| `uint32_t` | 4 | Byte length of CBOR manifest segment |
| `0x0C - 0x13` | `payload_len` | `uint64_t` | 8 | Byte length of payload segment |
| `0x14 - 0x15` | `sig_len` | `uint16_t` | 2 | Length of digital signature (64 for Ed25519) |
| `0x16 - 0x17` | `pubkey_len` | `uint16_t` | 2 | Length of embedded public key (32 for Ed25519) |
| `0x18 - 0x19` | `nonce_len` | `uint16_t` | 2 | Length of AEAD nonce (12 for AES-GCM, 0 if unencrypted) |
| `0x1A - 0x1F` | `reserved` | `uint8_t[6]` | 6 | Reserved padding (all zeros `0x00`) |

### 2.2 Header Flags

- `0x0001` (`FLAG_ENCRYPTED`): Payload is encrypted with AES-256-GCM.
- `0x0002` (`FLAG_MONOTONIC_REQ`): Verifier must ensure monotonic clock progression.
- `0x0004` (`FLAG_SECURE_SHRED`): Removal requires overwriting disk blocks with random noise before unlinking.
- `0x0008` (`FLAG_ONE_TIME_READ`): Container must be permanently destroyed immediately upon the first successful unpack.

---

## 3. Cryptographic Binding & Signing

To preclude header-mangling, length-extension, and timestamp-substitution attacks, the Ed25519 digital signature is computed over a canonical cryptographic digest covering all structural parameters:

$$\text{Preimage} = \text{Header}_{0:26} \mathbin{\Vert} \text{PubKey} \mathbin{\Vert} \text{Nonce} \mathbin{\Vert} \text{Manifest}_{\text{CBOR}} \mathbin{\Vert} \text{SHA256}(\text{Payload})$$

$$\text{Digest} = \text{SHA256}(\text{Preimage})$$

$$\text{Signature} = \text{Ed25519\_Sign}(\text{PrivateKey}_{\text{Issuer}}, \text{Digest})$$

Any modification to expiration timestamps, filenames, policies, flags, or payload bits invalidates this digital signature.

---

## 4. Manifest Specification

The manifest is deterministically serialized using Canonical CBOR (RFC 8949 §4.2), guaranteeing byte-level determinism. See [`docs/cddl/manifest.cddl`](cddl/manifest.cddl) for the formal schema.
