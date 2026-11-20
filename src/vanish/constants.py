"""Constants and bitmask definitions for the VANISH protocol."""

from enum import IntEnum, unique

# Magic identifier for binary container: "VAN1" (0x56 0x41 0x4E 0x31)
CONTAINER_MAGIC: bytes = b"VAN1"

# Protocol version 1 (uint16_t)
PROTOCOL_VERSION: int = 1

# Fixed binary header size in bytes
# 4 (magic) + 2 (version) + 2 (flags) + 4 (manifest_len) + 8 (payload_len)
# + 2 (sig_len) + 2 (pubkey_len) + 2 (nonce_len) + 6 (reserved) = 32 bytes
FIXED_HEADER_SIZE: int = 32

# Ed25519 standard key and signature byte lengths (RFC 8032)
ED25519_PUBLIC_KEY_SIZE: int = 32
ED25519_PRIVATE_KEY_SIZE: int = 32
ED25519_SIGNATURE_SIZE: int = 64

# AES-256-GCM AEAD standard parameters (NIST SP 800-38D)
AES_GCM_KEY_SIZE: int = 32       # 256-bit key
AES_GCM_NONCE_SIZE: int = 12     # 96-bit recommended nonce
AES_GCM_TAG_SIZE: int = 16       # 128-bit authentication tag

# SHA-256 digest length
SHA256_DIGEST_SIZE: int = 32

# Container Flags (Bitmask - uint16_t)
FLAG_NONE: int = 0x0000
FLAG_ENCRYPTED: int = 0x0001        # Bit 0: Payload is AES-256-GCM encrypted
FLAG_MONOTONIC_REQ: int = 0x0002    # Bit 1: Verifier must validate monotonic clock
FLAG_SECURE_SHRED: int = 0x0004     # Bit 2: OS daemon must overwrite disk blocks before unlink
FLAG_ONE_TIME_READ: int = 0x0008    # Bit 3: Burn on read (expire immediately after first unpack)


@unique
class ExpiryPolicy(IntEnum):
    """Enumeration of policy actions enforced upon expiration."""

    AUTO_UNLINK = 1       # Default: Delete file descriptor and remove directory entry
    SECURE_SHRED = 2      # Overwrite contents with cryptographically random bytes before unlinking
    REVOKE_KEY_ONLY = 3   # For encrypted files: delete key from keystore, leaving ciphertext intact
