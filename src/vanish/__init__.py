"""VANISH: Universal Self-Expiring Digital File Protocol.

This package provides a reference implementation of the VANISH protocol,
enabling creation, cryptographic verification, inspection, and lifecycle
management of self-expiring .vfile containers.
"""

from vanish.constants import (
    CONTAINER_MAGIC,
    PROTOCOL_VERSION,
    FLAG_ENCRYPTED,
    FLAG_MONOTONIC_REQ,
    FLAG_SECURE_SHRED,
    FLAG_ONE_TIME_READ,
    ExpiryPolicy,
)
from vanish.exceptions import (
    VanishError,
    ContainerFormatError,
    SignatureVerificationError,
    PayloadIntegrityError,
    ExpiredFileError,
    PrematureFileError,
    ClockRollbackError,
)
from vanish.manifest import Manifest
from vanish.container import VanishContainer
from vanish.engine import VanishEngine

__version__ = "0.1.0"
__all__ = [
    "CONTAINER_MAGIC",
    "PROTOCOL_VERSION",
    "FLAG_ENCRYPTED",
    "FLAG_MONOTONIC_REQ",
    "FLAG_SECURE_SHRED",
    "FLAG_ONE_TIME_READ",
    "ExpiryPolicy",
    "VanishError",
    "ContainerFormatError",
    "SignatureVerificationError",
    "PayloadIntegrityError",
    "ExpiredFileError",
    "PrematureFileError",
    "ClockRollbackError",
    "Manifest",
    "VanishContainer",
    "VanishEngine",
]
