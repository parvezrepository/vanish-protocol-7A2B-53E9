"""Custom exception hierarchy for the VANISH protocol."""


class VanishError(Exception):
    """Base exception for all VANISH protocol errors."""

    def __init__(self, message: str, details: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class ContainerFormatError(VanishError):
    """Raised when a .vfile container has invalid magic, corrupt headers, or invalid offsets."""
    pass


class SignatureVerificationError(VanishError):
    """Raised when cryptographic signature verification of the container or manifest fails."""
    pass


class PayloadIntegrityError(VanishError):
    """Raised when the calculated payload hash does not match the manifest payload_hash."""
    pass


class ExpiredFileError(VanishError):
    """Raised when attempting to access or decrypt a file whose expiry timestamp has passed."""

    def __init__(self, message: str, expires_at: int, current_time: int) -> None:
        super().__init__(
            message,
            f"expired_at={expires_at}, current_time={current_time}, delta_sec={current_time - expires_at}",
        )
        self.expires_at = expires_at
        self.current_time = current_time


class PrematureFileError(VanishError):
    """Raised when a file's issued_at timestamp lies in the future (potential clock skew/tampering)."""

    def __init__(self, message: str, issued_at: int, current_time: int) -> None:
        super().__init__(
            message,
            f"issued_at={issued_at}, current_time={current_time}, clock_skew_sec={issued_at - current_time}",
        )
        self.issued_at = issued_at
        self.current_time = current_time


class ClockRollbackError(VanishError):
    """Raised when local monotonic counter detects that the wall clock was manipulated backwards."""
    pass


class DecryptionError(VanishError):
    """Raised when AEAD decryption fails due to invalid key, tag mismatch, or corrupted ciphertext."""
    pass
