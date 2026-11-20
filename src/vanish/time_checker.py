"""Time verification and monotonic clock consistency checking for VANISH.

Defends against clock rollback attacks by monitoring both wall-clock time
and monotonic counters.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from vanish.exceptions import ClockRollbackError, ExpiredFileError, PrematureFileError

logger = logging.getLogger(__name__)

# Default permitted clock skew in seconds (accounting for benign NTP adjustments)
DEFAULT_MAX_CLOCK_SKEW_SEC: int = 120


@dataclass
class TimeState:
    """Persisted snapshot of system time to detect backwards clock rollbacks."""

    last_wall_time: float
    last_monotonic: float
    updated_at: float

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str) -> TimeState:
        parsed = json.loads(data)
        return cls(
            last_wall_time=float(parsed["last_wall_time"]),
            last_monotonic=float(parsed["last_monotonic"]),
            updated_at=float(parsed["updated_at"]),
        )


class TimeChecker:
    """Validates timestamps and enforces monotonic time progression."""

    def __init__(
        self,
        state_file: Path | str | None = None,
        max_skew_sec: int = DEFAULT_MAX_CLOCK_SKEW_SEC,
    ) -> None:
        self.state_file = Path(state_file) if state_file else None
        self.max_skew_sec = max_skew_sec
        self._initial_monotonic = time.monotonic()
        self._initial_wall_time = time.time()

    def get_current_time(self) -> int:
        """Return the current system epoch time in whole seconds."""
        return int(time.time())

    def record_time_observation(self) -> None:
        """Record current time checkpoint to state file to guard against rollback between reboots."""
        if not self.state_file:
            return

        now_wall = time.time()
        now_mono = time.monotonic()

        state = TimeState(
            last_wall_time=now_wall,
            last_monotonic=now_mono,
            updated_at=now_wall,
        )

        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self.state_file.with_suffix(".tmp")
            temp_path.write_text(state.to_json(), encoding="utf-8")
            # Atomic rename to prevent corrupt state files on sudden power off
            temp_path.replace(self.state_file)
        except OSError as exc:
            logger.warning("Could not persist time state to %s: %s", self.state_file, exc)

    def verify_monotonic_integrity(self) -> None:
        """Check whether wall-clock has been set backwards compared to previous observations.

        Raises:
            ClockRollbackError: If the system clock jumped backward beyond allowed threshold.
        """
        now_wall = time.time()
        now_mono = time.monotonic()

        # In-memory check: wall clock elapsed must not be significantly less than monotonic elapsed
        mono_elapsed = now_mono - self._initial_monotonic
        wall_elapsed = now_wall - self._initial_wall_time

        # If wall clock went backwards by more than max_skew_sec relative to monotonic counter
        if (wall_elapsed + self.max_skew_sec) < mono_elapsed:
            raise ClockRollbackError(
                f"Clock rollback detected in current session! "
                f"Monotonic elapsed: {mono_elapsed:.2f}s, Wall clock elapsed: {wall_elapsed:.2f}s"
            )

        # Check against persisted state file from previous process runs
        if self.state_file and self.state_file.exists():
            try:
                state = TimeState.from_json(self.state_file.read_text(encoding="utf-8"))
                if now_wall < (state.last_wall_time - self.max_skew_sec):
                    raise ClockRollbackError(
                        f"System clock rollback detected across sessions! "
                        f"Current time ({now_wall}) is earlier than previously recorded ({state.last_wall_time})"
                    )
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                logger.warning("Malformed time state file %s ignored: %s", self.state_file, exc)

    def validate_expiry(
        self,
        issued_at: int,
        expires_at: int,
        current_time: int | None = None,
        require_monotonic_check: bool = False,
    ) -> None:
        """Verify that a file is currently within its legitimate active lifecycle window.

        Raises:
            ExpiredFileError: If current_time >= expires_at.
            PrematureFileError: If current_time < (issued_at - max_skew_sec).
            ClockRollbackError: If monotonic verification fails and require_monotonic_check is True.
        """
        if require_monotonic_check:
            self.verify_monotonic_integrity()

        now = self.get_current_time() if current_time is None else current_time

        # Check 1: File has expired
        if now >= expires_at:
            raise ExpiredFileError(
                f"File expired at epoch {expires_at}",
                expires_at=expires_at,
                current_time=now,
            )

        # Check 2: File issued timestamp is impossibly far in the future
        if now < (issued_at - self.max_skew_sec):
            raise PrematureFileError(
                f"File issued timestamp ({issued_at}) is ahead of current time ({now})",
                issued_at=issued_at,
                current_time=now,
            )

        # Record progressive observation
        self.record_time_observation()
