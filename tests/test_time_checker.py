"""Tests for TimeChecker and clock rollback defense."""

import tempfile
import time
from pathlib import Path
import pytest

from vanish.exceptions import ClockRollbackError, ExpiredFileError, PrematureFileError
from vanish.time_checker import TimeChecker


def test_time_checker_valid_window() -> None:
    checker = TimeChecker(max_skew_sec=60)
    current_time = 1700000500
    issued_at = 1700000000
    expires_at = 1700001000

    # Should not raise
    checker.validate_expiry(issued_at=issued_at, expires_at=expires_at, current_time=current_time)


def test_time_checker_expired_detection() -> None:
    checker = TimeChecker()
    current_time = 1700002000
    issued_at = 1700000000
    expires_at = 1700001000

    with pytest.raises(ExpiredFileError) as exc_info:
        checker.validate_expiry(issued_at=issued_at, expires_at=expires_at, current_time=current_time)
    assert exc_info.value.expires_at == expires_at
    assert exc_info.value.current_time == current_time


def test_time_checker_premature_future_file() -> None:
    checker = TimeChecker(max_skew_sec=30)
    current_time = 1700000000
    # Issued 500 seconds into the future
    issued_at = 1700000500
    expires_at = 1700001000

    with pytest.raises(PrematureFileError):
        checker.validate_expiry(issued_at=issued_at, expires_at=expires_at, current_time=current_time)


def test_time_checker_cross_session_rollback_detection() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_file = Path(tmp_dir) / "time_state.json"

        # Session 1 records time 1700010000
        checker1 = TimeChecker(state_file=state_file, max_skew_sec=10)
        checker1.record_time_observation()

        # Session 2 tries to run with clock rolled back by 5 hours
        checker2 = TimeChecker(state_file=state_file, max_skew_sec=10)
        # Manually alter the state file to simulate future timestamp
        state_file.write_text(
            '{"last_wall_time": 2000000000.0, "last_monotonic": 100.0, "updated_at": 2000000000.0}',
            encoding="utf-8",
        )

        with pytest.raises(ClockRollbackError, match="rollback detected across sessions"):
            checker2.verify_monotonic_integrity()
