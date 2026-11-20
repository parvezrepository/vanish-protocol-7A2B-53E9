"""Tests for VanishLifecycleDaemon (OS background enforcement service)."""

import tempfile
import time
from pathlib import Path

from vanish.constants import ExpiryPolicy
from vanish.crypto import generate_ed25519_keypair
from vanish.daemon import VanishLifecycleDaemon
from vanish.engine import VanishEngine


def test_daemon_lifecycle_automatic_purge() -> None:
    priv, pub = generate_ed25519_keypair()
    engine = VanishEngine()

    with tempfile.TemporaryDirectory() as tmp_dir:
        watch_path = Path(tmp_dir) / "managed_storage"
        watch_path.mkdir()

        # Regular non-vfile (should be ignored and never purged)
        regular_file = watch_path / "important_keep.txt"
        regular_file.write_text("Permanent user document", encoding="utf-8")

        # 1. Create container 1: Short TTL (1 second), policy = SECURE_SHRED
        f1_src = Path(tmp_dir) / "short.txt"
        f1_src.write_text("Short ephemeral file", encoding="utf-8")
        f1_vfile = watch_path / "short.vfile"
        engine.pack_file(
            input_path=f1_src,
            output_path=f1_vfile,
            private_key=priv,
            ttl_seconds=1,
            expiry_policy=ExpiryPolicy.SECURE_SHRED,
        )

        # 2. Create container 2: Long TTL (600 seconds)
        f2_src = Path(tmp_dir) / "long.txt"
        f2_src.write_text("Long lived file", encoding="utf-8")
        f2_vfile = watch_path / "long.vfile"
        engine.pack_file(
            input_path=f2_src,
            output_path=f2_vfile,
            private_key=priv,
            ttl_seconds=600,
        )

        assert f1_vfile.exists()
        assert f2_vfile.exists()
        assert regular_file.exists()

        # Start daemon with short sweep interval
        daemon = VanishLifecycleDaemon(
            watch_dirs=[watch_path],
            engine=engine,
            sweep_interval_sec=0.5,
        )
        daemon.start(blocking=False)

        try:
            # Wait 2.5 seconds for short.vfile to expire and be purged by daemon
            time.sleep(2.5)

            # short.vfile should be purged
            assert not f1_vfile.exists(), "short.vfile was not purged by daemon after expiration"

            # long.vfile and regular_file must remain intact
            assert f2_vfile.exists(), "long.vfile should remain active"
            assert regular_file.exists(), "regular non-vfile must not be touched"

            # Dynamic test: Drop a new container while daemon is running
            f3_src = Path(tmp_dir) / "dynamic.txt"
            f3_src.write_text("Dynamically dropped file", encoding="utf-8")
            f3_vfile = watch_path / "dynamic.vfile"
            engine.pack_file(
                input_path=f3_src,
                output_path=f3_vfile,
                private_key=priv,
                ttl_seconds=1,
            )
            assert f3_vfile.exists()

            # Wait 2.5 seconds for dynamic file to expire and be purged
            time.sleep(2.5)
            assert not f3_vfile.exists(), "Dynamically dropped file was not purged by daemon"

        finally:
            daemon.stop()
