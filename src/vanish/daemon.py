"""Native OS Background Lifecycle Enforcement Daemon for VANISH.

Monitors designated filesystem directories in real-time, ingests incoming .vfile
containers, verifies their authenticity, registers their expiry schedules in an
in-memory priority queue, and automatically purges or shreds them at the exact
moment of expiration.
"""

from __future__ import annotations

import heapq
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from vanish.constants import ExpiryPolicy
from vanish.engine import VanishEngine
from vanish.exceptions import VanishError

logger = logging.getLogger("vanishd")


@dataclass(order=True)
class ExpiryTask:
    """An active lifecycle task tracked in the priority heap queue."""

    expires_at: int
    file_id: str = field(compare=False)
    file_path: Path = field(compare=False)
    expiry_policy: int = field(compare=False)
    requires_shred: bool = field(compare=False)


class VanishDirectoryHandler(FileSystemEventHandler):
    """Watches filesystem events and queues newly detected .vfile containers."""

    def __init__(self, daemon: VanishLifecycleDaemon) -> None:
        super().__init__()
        self.daemon = daemon

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory and event.src_path.endswith(".vfile"):
            logger.info("Filesystem event: new container detected -> %s", event.src_path)
            self.daemon.register_container(Path(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory and event.src_path.endswith(".vfile"):
            logger.debug("Filesystem event: container modified -> %s", event.src_path)
            self.daemon.register_container(Path(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        dest = getattr(event, "dest_path", None)
        if dest and dest.endswith(".vfile"):
            logger.info("Filesystem event: container moved to -> %s", dest)
            self.daemon.register_container(Path(dest))


class VanishLifecycleDaemon:
    """Operating System Background Enforcement Daemon (vanishd)."""

    def __init__(
        self,
        watch_dirs: list[Path | str],
        engine: VanishEngine | None = None,
        sweep_interval_sec: float = 2.0,
    ) -> None:
        self.watch_dirs = [Path(d).resolve() for d in watch_dirs]
        self.engine = engine or VanishEngine()
        self.sweep_interval_sec = sweep_interval_sec

        self._task_heap: list[ExpiryTask] = []
        self._tracked_ids: set[str] = set()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        self._observer = Observer()
        self._worker_thread: threading.Thread | None = None

    def register_container(self, file_path: Path) -> bool:
        """Inspect, verify, and register a .vfile container into the expiration queue."""
        if not file_path.is_file():
            return False

        try:
            info = self.engine.inspect_container(file_path)
            file_id = info["file_id"]
            expires_at = info["expires_at"]
            requires_shred = info["requires_secure_shred"]
            policy_val = ExpiryPolicy[info["expiry_policy"]].value

            now = self.engine.time_checker.get_current_time()

            # If already expired, execute purge immediately
            if now >= expires_at:
                logger.warning("Container %s is ALREADY EXPIRED. Triggering immediate purge.", file_path.name)
                self._execute_purge(file_path, requires_shred)
                return True

            with self._lock:
                if file_id in self._tracked_ids:
                    return False  # Already registered

                task = ExpiryTask(
                    expires_at=expires_at,
                    file_id=file_id,
                    file_path=file_path.resolve(),
                    expiry_policy=policy_val,
                    requires_shred=requires_shred,
                )
                heapq.heappush(self._task_heap, task)
                self._tracked_ids.add(file_id)
                logger.info(
                    "Registered container [%s] -> expires in %ds (policy: %s)",
                    file_path.name,
                    expires_at - now,
                    info["expiry_policy"],
                )
                return True
        except VanishError as exc:
            logger.warning("Failed to register %s (invalid container): %s", file_path, exc)
            return False
        except Exception as exc:
            logger.error("Unexpected error reading %s: %s", file_path, exc)
            return False

    def scan_all_directories(self) -> int:
        """Scan all watched directories for existing .vfile containers."""
        registered = 0
        for watch_dir in self.watch_dirs:
            if not watch_dir.exists():
                continue
            for vfile in watch_dir.glob("*.vfile"):
                if self.register_container(vfile):
                    registered += 1
        return registered

    def _execute_purge(self, file_path: Path, requires_shred: bool) -> None:
        """Execute scheduled expiration removal."""
        if not file_path.exists():
            return

        logger.info("[PURGE ACTION] Expiring file %s...", file_path)
        if requires_shred:
            logger.info("-> Overwriting disk blocks (SECURE_SHRED)...")
            self.engine.shred_file(file_path, passes=2)
        else:
            logger.info("-> Standard unlinking (AUTO_UNLINK)...")
            file_path.unlink(missing_ok=True)

    def _lifecycle_loop(self) -> None:
        """Background thread loop that pops tasks from priority queue upon expiration."""
        logger.info("VANISH OS Enforcement Lifecycle thread started.")

        while not self._stop_event.is_set():
            now = self.engine.time_checker.get_current_time()

            with self._lock:
                while self._task_heap and self._task_heap[0].expires_at <= now:
                    task = heapq.heappop(self._task_heap)
                    self._tracked_ids.discard(task.file_id)
                    # Trigger purge outside of lock if possible, or right here
                    self._execute_purge(task.file_path, task.requires_shred)

            # Also perform periodic directory sweep to catch any missed files
            self.scan_all_directories()

            self._stop_event.wait(timeout=self.sweep_interval_sec)

        logger.info("VANISH OS Enforcement Lifecycle thread stopped.")

    def start(self, blocking: bool = False) -> None:
        """Start filesystem monitoring and lifecycle worker."""
        for watch_dir in self.watch_dirs:
            watch_dir.mkdir(parents=True, exist_ok=True)
            handler = VanishDirectoryHandler(self)
            self._observer.schedule(handler, str(watch_dir), recursive=False)
            logger.info("Attached filesystem observer to: %s", watch_dir)

        # Initial scan
        initial_count = self.scan_all_directories()
        logger.info("Initial sweep discovered %d active .vfile container(s).", initial_count)

        self._observer.start()

        self._worker_thread = threading.Thread(target=self._lifecycle_loop, daemon=True)
        self._worker_thread.start()

        if blocking:
            try:
                while not self._stop_event.is_set():
                    time.sleep(0.5)
            except KeyboardInterrupt:
                logger.info("Received interrupt signal. Shutting down daemon...")
                self.stop()

    def stop(self) -> None:
        """Gracefully terminate daemon observers and threads."""
        self._stop_event.set()
        self._observer.stop()
        self._observer.join(timeout=3.0)
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)
        logger.info("VANISH daemon successfully terminated.")
