"""Cross-process coordination for archive mutations and consistent backups."""

from __future__ import annotations

import fcntl
import threading
from contextlib import contextmanager
from pathlib import Path


class ArchiveDataLock:
    """Serialize local writers and let a backup hold an exclusive process lock."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._thread_lock = threading.RLock()
        self._local = threading.local()

    @contextmanager
    def shared(self):
        with self._acquire(fcntl.LOCK_SH):
            yield

    @contextmanager
    def exclusive(self):
        with self._acquire(fcntl.LOCK_EX):
            yield

    @contextmanager
    def _acquire(self, mode: int):
        with self._thread_lock:
            depth = getattr(self._local, "depth", 0)
            if depth:
                self._local.depth = depth + 1
                try:
                    yield
                finally:
                    self._local.depth -= 1
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a+b") as handle:
                fcntl.flock(handle.fileno(), mode)
                self._local.depth = 1
                try:
                    yield
                finally:
                    self._local.depth = 0
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
