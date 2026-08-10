#!/usr/bin/env python3
"""Load a protected KEY=VALUE file and exec a managed service command."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def load_environment(path: Path) -> dict[str, str]:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(f"environment file must not be accessible by group/others: {path}")
    values = dict(os.environ)
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator or not name.replace("_", "").isalnum() or not name[0].isalpha():
            raise ValueError(f"invalid environment entry on line {number}")
        values[name] = value
    return values


def executable_path(value: str) -> str:
    """Return an absolute executable path without resolving virtualenv symlinks."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return os.path.abspath(path)


def main() -> None:
    if len(sys.argv) < 4:
        raise SystemExit("usage: service_runner.py ENV_FILE EXECUTABLE ARG...")
    environment = load_environment(Path(sys.argv[1]).expanduser().resolve())
    executable = executable_path(sys.argv[2])
    os.execve(executable, [executable, *sys.argv[3:]], environment)


if __name__ == "__main__":
    main()
