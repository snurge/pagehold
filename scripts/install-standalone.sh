#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PYTHON=${PYTHON:-python3}

"$PYTHON" - <<'PY'
import sys

if sys.version_info < (3, 11):
    version = ".".join(str(part) for part in sys.version_info[:3])
    raise SystemExit(
        f"PageHold requires Python 3.11 or newer; {sys.executable} is {version}. "
        "Install a current Python, then rerun with PYTHON=/path/to/python."
    )
PY

if [ ! -x "$ROOT/.venv/bin/python" ]; then
    "$PYTHON" -m venv "$ROOT/.venv"
fi

"$ROOT/.venv/bin/python" -m pip install --disable-pip-version-check -r requirements.txt
"$ROOT/.venv/bin/python" -m playwright install chromium
"$ROOT/.venv/bin/python" -m pip check

printf '%s\n' "PageHold is installed."
printf '%s\n' "Start it with: .venv/bin/python dev_service.py start"
printf '%s\n' "Then open: http://127.0.0.1:18765"
