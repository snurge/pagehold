#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [ -x "$ROOT/.venv/bin/python" ]; then
    PYTHON=$ROOT/.venv/bin/python
else
    PYTHON=$(command -v python3)
fi

WEBSNAPSHOT_BROWSER_TEST=1 "$PYTHON" -m unittest -v tests.test_browser_ui
