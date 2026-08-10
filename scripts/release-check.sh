#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [ -x "$ROOT/.venv/bin/python" ]; then
    PYTHON=$ROOT/.venv/bin/python
else
    PYTHON=$(command -v python3)
fi

./scripts/check-staged.py

"$PYTHON" -m unittest -v tests.test_standalone_edition

./scripts/run-tests.sh
"$PYTHON" -m pip check

if [ -n "${WEBSNAPSHOT_RELEASE_DATA_DIR:-}" ]; then
    "$PYTHON" websnapshot_admin.py integrity --data-dir "$WEBSNAPSHOT_RELEASE_DATA_DIR"
fi

printf '%s\n' 'Mandatory PageHold release checks passed.'
printf '%s\n' 'Run scripts/run-browser-tests.sh separately when user-interface code changed.'
