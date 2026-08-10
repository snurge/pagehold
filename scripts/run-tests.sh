#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [ -n "${WEBSNAPSHOT_TEST_PYTHON:-}" ]; then
    PYTHON=$WEBSNAPSHOT_TEST_PYTHON
elif [ -x "$ROOT/.venv/bin/python" ]; then
    PYTHON=$ROOT/.venv/bin/python
else
    PYTHON=$(command -v python3)
fi

"$PYTHON" - <<'PY'
import importlib.util
import sys

if sys.version_info < (3, 11):
    raise SystemExit("WebSnapshot tests require Python 3.11 or newer.")

required = ("cryptography", "jsonschema", "playwright")
missing = [name for name in required if importlib.util.find_spec(name) is None]
if missing:
    joined = ", ".join(missing)
    raise SystemExit(
        f"Missing test dependencies: {joined}. Run: python3 -m pip install -r requirements.txt"
    )
PY

"$PYTHON" -m unittest discover -v

"$PYTHON" - <<'PY'
from pathlib import Path

excluded = {".git", ".venv", "data", "__pycache__"}
checked = 0
for path in sorted(Path(".").rglob("*.py")):
    if any(part in excluded for part in path.parts):
        continue
    compile(path.read_bytes(), str(path), "exec")
    checked += 1
print(f"Syntax checked {checked} Python files.")
PY
