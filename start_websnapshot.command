#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

if [ -x "$ROOT/.venv/bin/python" ]; then
    exec "$ROOT/.venv/bin/python" dev_service.py start
fi

exec python3 dev_service.py start
