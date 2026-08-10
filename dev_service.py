#!/usr/bin/env python3
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from product import NAME as PRODUCT_NAME


ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("WEBSNAPSHOT_DATA_DIR", ROOT / "data")).expanduser().resolve()
RUN_DIR = DATA_DIR / "run"
PID_FILE = RUN_DIR / "websnapshot.pid"
LOG_FILE = RUN_DIR / "websnapshot.log"
APP = ROOT / "app.py"
PORT = int(os.environ.get("PORT", "18765"))
START_TIMEOUT_SECONDS = float(os.environ.get("WEBSNAPSHOT_DEV_START_TIMEOUT_SECONDS", "120"))


def read_pid():
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return None


def is_running(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def is_healthy():
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=2) as response:
            return response.status == 200
    except Exception:
        return False


def start():
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    pid = read_pid()
    if is_running(pid):
        print(f"{PRODUCT_NAME} is already running with PID {pid}.")
        return 0
    if is_healthy():
        print(f"{PRODUCT_NAME} is already running on http://127.0.0.1:{PORT} (untracked process).")
        return 0
    with LOG_FILE.open("ab") as log:
        process = subprocess.Popen(
            [sys.executable, str(APP)],
            cwd=str(ROOT),
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
    deadline = time.monotonic() + max(5, START_TIMEOUT_SECONDS)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        if is_healthy():
            PID_FILE.write_text(str(process.pid), encoding="utf-8")
            print(f"{PRODUCT_NAME} started on http://127.0.0.1:{PORT} with PID {process.pid}.")
            print(f"Log: {LOG_FILE}")
            return 0
        time.sleep(0.25)
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=45)
        except subprocess.TimeoutExpired:
            print(f"{PRODUCT_NAME} startup timed out and PID {process.pid} did not stop cleanly.")
            return 1
    PID_FILE.unlink(missing_ok=True)
    print(f"{PRODUCT_NAME} did not stay running. Check {LOG_FILE}.")
    return 1


def stop():
    pid = read_pid()
    if not is_running(pid):
        PID_FILE.unlink(missing_ok=True)
        print(f"{PRODUCT_NAME} is not running.")
        return 0
    os.kill(pid, signal.SIGTERM)
    for _ in range(225):
        if not is_running(pid):
            PID_FILE.unlink(missing_ok=True)
            print(f"{PRODUCT_NAME} stopped.")
            return 0
        time.sleep(0.2)
    print(f"{PRODUCT_NAME} did not stop cleanly. PID {pid} is still running.")
    return 1


def status():
    pid = read_pid()
    healthy = is_healthy()
    if healthy:
        pid_text = f" with PID {pid}" if pid else ""
        print(f"{PRODUCT_NAME} is running{pid_text}.")
        print(f"URL: http://127.0.0.1:{PORT}")
        print(f"Log: {LOG_FILE}")
        return 0
    print(f"{PRODUCT_NAME} is not running.")
    return 1


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "start":
        return start()
    if command == "stop":
        return stop()
    if command == "restart":
        stop()
        return start()
    if command == "status":
        return status()
    print("Usage: python3 dev_service.py [start|stop|restart|status]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
