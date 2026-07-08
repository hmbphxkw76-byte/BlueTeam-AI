"""Run FastAPI lab server — default HTTPS 443, optional HTTP via UVICORN_HTTP_PORT."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from certificates import ensure_self_signed_certificate

APP_MODULE = os.getenv("LAB_UVICORN_APP", "src.llamafw:app")
HOST = os.getenv("UVICORN_HOST", "0.0.0.0")
HTTPS_PORT = os.getenv("UVICORN_HTTPS_PORT", "443")
HTTP_PORT = os.getenv("UVICORN_HTTP_PORT", "")            # 留空则不启动 HTTP


def uvicorn_command(port: str, cert_file: Path | None = None, key_file: Path | None = None) -> list[str]:
    command = [sys.executable, "-m", "uvicorn", APP_MODULE, "--host", HOST, "--port", port]
    if cert_file and key_file:
        command.extend(["--ssl-certfile", str(cert_file), "--ssl-keyfile", str(key_file)])
    return command


def terminate(processes: list[subprocess.Popen]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def main() -> int:
    cert_file, key_file = ensure_self_signed_certificate()

    processes = [subprocess.Popen(uvicorn_command(HTTPS_PORT, cert_file, key_file))]

    if HTTP_PORT:
        processes.append(subprocess.Popen(uvicorn_command(HTTP_PORT)))

    print(f"\n  AI-300 靶机已启动:")
    print(f"    HTTPS → https://localhost:{HTTPS_PORT}  (自签名证书)")
    if HTTP_PORT:
        print(f"    HTTP  → http://localhost:{HTTP_PORT}")
    print()

    def handle_signal(signum, _frame):
        terminate(processes)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        while True:
            for process in processes:
                exit_code = process.poll()
                if exit_code is not None:
                    terminate(processes)
                    return exit_code
            time.sleep(1)
    except KeyboardInterrupt:
        terminate(processes)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
