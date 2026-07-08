"""AI-300 靶机启动入口 — 默认 HTTPS 443，通过环境变量可开启 HTTP 双栈。"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from docker.certificates import ensure_self_signed_certificate

APP_MODULE = os.getenv("LAB_UVICORN_APP", "src.llamafw:app")
HOST = os.getenv("UVICORN_HOST", "0.0.0.0")
HTTPS_PORT = os.getenv("UVICORN_HTTPS_PORT", "443")
HTTP_PORT = os.getenv("UVICORN_HTTP_PORT", "")         # 留空则不启动 HTTP


def _cmd(port: str, cert: str = "", key: str = "") -> list[str]:
    cmd = [sys.executable, "-m", "uvicorn", APP_MODULE, "--host", HOST, "--port", port]
    if cert and key:
        cmd += ["--ssl-certfile", cert, "--ssl-keyfile", key]
    return cmd


def _terminate(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


def main() -> int:
    cert_file, key_file = ensure_self_signed_certificate()

    procs: list[subprocess.Popen] = []
    urls: list[str] = []

    # HTTPS（始终启动）
    procs.append(subprocess.Popen(_cmd(HTTPS_PORT, str(cert_file), str(key_file))))
    urls.append(f"    HTTPS → https://localhost:{HTTPS_PORT}  (自签名证书)")

    # HTTP（通过 UVICORN_HTTP_PORT 可选开启）
    if HTTP_PORT:
        procs.append(subprocess.Popen(_cmd(HTTP_PORT)))
        urls.append(f"    HTTP  → http://localhost:{HTTP_PORT}")

    print(f"\n  AI-300 靶机已启动:")
    for url in urls:
        print(url)
    print()

    def _handler(signum, _frame):
        _terminate(procs)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

    try:
        while True:
            for p in procs:
                if p.poll() is not None:
                    _terminate(procs)
                    return p.returncode or 0
            time.sleep(0.5)
    except KeyboardInterrupt:
        _terminate(procs)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
