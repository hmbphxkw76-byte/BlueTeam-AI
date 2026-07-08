"""Container entrypoint.

Synchronize Docker-injected environment variables into /app/.env before
starting the configured app command. The web app can then keep updating the
same writable file.
"""
import os
import sys
from pathlib import Path


ENV_FILE = Path(os.getenv("APP_ENV_FILE", "/app/.env"))

BASE_KEYS = {
    "MODEL_CONFIGS",
    "OLLAMA_BASE_URL",
    "OLLAMA_API_KEY",
    "OLLAMA_MODEL",
    "ZHIPU_URL",
    "ZHIPU_API_KEY",
    "ZHIPU_MODEL",
    "OPENAI_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
    "LAB_NAME",
    "LAB_DEFENSE_MODE",
    "LAB_ADMIN_TOKEN",
    "LAB_COMPAT_API_KEY",
    "LAB_API_RATE_LIMIT",
    "UVICORN_HTTPS_PORT",
    "LAB_TLS_CERT_FILE",
    "LAB_TLS_KEY_FILE",
    "LAB_TLS_HOSTS",
}


def custom_model_keys() -> set[str]:
    prefixes = [
        prefix.strip().upper()
        for prefix in os.getenv("MODEL_CONFIGS", "").split(",")
        if prefix.strip()
    ]
    keys: set[str] = set()
    for prefix in prefixes:
        keys.update({
            f"{prefix}_NAME",
            f"{prefix}_BASE_URL",
            f"{prefix}_API_KEY",
            f"{prefix}_MODEL",
        })
    return keys


def sync_env_file() -> None:
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []

    known_keys = BASE_KEYS | custom_model_keys()
    updates = {key: os.environ[key] for key in known_keys if key in os.environ}
    if not updates:
        ENV_FILE.touch(exist_ok=True)
        return

    pending = dict(updates)
    emitted: set[str] = set()
    new_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        candidate = stripped[1:].lstrip() if stripped.startswith("#") else stripped
        key, sep, _ = candidate.partition("=")

        if sep and key in updates:
            if key in emitted:
                continue
            new_lines.append(f"{key}={updates[key]}")
            pending.pop(key, None)
            emitted.add(key)
        else:
            new_lines.append(line)

    if pending:
        if new_lines and new_lines[-1].strip():
            new_lines.append("")
        new_lines.append("# Docker runtime environment")
        for key in sorted(pending):
            new_lines.append(f"{key}={pending[key]}")

    ENV_FILE.write_text("\n".join(new_lines).rstrip() + "\n", encoding="utf-8")


def main() -> None:
    sync_env_file()
    if len(sys.argv) <= 1:
        raise SystemExit("missing command")
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
