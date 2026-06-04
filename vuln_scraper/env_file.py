from __future__ import annotations

import json
import os
import time
from pathlib import Path

_DEBUG_LOG_PATH = Path(__file__).resolve().parents[1] / ".cursor" / "debug-79af1a.log"
_DEBUG_SESSION_ID = "79af1a"

_dotenv_logged = False


def _dotenv_paths() -> list[Path]:
    return [Path.cwd() / ".env"]


def read_dotenv(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped.removeprefix("export ").strip()
        key, separator, value = stripped.partition("=")
        key = key.strip()
        if not separator or not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def load_project_dotenv(*, override: bool = False) -> Path | None:
    """Load the first project .env into os.environ (does not override by default)."""
    global _dotenv_logged

    loaded_path: Path | None = None
    for path in _dotenv_paths():
        if not path.exists():
            continue
        for key, value in read_dotenv(path).items():
            if override or key not in os.environ:
                os.environ[key] = value
        loaded_path = path
        break

    if not _dotenv_logged:
        _dotenv_logged = True
        # region agent log
        try:
            payload = {
                "sessionId": _DEBUG_SESSION_ID,
                "runId": "pre-fix",
                "hypothesisId": "H1",
                "location": "env_file.py:load_project_dotenv",
                "message": "dotenv load result",
                "data": {
                    "loaded": loaded_path is not None,
                    "path": str(loaded_path) if loaded_path else None,
                    "cisco_token_set": bool(os.getenv("CISCO_OPENVULN_TOKEN", "").strip()),
                },
                "timestamp": int(time.time() * 1000),
            }
            _DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with _DEBUG_LOG_PATH.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload) + "\n")
        except OSError:
            pass
        # endregion
    return loaded_path
