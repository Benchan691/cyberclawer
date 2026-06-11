from __future__ import annotations

import os
from pathlib import Path


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
    loaded_path: Path | None = None
    for path in _dotenv_paths():
        if not path.exists():
            continue
        for key, value in read_dotenv(path).items():
            if override or key not in os.environ:
                os.environ[key] = value
        loaded_path = path
        break
    return loaded_path
