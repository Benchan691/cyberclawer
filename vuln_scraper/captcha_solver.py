from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any


def hash_captcha_image_bytes(image_bytes: bytes) -> str:
    return hashlib.sha256(image_bytes).hexdigest()


def hash_captcha_data_url(src_url: str) -> str | None:
    if not src_url:
        return None
    payload = src_url
    if "," in payload:
        payload = payload.split(",", 1)[1]
    try:
        image_bytes = base64.b64decode(payload, validate=False)
    except (ValueError, binascii.Error):
        return None
    if not image_bytes:
        return None
    return hash_captcha_image_bytes(image_bytes)


def resolve_captcha_map_path(
    *,
    explicit: Path | str | None = None,
    data_dir: Path | None = None,
) -> Path | None:
    if explicit is not None:
        path = Path(explicit)
        return path if path.is_file() else None

    import os

    env_path = os.getenv("CAPTCHA_MAP_FILE")
    if env_path:
        path = Path(env_path)
        if path.is_file():
            return path

    for candidate in (Path("captcha_map.json"), Path.cwd() / "captcha_map.json"):
        if candidate.is_file():
            return candidate

    if data_dir is not None:
        path = Path(data_dir) / "captcha_map.json"
        if path.is_file():
            return path
    return None


class CaptchaMap:
    def __init__(self, entries: dict[str, str]) -> None:
        self._answers = entries

    @classmethod
    def load(cls, path: Path) -> CaptchaMap:
        raw = json.loads(path.read_text(encoding="utf-8"))
        answers: dict[str, str] = {}
        if isinstance(raw, dict):
            for key, value in raw.items():
                if not isinstance(key, str):
                    continue
                if isinstance(value, dict):
                    answer = value.get("answer")
                else:
                    answer = value
                if not isinstance(answer, str) or not answer:
                    continue
                answers[key] = answer
                if isinstance(value, dict):
                    src_url = value.get("src_url")
                    if isinstance(src_url, str):
                        src_hash = hash_captcha_data_url(src_url)
                        if src_hash:
                            answers[src_hash] = answer
        return cls(answers)

    def lookup(self, image_hash: str) -> str | None:
        return self._answers.get(image_hash)

    def __len__(self) -> int:
        return len(self._answers)

