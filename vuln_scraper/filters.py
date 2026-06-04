from __future__ import annotations

from .config import MAX_RESULT_LIMIT


def validate_limit(value: int) -> int:
    if not 1 <= value <= MAX_RESULT_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_RESULT_LIMIT}")
    return value
