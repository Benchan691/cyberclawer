from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class RansomwareLiveVictimRecord:
    victim: str | None = None
    group: str | None = None
    attackdate: str | None = None
    discovered: str | None = None
    country: str | None = None
    activity: str | None = None
    website: str | None = None
    screenshot: str | None = None
    infostealer: Any = None
    press: Any = None
    permalink: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_victim_response(data: Any) -> RansomwareLiveVictimRecord:
    payload = _coerce_json(data)
    victim = _extract_victim(payload)
    return RansomwareLiveVictimRecord(
        victim=_optional_str(_first_present(victim, "victim", "post_title")),
        group=_optional_str(_first_present(victim, "group", "group_name")),
        attackdate=_optional_str(_first_present(victim, "attackdate", "published")),
        discovered=_optional_str(victim.get("discovered")),
        country=_optional_str(victim.get("country")),
        activity=_optional_str(_first_present(victim, "activity", "sector")),
        website=_optional_str(victim.get("website")),
        screenshot=_optional_str(victim.get("screenshot")),
        infostealer=victim.get("infostealer"),
        press=victim.get("press"),
        permalink=_optional_str(victim.get("permalink")),
        raw=dict(victim),
    )


def _extract_victim(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        for key in ("victim", "data", "result"):
            value = payload.get(key)
            if isinstance(value, dict):
                return dict(value)
        if payload.get("id") or payload.get("victim") or payload.get("post_title"):
            return dict(payload)
    raise ValueError("ransomware.live victim response did not contain a victim object")


def _first_present(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if value is not None:
            return value
    return None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
