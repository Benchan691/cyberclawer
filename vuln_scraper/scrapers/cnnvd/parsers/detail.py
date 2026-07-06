from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from vuln_scraper.client import CaptchaRequiredError


@dataclass(slots=True)
class CNNVDDetailRecord:
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return dict(self.data)


def parse_vulnerability_detail(data: Any) -> CNNVDDetailRecord:
    payload = _coerce_json(data)
    return CNNVDDetailRecord(_detail_payload(payload))


def _detail_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        _raise_if_captcha_required(payload)
        if payload.get("success") is False:
            message = payload.get("message") or payload.get("msg") or "unknown API error"
            code = payload.get("code")
            raise ValueError(f"CNNVD detail API error {code}: {message}")
        data = payload.get("data")
        if isinstance(data, dict):
            if _looks_like_detail(data):
                return dict(data)
            for key in ("cnnvdDetail", "receviceVulDetail"):
                item = data.get(key)
                if isinstance(item, dict):
                    return dict(item)
        if _looks_like_detail(payload):
            return dict(payload)
    raise ValueError("CNNVD detail response did not contain a vulnerability object")


def _raise_if_captcha_required(payload: dict[str, Any]) -> None:
    message = str(payload.get("message") or payload.get("msg") or "")
    code = str(payload.get("code") or "")
    if code == "4010" or "人机验证" in message:
        raise CaptchaRequiredError(f"CNNVD captcha required: {message or code}")


def _looks_like_detail(payload: dict[str, Any]) -> bool:
    return any(
        payload.get(key)
        for key in (
            "id",
            "cnnvdId",
            "cnnvdCode",
            "cveId",
            "cveCode",
            "vulName",
            "vulDesc",
            "vulDetail",
        )
    )


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
