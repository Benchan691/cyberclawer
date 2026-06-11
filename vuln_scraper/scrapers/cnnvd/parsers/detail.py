from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


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
        data = payload.get("data")
        if isinstance(data, dict):
            for key in ("cnnvdDetail", "receviceVulDetail"):
                item = data.get(key)
                if isinstance(item, dict):
                    return dict(item)
        if payload.get("cnnvdCode") or payload.get("vulName"):
            return dict(payload)
    raise ValueError("CNNVD detail response did not contain a vulnerability object")


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
