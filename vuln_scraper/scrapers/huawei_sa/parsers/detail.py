from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class HuaweiSADetailRecord:
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.raw)


def parse_detail_payload(content: Any) -> HuaweiSADetailRecord:
    if isinstance(content, dict):
        return HuaweiSADetailRecord(raw=content)
    return HuaweiSADetailRecord()
