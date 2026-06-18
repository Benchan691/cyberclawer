from __future__ import annotations

import html
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


GENERIC_ALIASES = {
    "linux",
    "windows",
    "server",
    "manager",
    "router",
    "switch",
    "kernel",
    "browser",
    "database",
}

STRONG_FIELD_NAMES = (
    "product_names",
    "affectedProduct",
    "affectedSystem",
    "affected_products",
    "affected_software",
    "products",
    "product_status",
    "product_statuses",
    "vulnerabilities",
    "configurations",
)

WEAK_FIELD_NAMES = (
    "summary",
    "description",
    "vulDesc",
    "productDesc",
    "impact",
    "solution",
    "recommendation",
    "raw",
)


@dataclass(frozen=True)
class AliasCandidate:
    vendor: str
    product: str
    alias: str
    normalized_alias: str


@dataclass(frozen=True)
class VendorCandidate:
    vendor: str
    alias: str
    normalized_alias: str


@dataclass(frozen=True)
class MatchResult:
    vendor: str
    product: str
    confidence: float
    method: str
    matched_alias: str
    matched_text: str


def default_aliases_path() -> Path:
    return Path(__file__).resolve().parent / "aliases.json"


def normalize_text(value: Any) -> str:
    text = html.unescape(str(value or ""))
    chars: list[str] = []
    for char in text.casefold():
        if char in {"®", "™", "©", "℠"}:
            continue
        if char.isalnum():
            chars.append(char)
        else:
            chars.append(" ")
    return " ".join("".join(chars).split())


def is_generic_alias(alias: str) -> bool:
    return normalize_text(alias) in GENERIC_ALIASES


def phrase_in_text(normalized_alias: str, normalized_text: str) -> bool:
    if not normalized_alias or not normalized_text:
        return False
    return f" {normalized_alias} " in f" {normalized_text} "


def load_aliases(path: str | Path | None = None) -> list[dict[str, Any]]:
    alias_path = Path(path) if path is not None else default_aliases_path()
    with alias_path.open(encoding="utf-8") as handle:
        aliases = json.load(handle)
    if not isinstance(aliases, list):
        raise ValueError("aliases.json must contain a list")
    return aliases


def aliases_fingerprint(aliases: Iterable[dict[str, Any]] | None = None) -> str:
    materialized = list(aliases) if aliases is not None else load_aliases()
    payload = json.dumps(
        materialized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def build_candidates(aliases: Iterable[dict[str, Any]]) -> list[AliasCandidate]:
    candidates: list[AliasCandidate] = []
    for entry in aliases:
        vendor = str(entry.get("vendor") or "").strip()
        product = str(entry.get("product") or "").strip()
        if not vendor or not product:
            continue
        names = list(entry.get("aliases") or [])
        names.append(f"{vendor} {product}")
        seen: set[str] = set()
        for alias in names:
            alias_text = str(alias or "").strip()
            normalized = normalize_text(alias_text)
            if not alias_text or not normalized or normalized in seen:
                continue
            seen.add(normalized)
            if is_generic_alias(alias_text):
                continue
            candidates.append(
                AliasCandidate(
                    vendor=vendor,
                    product=product,
                    alias=alias_text,
                    normalized_alias=normalized,
                )
            )
    return sorted(
        candidates,
        key=lambda candidate: (
            len(candidate.normalized_alias.split()),
            len(candidate.normalized_alias),
        ),
        reverse=True,
    )


def build_vendor_candidates(aliases: Iterable[dict[str, Any]]) -> list[VendorCandidate]:
    candidates: list[VendorCandidate] = []
    seen: set[str] = set()
    for entry in aliases:
        vendor = str(entry.get("vendor") or "").strip()
        if not vendor:
            continue
        normalized = normalize_text(vendor)
        if not normalized or normalized in seen or normalized in GENERIC_ALIASES:
            continue
        seen.add(normalized)
        candidates.append(
            VendorCandidate(
                vendor=vendor,
                alias=vendor,
                normalized_alias=normalized,
            )
        )
    return sorted(
        candidates,
        key=lambda candidate: (
            len(candidate.normalized_alias.split()),
            len(candidate.normalized_alias),
        ),
        reverse=True,
    )


def flatten_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = html.unescape(value).strip()
        return [text] if text else []
    if isinstance(value, dict):
        texts: list[str] = []
        for item in value.values():
            texts.extend(flatten_strings(item))
        return texts
    if isinstance(value, (list, tuple, set)):
        texts = []
        for item in value:
            texts.extend(flatten_strings(item))
        return texts
    return []


def _provider_details(document: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    details = document.get("details")
    if not isinstance(details, dict):
        return []
    return [
        (str(provider), detail)
        for provider, detail in details.items()
        if isinstance(detail, dict)
    ]


def _field_texts(
    document: dict[str, Any],
    *,
    include_title: bool,
    field_names: Iterable[str],
) -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = []
    if include_title:
        for text in flatten_strings(document.get("title")):
            texts.append(("title", text))
    for provider, detail in _provider_details(document):
        for field_name in field_names:
            if field_name not in detail:
                continue
            for text in flatten_strings(detail.get(field_name)):
                texts.append((f"details.{provider}.{field_name}", text))
    return texts


def strong_field_texts(document: dict[str, Any]) -> list[tuple[str, str]]:
    return _field_texts(
        document,
        include_title=False,
        field_names=STRONG_FIELD_NAMES,
    )


def weak_field_texts(document: dict[str, Any]) -> list[tuple[str, str]]:
    return _field_texts(
        document,
        include_title=True,
        field_names=WEAK_FIELD_NAMES,
    )


def evidence_texts(document: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for _, text in strong_field_texts(document) + weak_field_texts(document):
        normalized = " ".join(text.split())
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


class RuleAliasMatcher:
    def __init__(
        self,
        candidates: Iterable[AliasCandidate],
        vendor_candidates: Iterable[VendorCandidate] | None = None,
        *,
        taxonomy_version: str | None = None,
    ) -> None:
        self.candidates = list(candidates)
        self.vendor_candidates = list(vendor_candidates or [])
        self.taxonomy_version = taxonomy_version

    @classmethod
    def from_aliases(cls, aliases: Iterable[dict[str, Any]]) -> "RuleAliasMatcher":
        materialized = list(aliases)
        return cls(
            build_candidates(materialized),
            build_vendor_candidates(materialized),
            taxonomy_version=aliases_fingerprint(materialized),
        )

    @classmethod
    def from_file(cls, path: str | Path | None = None) -> "RuleAliasMatcher":
        return cls.from_aliases(load_aliases(path))

    def _match_texts(
        self,
        texts: Iterable[tuple[str, str]],
        *,
        method: str,
    ) -> MatchResult | None:
        for _, text in texts:
            normalized_text = normalize_text(text)
            if not normalized_text:
                continue
            for candidate in self.candidates:
                if phrase_in_text(candidate.normalized_alias, normalized_text):
                    return MatchResult(
                        vendor=candidate.vendor,
                        product=candidate.product,
                        confidence=1.0,
                        method=method,
                        matched_alias=candidate.alias,
                        matched_text=text,
                    )
        return None

    def _match_vendor_texts(
        self,
        texts: Iterable[tuple[str, str]],
        *,
        method: str,
    ) -> MatchResult | None:
        for _, text in texts:
            normalized_text = normalize_text(text)
            if not normalized_text:
                continue
            for candidate in self.vendor_candidates:
                if phrase_in_text(candidate.normalized_alias, normalized_text):
                    return MatchResult(
                        vendor=candidate.vendor,
                        product="",
                        confidence=0.7,
                        method=method,
                        matched_alias=candidate.alias,
                        matched_text=text,
                    )
        return None

    def match_document(self, document: dict[str, Any]) -> MatchResult | None:
        strong = self._match_texts(
            strong_field_texts(document),
            method="rule_alias_strong",
        )
        if strong is not None:
            return strong
        return self._match_texts(
            weak_field_texts(document),
            method="rule_alias_weak",
        )

    def match_vendor_document(self, document: dict[str, Any]) -> MatchResult | None:
        return self._match_vendor_texts(
            strong_field_texts(document) + weak_field_texts(document),
            method="rule_alias_vendor",
        )
