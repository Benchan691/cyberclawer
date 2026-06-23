from __future__ import annotations

import csv
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CpeCandidate:
    vendor: str
    product: str
    cpe: str
    title: str

    @property
    def text(self) -> str:
        return f"{self.vendor} {self.product} {self.title} {self.cpe}"


def default_dictionary_path() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "cpes.csv"


def resolve_dictionary_path(path: str | Path | None = None) -> Path:
    raw = os.getenv("CPE_DICTIONARY_PATH") or path
    candidate = Path(raw) if raw else default_dictionary_path()
    if not candidate.is_absolute():
        candidate = Path(__file__).resolve().parent / candidate
    return candidate


def cpe_fingerprint(path: str | Path | None = None) -> str:
    dictionary = resolve_dictionary_path(path)
    return hashlib.sha256(dictionary.read_bytes()).hexdigest()[:16]


def vendor_product_from_cpe(cpe: str) -> tuple[str, str]:
    vendor, product = _parse_cpe(cpe)
    return _display(vendor), _display(product)


@dataclass(frozen=True)
class LookupResult:
    candidate: CpeCandidate
    confidence: float
    evidence: str
    match_type: str


class CpeDictionaryLookup:
    def __init__(
        self,
        *,
        dictionary_path: str | Path | None = None,
        candidates: list[CpeCandidate] | None = None,
    ) -> None:
        self.dictionary_path = dictionary_path
        self.candidates = candidates if candidates is not None else load_cpe_dictionary(dictionary_path)
        self.dictionary_version = (
            "in-memory" if candidates is not None else cpe_fingerprint(dictionary_path)
        )
        self._by_cpe = {candidate.cpe.casefold(): candidate for candidate in self.candidates}
        self._by_vendor_product = {
            (candidate.vendor.casefold(), candidate.product.casefold()): candidate
            for candidate in self.candidates
        }
        self._by_normalized_vendor_product = {
            (
                _normalize_vendor_for_lookup(candidate.vendor),
                _normalize_product_for_lookup(candidate.vendor, candidate.product),
            ): candidate
            for candidate in self.candidates
        }
        labels: list[tuple[str, CpeCandidate]] = []
        seen_labels: set[str] = set()
        for candidate in self.candidates:
            for label in (_normalize_label(f"{candidate.vendor} {candidate.product}"), _normalize_label(candidate.title)):
                if label and label not in seen_labels:
                    seen_labels.add(label)
                    labels.append((label, candidate))
        self._labels = sorted(labels, key=lambda item: len(item[0]), reverse=True)

    def lookup(self, evidence: list[Any]) -> LookupResult | None:
        for item in evidence:
            cpe = getattr(item, "cpe", None) or (item.get("cpe") if isinstance(item, dict) else None)
            if cpe:
                candidate = self._by_cpe.get(str(cpe).casefold())
                if candidate is not None:
                    return LookupResult(candidate, 1.0, str(cpe), "cpe")

        for item in evidence:
            vendor = getattr(item, "vendor", None) or (item.get("vendor") if isinstance(item, dict) else None)
            product = getattr(item, "product", None) or (item.get("product") if isinstance(item, dict) else None)
            if vendor and product:
                lookup_keys = [
                    (str(vendor).casefold(), str(product).casefold()),
                    (
                        _normalize_vendor_for_lookup(str(vendor)),
                        _normalize_product_for_lookup(str(vendor), str(product)),
                    ),
                ]
                candidate = None
                for lookup_key in lookup_keys:
                    candidate = self._by_vendor_product.get(lookup_key)
                    if candidate is not None:
                        break
                if candidate is None:
                    candidate = self._by_normalized_vendor_product.get(lookup_keys[1])
                if candidate is not None:
                    evidence_text = f"{vendor} {product}"
                    return LookupResult(candidate, 1.0, evidence_text, "vendor_product")

        for item in evidence:
            text = getattr(item, "text", None) or (item.get("text") if isinstance(item, dict) else None)
            if not text:
                continue
            candidate = self._lookup_text(str(text))
            if candidate is not None:
                return LookupResult(candidate, 1.0, str(text), "text")

        return None

    def lookup_cpe_strings(self, strings: list[str]) -> LookupResult | None:
        for text in strings:
            candidate = self._by_cpe.get(text.casefold())
            if candidate is not None:
                return LookupResult(candidate, 1.0, text, "cpe")
        return None

    def _lookup_text(self, text: str) -> CpeCandidate | None:
        normalized = _normalize_label(text)
        if not normalized:
            return None
        matches: list[tuple[int, CpeCandidate]] = []
        for label, candidate in self._labels:
            if label in normalized:
                matches.append((len(label), candidate))
        if not matches:
            return None
        best_len = max(length for length, _ in matches)
        best = [candidate for length, candidate in matches if length == best_len]
        unique = {candidate.cpe for candidate in best}
        if len(unique) != 1:
            return None
        return best[0]


def _normalize_label(text: str) -> str:
    return " ".join(text.casefold().split())


def _synthesize_cpe(vendor: str, product: str, *, part: str = "a") -> str:
    return f"cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*"


def load_cpe_dictionary(path: str | Path | None = None) -> list[CpeCandidate]:
    dictionary = resolve_dictionary_path(path)
    with dictionary.open(newline="", encoding="utf-8") as handle:
        rows = csv.DictReader(handle)
        candidates: list[CpeCandidate] = []
        seen: set[tuple[str, str]] = set()
        for row in rows:
            if str(_first(row, "deprecated", "is_deprecated")).strip().lower() in {"1", "true", "yes"}:
                continue
            cpe = _first(row, "cpe", "cpe23Uri", "cpe23_uri", "criteria", "uri")
            parsed_vendor, parsed_product = _parse_cpe(cpe)
            slug_vendor = _first(row, "vendor", "part_vendor") or parsed_vendor
            slug_product = _first(row, "product", "part_product") or parsed_product
            if not cpe and slug_vendor and slug_product:
                cpe = _synthesize_cpe(slug_vendor, slug_product)
            vendor = _display(slug_vendor)
            product = _display(slug_product)
            if not cpe or not vendor or not product:
                continue
            key = (vendor.casefold(), product.casefold())
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                CpeCandidate(
                    vendor=vendor,
                    product=product,
                    cpe=cpe,
                    title=_first(row, "title", "name") or f"{vendor} {product}",
                )
            )
    return candidates


class CpeIndex:
    def __init__(self, embeddings: list[Any]) -> None:
        self.embeddings = embeddings
        self._faiss_index = None
        try:
            import faiss
            import numpy as np

            matrix = np.asarray(embeddings, dtype="float32")
            index = faiss.IndexFlatIP(matrix.shape[1])
            index.add(matrix)
            self._faiss_index = index
        except Exception:
            pass

    def search(self, embedding: Any, *, k: int = 1) -> list[tuple[int, float]]:
        if self._faiss_index is not None:
            import numpy as np

            scores, indexes = self._faiss_index.search(np.asarray([embedding], dtype="float32"), k)
            return [(int(index), float(score)) for index, score in zip(indexes[0], scores[0]) if index >= 0]

        scored = [
            (index, _cosine(embedding, candidate))
            for index, candidate in enumerate(self.embeddings)
        ]
        return sorted(scored, key=lambda item: item[1], reverse=True)[:k]


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _normalize_vendor_for_lookup(vendor: str) -> str:
    return re.sub(r"[^a-z0-9]", "", vendor.casefold())


def _normalize_product_for_lookup(vendor: str, product: str) -> str:
    text = product.casefold().strip()
    vendor_fold = vendor.casefold().strip()
    if vendor_fold and text.startswith(vendor_fold):
        text = text[len(vendor_fold) :].strip()
    text = re.sub(r"\s+\d+([.\d]*)*$", "", text).strip()
    return _normalize_label(text.replace("_", " "))


def _parse_cpe(cpe: str) -> tuple[str, str]:
    parts = _split_cpe(cpe)
    if len(parts) > 4 and parts[:2] == ["cpe", "2.3"]:
        return (parts[3], parts[4])
    if len(parts) > 3 and parts[0] == "cpe" and parts[1].startswith("/"):
        return (parts[2], parts[3])
    return ("", "")


def _split_cpe(cpe: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in cpe:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _display(value: str) -> str:
    return value.replace("_", " ").strip()


def _vector(value: Any) -> list[float]:
    if hasattr(value, "tolist"):
        value = value.tolist()
    return [float(item) for item in value]


def _cosine(left: Any, right: Any) -> float:
    a = _vector(left)
    b = _vector(right)
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    left_norm = sum(x * x for x in a) ** 0.5
    right_norm = sum(y * y for y in b) ** 0.5
    return dot / (left_norm * right_norm) if left_norm and right_norm else 0.0
