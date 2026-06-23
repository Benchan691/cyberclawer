from __future__ import annotations

import argparse
import sys
from dataclasses import asdict, dataclass
from typing import Any

try:
    from .cpe_dictionary import CpeDictionaryLookup, cpe_fingerprint
    from .cve_cpe import extract_vendor_product_evidence
    from .mongo_utils import (
        create_mongo_client,
        get_database,
        load_config,
        utc_now_iso,
        write_classification,
    )
    from .zero_shot_worker import (
        EmbeddingZeroShotClassifier,
        _disabled_classification,
        _low_confidence_classification,
        _success_classification,
    )
except ImportError:
    from cpe_dictionary import CpeDictionaryLookup, cpe_fingerprint
    from cve_cpe import extract_vendor_product_evidence
    from mongo_utils import (
        create_mongo_client,
        get_database,
        load_config,
        utc_now_iso,
        write_classification,
    )
    from zero_shot_worker import (
        EmbeddingZeroShotClassifier,
        _disabled_classification,
        _low_confidence_classification,
        _success_classification,
    )


COMPARE_FIELDS = (
    "status",
    "vendor",
    "product",
    "cpe",
    "confidence",
    "method",
    "reason",
    "candidate",
    "dictionary_version",
    "classifier_version",
)


@dataclass(slots=True)
class ReclassifyResult:
    scanned: int = 0
    updated: int = 0
    unchanged: int = 0
    classified: int = 0
    unclassified: int = 0
    skipped: int = 0
    errors: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _dictionary_path(config: dict[str, Any]) -> str | None:
    value = (config.get("cpe_dictionary") or {}).get("path")
    return str(value) if value else None


def _lookup_from_config(config: dict[str, Any]) -> CpeDictionaryLookup:
    return CpeDictionaryLookup(dictionary_path=_dictionary_path(config))


def _zero_shot_from_config(config: dict[str, Any]) -> EmbeddingZeroShotClassifier:
    zero_shot = config["zero_shot"]
    return EmbeddingZeroShotClassifier(
        model_name=zero_shot["model_name"],
        confidence_threshold=float(zero_shot["confidence_threshold"]),
        dictionary_path=_dictionary_path(config),
    )


def _normalize_candidate(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    candidate = {
        key: str(value.get(key) or "").strip()
        for key in ("vendor", "product", "cpe")
        if value.get(key)
    }
    return candidate or None


def _classification_signature(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    signature: dict[str, Any] = {}
    for field in COMPARE_FIELDS:
        item = value.get(field)
        if field == "candidate":
            item = _normalize_candidate(item)
        elif field in {"confidence"} and item is not None:
            item = round(float(item), 4)
        elif item is not None and field not in {"candidate"}:
            item = str(item).strip()
        if item not in (None, "", {}, []):
            signature[field] = item
    return signature


def classification_changed(before: Any, after: dict[str, Any]) -> bool:
    return _classification_signature(before) != _classification_signature(after)


def classify_cve_document(
    document: dict[str, Any],
    config: dict[str, Any],
    *,
    lookup: CpeDictionaryLookup | None = None,
    zero_shot_classifier: EmbeddingZeroShotClassifier | None = None,
    use_zero_shot: bool = False,
) -> dict[str, Any]:
    dictionary_enabled = bool((config.get("dictionary_lookup") or {}).get("enabled", True))
    if dictionary_enabled:
        lookup = lookup or _lookup_from_config(config)
        hit = lookup.lookup(extract_vendor_product_evidence(document))
        if hit is not None:
            return {
                "status": "classified",
                "vendor": hit.candidate.vendor,
                "product": hit.candidate.product,
                "cpe": hit.candidate.cpe,
                "confidence": hit.confidence,
                "method": "dictionary",
                "dictionary_version": lookup.dictionary_version,
                "updated_at": utc_now_iso(),
            }

    if not use_zero_shot or not bool(config.get("zero_shot", {}).get("enabled")):
        return {
            "status": "unclassified",
            "reason": "dictionary miss",
            "dictionary_version": cpe_fingerprint(_dictionary_path(config)),
            "updated_at": utc_now_iso(),
        }

    zero_shot_classifier = zero_shot_classifier or _zero_shot_from_config(config)
    result = zero_shot_classifier.classify(document)
    if result.get("classified"):
        return _success_classification(result)
    if not bool(config.get("zero_shot", {}).get("enabled")):
        return _disabled_classification()
    return _low_confidence_classification(result)


def reclassify_cve(
    database: Any,
    config: dict[str, Any],
    *,
    collection_name: str = "cve",
    dry_run: bool = True,
    limit: int | None = None,
    use_zero_shot: bool = False,
) -> ReclassifyResult:
    collection = database[collection_name]
    lookup = _lookup_from_config(config) if (config.get("dictionary_lookup") or {}).get("enabled", True) else None
    zero_shot_classifier = _zero_shot_from_config(config) if use_zero_shot else None
    result = ReclassifyResult()

    cursor = collection.find({})
    if limit is not None:
        cursor = cursor.limit(limit)

    for document in cursor:
        result.scanned += 1
        document_id = str(document.get("_id") or "")
        if not document_id:
            result.skipped += 1
            continue
        try:
            classification = classify_cve_document(
                document,
                config,
                lookup=lookup,
                zero_shot_classifier=zero_shot_classifier,
                use_zero_shot=use_zero_shot,
            )
        except Exception:
            result.errors += 1
            continue

        if not classification_changed(document.get("classification"), classification):
            result.unchanged += 1
            continue

        result.updated += 1
        if classification.get("status") == "classified":
            result.classified += 1
        else:
            result.unclassified += 1

        if not dry_run:
            write_classification(collection, document_id, classification)

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="One-time CVE vendor/product reclassification against the current CPE dictionary.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report how many documents would change without writing to MongoDB.",
    )
    parser.add_argument(
        "--database",
        default=None,
        help="MongoDB database name override.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum CVE documents to scan.",
    )
    parser.add_argument(
        "--zero-shot",
        action="store_true",
        help="Run embedding classification when dictionary lookup misses (slow on large collections).",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Classifier config JSON path (default: vendor_product_classifier/config/classifier.json).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config, require_secrets=not bool(args.database))
    if args.database:
        config["mongo"]["database"] = args.database

    client = create_mongo_client(config)
    try:
        database = get_database(client, config)
        result = reclassify_cve(
            database,
            config,
            dry_run=args.dry_run,
            limit=args.limit,
            use_zero_shot=args.zero_shot,
        )
    finally:
        client.close()

    action = "would_update" if args.dry_run else "updated"
    print(
        "reclassify-cve: "
        f"scanned={result.scanned} "
        f"{action}={result.updated} "
        f"unchanged={result.unchanged} "
        f"classified={result.classified} "
        f"unclassified={result.unclassified} "
        f"skipped={result.skipped} "
        f"errors={result.errors}"
    )
    return 1 if result.errors else 0


if __name__ == "__main__":
    sys.exit(main())
