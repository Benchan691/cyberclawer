from __future__ import annotations

from typing import Any

try:
    from .cpe_dictionary import CpeCandidate, CpeDictionaryLookup, CpeIndex, cpe_fingerprint, load_cpe_dictionary
    from .cve_cpe import extract_embedding_evidence, extract_vendor_product_evidence
    from .logging_utils import log_event
    from .mongo_utils import utc_now_iso
except ImportError:
    from cpe_dictionary import CpeCandidate, CpeDictionaryLookup, CpeIndex, cpe_fingerprint, load_cpe_dictionary
    from cve_cpe import extract_embedding_evidence, extract_vendor_product_evidence
    from logging_utils import log_event
    from mongo_utils import utc_now_iso


COMPONENT = "vendor-product-zero-shot"


def log(message: str, *, level: str = "INFO", **fields: Any) -> None:
    log_event(COMPONENT, message, level=level, **fields)


class EmbeddingZeroShotClassifier:
    def __init__(
        self,
        *,
        model_name: str,
        confidence_threshold: float,
        dictionary_path: str | None = None,
        candidates: list[CpeCandidate] | None = None,
        model: Any = None,
        lookup: CpeDictionaryLookup | None = None,
    ) -> None:
        self.model_name = model_name
        self.confidence_threshold = confidence_threshold
        self.dictionary_path = dictionary_path
        self.candidates = candidates if candidates is not None else load_cpe_dictionary(dictionary_path)
        self.dictionary_version = "in-memory" if candidates is not None else cpe_fingerprint(dictionary_path)
        self.lookup = lookup or CpeDictionaryLookup(
            dictionary_path=dictionary_path,
            candidates=self.candidates,
        )
        self.model = model
        self._candidate_embeddings: list[Any] | None = None
        self._index: CpeIndex | None = None
        log(
            "zero-shot classifier initialized",
            model_name=self.model_name,
            confidence_threshold=self.confidence_threshold,
            dictionary_version=self.dictionary_version,
            candidates=len(self.candidates),
            lazy_model_load=self.model is None,
        )

    def _load_model(self) -> Any:
        if self.model is None:
            log("loading sentence-transformers model", model_name=self.model_name)
            from sentence_transformers import SentenceTransformer

            self.model = SentenceTransformer(self.model_name)
            log("sentence-transformers model loaded", model_name=self.model_name)
        return self.model

    def _encode(self, texts: list[str]) -> list[Any]:
        model = self._load_model()
        try:
            embeddings = model.encode(texts, normalize_embeddings=True)
        except TypeError:
            embeddings = model.encode(texts)
        return embeddings.tolist() if hasattr(embeddings, "tolist") else list(embeddings)

    def _ensure_index(self) -> CpeIndex:
        if self._index is None:
            self._candidate_embeddings = self._encode([candidate.text for candidate in self.candidates])
            self._index = CpeIndex(self._candidate_embeddings)
        return self._index

    def classify(self, document: dict[str, Any]) -> dict[str, Any]:
        evidence = extract_embedding_evidence(document)
        if not evidence:
            return {"classified": False, "confidence": 0.0, "reason": "no evidence"}
        if not self.candidates:
            return {"classified": False, "confidence": 0.0, "reason": "empty CPE dictionary"}

        hit = self.lookup.lookup(extract_vendor_product_evidence(document))
        if hit is None:
            hit = self.lookup.lookup_cpe_strings(evidence)
        if hit is not None:
            return self._result(hit.candidate, hit.confidence, hit.evidence, classified=True, method="zero_shot")

        index = self._ensure_index()
        best_candidate = self.candidates[0]
        best_score = -1.0
        best_evidence = evidence[0]
        for text, embedding in zip(evidence, self._encode(evidence)):
            for candidate_index, score in index.search(embedding, k=1):
                if score > best_score:
                    best_candidate = self.candidates[candidate_index]
                    best_score = score
                    best_evidence = text

        return self._result(
            best_candidate,
            best_score,
            best_evidence,
            classified=best_score >= self.confidence_threshold,
            method="zero_shot",
        )

    def _result(
        self,
        candidate: CpeCandidate,
        confidence: float,
        evidence: str,
        *,
        classified: bool,
        method: str = "zero_shot",
    ) -> dict[str, Any]:
        result = {
            "classified": classified,
            "vendor": candidate.vendor,
            "product": candidate.product,
            "cpe": candidate.cpe,
            "confidence": float(confidence),
            "dictionary_version": self.dictionary_version,
            "evidence": evidence,
            "method": method,
        }
        if not classified:
            result["reason"] = "confidence below threshold"
        return result


def zero_shot_from_config(config: dict[str, Any]) -> EmbeddingZeroShotClassifier:
    zero_shot = config["zero_shot"]
    dictionary_path = (config.get("cpe_dictionary") or {}).get("path")
    return EmbeddingZeroShotClassifier(
        model_name=zero_shot["model_name"],
        confidence_threshold=float(zero_shot["confidence_threshold"]),
        dictionary_path=str(dictionary_path) if dictionary_path else None,
    )


def reload_zero_shot_if_needed(
    classifier: EmbeddingZeroShotClassifier | None,
    config: dict[str, Any],
) -> EmbeddingZeroShotClassifier | None:
    if not bool(config.get("zero_shot", {}).get("enabled")):
        return None
    if classifier is None:
        return zero_shot_from_config(config)
    dictionary_path = (config.get("cpe_dictionary") or {}).get("path")
    dictionary_version = cpe_fingerprint(str(dictionary_path) if dictionary_path else None)
    if classifier.dictionary_version == dictionary_version:
        return classifier
    log(
        "CPE dictionary changed; reloading zero-shot labels",
        previous_dictionary_version=classifier.dictionary_version,
        dictionary_version=dictionary_version,
    )
    return zero_shot_from_config(config)


def disabled_classification() -> dict[str, Any]:
    return {
        "status": "unclassified",
        "reason": "zero-shot disabled",
        "confidence": 0.0,
        "updated_at": utc_now_iso(),
    }


def success_classification(result: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "status": "classified",
        "vendor": result["vendor"],
        "product": result["product"],
        "cpe": result["cpe"],
        "confidence": float(result["confidence"]),
        "dictionary_version": result.get("dictionary_version"),
        "updated_at": utc_now_iso(),
    }
    if result.get("method"):
        payload["method"] = result["method"]
    return payload


def low_confidence_classification(result: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "status": "unclassified",
        "reason": result.get("reason") or "confidence below threshold",
        "confidence": float(result.get("confidence") or 0.0),
        "dictionary_version": result.get("dictionary_version"),
        "updated_at": utc_now_iso(),
    }
    if result.get("vendor") or result.get("product") or result.get("cpe"):
        payload["candidate"] = {
            "vendor": result.get("vendor"),
            "product": result.get("product"),
            "cpe": result.get("cpe"),
        }
    return payload
