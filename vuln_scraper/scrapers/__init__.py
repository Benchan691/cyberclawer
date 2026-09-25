"""Provider registry.

Providers are self-contained packages under ``vuln_scraper/scrapers/<key>/``.
A package participates in the registry simply by existing: it must contain a
``provider.py`` module that either exports ``PROVIDER_CLASS`` or defines a
class whose ``key`` attribute equals the package directory name and implements
the :class:`ScraperProvider` protocol.  There is no central import list —
adding a provider means dropping in a directory, removing one means deleting
it.  Packages that fail to import or do not conform are skipped with a warning.
"""

from __future__ import annotations

import dataclasses
import importlib
import logging
from pathlib import Path
from typing import Any, Literal, Protocol

from vuln_scraper.models import ListPage

logger = logging.getLogger(__name__)


class ScraperProvider(Protocol):
    key: str
    source_url: str
    default_mongo_collection: str
    content_type: Literal["html", "json"]
    default_request_delay: float
    stop_on_first_known: bool

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str: ...

    def detail_url(self, identity_display: str) -> str: ...

    def parse_list(self, content: Any, *, page: int) -> ListPage: ...

    def parse_detail(self, content: Any) -> Any: ...


_DISCOVERED: dict[str, type[ScraperProvider]] | None = None


def _declared_key(cls: type) -> str | None:
    """Read a provider class's declared ``key`` (works for slots dataclasses)."""
    if dataclasses.is_dataclass(cls):
        for field in dataclasses.fields(cls):
            if field.name == "key" and field.default is not dataclasses.MISSING:
                return str(field.default)
    value = getattr(cls, "key", None)
    return value if isinstance(value, str) else None


def _provider_class_from_module(module: Any, package_name: str) -> type[ScraperProvider] | None:
    """Find the provider class in a ``provider.py`` module."""
    explicit = getattr(module, "PROVIDER_CLASS", None)
    if explicit is not None:
        return explicit
    candidates = [
        obj
        for obj in vars(module).values()
        if isinstance(obj, type)
        and _declared_key(obj) == package_name
        and callable(getattr(obj, "parse_list", None))
        and callable(getattr(obj, "parse_detail", None))
    ]
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise ValueError(f"multiple provider classes match key {package_name!r}")
    return None


def _discover_providers() -> dict[str, type[ScraperProvider]]:
    discovered: dict[str, type[ScraperProvider]] = {}
    package_dir = Path(__file__).parent
    for entry in sorted(package_dir.iterdir(), key=lambda item: item.name):
        if not entry.is_dir() or entry.name.startswith("_") or entry.name == "__pycache__":
            continue
        package_name = entry.name
        try:
            module = importlib.import_module(f".{package_name}.provider", __package__)
            provider_class = _provider_class_from_module(module, package_name)
        except Exception as exc:  # noqa: BLE001 - a broken plugin must not kill the CLI
            logger.warning("Skipping provider package %s: %s", package_name, exc)
            continue
        if provider_class is None:
            logger.warning(
                "Skipping provider package %s: no provider class found in provider.py",
                package_name,
            )
            continue
        discovered[package_name] = provider_class
    return discovered


def _providers() -> dict[str, type[ScraperProvider]]:
    global _DISCOVERED
    if _DISCOVERED is None:
        _DISCOVERED = _discover_providers()
    return _DISCOVERED


# Kept as a public alias for backward compatibility; populated lazily.
def __getattr__(name: str) -> Any:
    if name == "PROVIDERS":
        return _providers()
    # Allow ``from vuln_scraper.scrapers import <X>Provider`` for any
    # discovered provider class without a central import list.
    for provider_class in _providers().values():
        if provider_class.__name__ == name:
            return provider_class
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def provider_keys() -> tuple[str, ...]:
    return tuple(sorted(_providers()))


def get_provider(key: str) -> ScraperProvider:
    factory = _providers().get(key)
    if factory is None:
        choices = ", ".join(sorted(_providers()))
        raise KeyError(f"unknown provider {key!r}; choose one of: {choices}")
    return factory()


def all_providers() -> list[ScraperProvider]:
    return [factory() for factory in _providers().values()]
