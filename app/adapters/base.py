"""
CTIR Adapter Layer — Base Protocol & Registry
Every output-format adapter must implement AdapterBase.
The registry allows the API to dispatch by format name at runtime.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from fastapi.responses import Response

from app.adapters.query_filter import AdapterQueryFilter
from app.core.logging import get_logger

logger = get_logger(__name__)


@runtime_checkable
class AdapterBase(Protocol):
    """
    Contract every adapter must satisfy.

    serialize() receives a list of raw ORM Ioc instances plus helper callables
    and returns a FastAPI Response (with the correct Content-Type already set).
    """

    #: Human-readable name shown in the registry listing
    name: str

    #: MIME type for the HTTP response Content-Type header
    media_type: str

    #: Short description for the /adapter/formats listing
    description: str

    def serialize(
        self,
        iocs: list[Any],         # list[Ioc] ORM instances
        meta: dict[str, Any],    # {total, page, page_size, type_map, feed_map}
        query_filter: AdapterQueryFilter,
    ) -> Response:
        """Serialize IOCs to the adapter's wire format and return a Response."""
        ...


# ── Registry ──────────────────────────────────────────────────────────────────

_REGISTRY: dict[str, AdapterBase] = {}


def register_adapter(adapter: AdapterBase) -> None:
    _REGISTRY[adapter.name] = adapter
    logger.info("adapter_registered", name=adapter.name, media_type=adapter.media_type)


def get_adapter(name: str) -> AdapterBase:
    if name not in _REGISTRY:
        available = list(_REGISTRY.keys())
        raise KeyError(
            f"No adapter registered for format '{name}'. Available: {available}"
        )
    return _REGISTRY[name]


def list_adapters() -> list[dict[str, str]]:
    return [
        {
            "name": a.name,
            "media_type": a.media_type,
            "description": a.description,
        }
        for a in _REGISTRY.values()
    ]