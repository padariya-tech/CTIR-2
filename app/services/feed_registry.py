"""
CTIR — Feed Registry
Maintains a catalogue of available feed connectors.
As new feeds are added, register them here — the ingestion
service resolves connectors by feed name at runtime.
"""

from typing import Callable, Protocol, runtime_checkable
from app.core.logging import get_logger

logger = get_logger(__name__)


@runtime_checkable
class FeedConnector(Protocol):
    """Interface every connector must satisfy."""

    async def fetch_recent(self, days: int = 1) -> tuple[list[dict], dict]:
        """Fetch raw records. Returns (records, metrics_dict)."""
        ...

    def normalize_record(self, raw: dict) -> dict | None:
        """Map one raw record to the CTIR NormalizedIoc dict shape."""
        ...


# Registry: feed_name -> connector factory (callable returning a connector)
_REGISTRY: dict[str, Callable] = {}


def register_feed(name: str, factory: Callable) -> None:
    """Register a connector factory under `name`."""
    _REGISTRY[name] = factory
    logger.info("feed_registered", feed_name=name)


def get_connector(name: str) -> FeedConnector:
    """
    Resolve and instantiate a connector by feed name.
    Raises KeyError if the feed is not registered.
    """
    if name not in _REGISTRY:
        available = list(_REGISTRY.keys())
        raise KeyError(
            f"No connector registered for feed '{name}'. "
            f"Available: {available}"
        )
    return _REGISTRY[name]()


def list_feeds() -> list[str]:
    return list(_REGISTRY.keys())


# ── Built-in registrations ────────────────────────────────────────────────────

def _register_defaults() -> None:
    from app.services.connectors.threatfox import ThreatFoxConnector
    register_feed("ThreatFox", ThreatFoxConnector)


_register_defaults()