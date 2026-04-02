"""
ThreatFox Feed Connector
Fetches IOCs from https://threatfox.abuse.ch/api/v1/
Supports both API-key authenticated and anonymous (rate-limited) access.
"""

import time
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)
import logging

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

# ThreatFox confidence → CTIR severity map
_CONFIDENCE_TO_SEVERITY = {
    range(80, 101): "critical",
    range(60, 80):  "high",
    range(40, 60):  "medium",
    range(20, 40):  "low",
    range(0, 20):   "info",
}

# ThreatFox ioc_type → CTIR ioc_type
_IOC_TYPE_MAP: dict[str, str] = {
    "ip:port":   "ip",
    "domain":    "domain",
    "url":       "url",
    "md5_hash":  "hash_md5",
    "sha1_hash": "hash_sha1",
    "sha256_hash": "hash_sha256",
}


def _confidence_to_severity(confidence: int) -> str:
    for r, severity in _CONFIDENCE_TO_SEVERITY.items():
        if confidence in r:
            return severity
    return "medium"


def _map_ioc_type(tf_type: str) -> str:
    return _IOC_TYPE_MAP.get(tf_type, "other")


def _parse_ts(ts_str: str | None) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


class ThreatFoxConnector:
    """
    Async connector for the ThreatFox REST API.
    Reference: https://threatfox.abuse.ch/api/
    """

    BASE_URL = settings.THREATFOX_BASE_URL

    def __init__(self) -> None:
        headers = {"Content-Type": "application/json"}
        if settings.THREATFOX_API_KEY:
            headers["API-KEY"] = settings.THREATFOX_API_KEY

        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            headers=headers,
            timeout=settings.THREATFOX_TIMEOUT_SECONDS,
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self._client.aclose()

    # ── Internal helpers ──────────────────────────────────────

    @retry(
        stop=stop_after_attempt(settings.THREATFOX_MAX_RETRIES),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.WARNING),
        reraise=True,
    )
    async def _post(self, payload: dict) -> dict:
        t0 = time.monotonic()
        response = await self._client.post("", json=payload)
        latency_ms = int((time.monotonic() - t0) * 1000)
        response.raise_for_status()
        data = response.json()

        logger.debug(
            "threatfox_api_call",
            payload_query=payload.get("query"),
            status_code=response.status_code,
            latency_ms=latency_ms,
        )

        if data.get("query_status") not in ("ok", "no_results"):
            raise ValueError(
                f"ThreatFox API error: {data.get('query_status')} – {data}"
            )
        return data

    # ── Public methods ────────────────────────────────────────

    async def fetch_recent(self, days: int = 1) -> tuple[list[dict[str, Any]], dict]:
        """
        Pull IOCs submitted in the last `days` days.
        Returns (raw_records, metrics).
        """
        payload = {"query": "get_iocs", "days": days}
        t0 = time.monotonic()

        try:
            data = await self._post(payload)
        except httpx.HTTPStatusError as exc:
            logger.error(
                "threatfox_http_error",
                status_code=exc.response.status_code,
                body=exc.response.text[:500],
            )
            raise
        except httpx.TransportError as exc:
            logger.error("threatfox_transport_error", error=str(exc))
            raise
        except ValueError as exc:
            logger.error("threatfox_api_error", error=str(exc))
            raise

        records: list[dict] = data.get("data") or []
        latency_ms = int((time.monotonic() - t0) * 1000)

        metrics = {
            "records_fetched": len(records),
            "latency_ms": latency_ms,
            "query_status": data.get("query_status"),
        }
        logger.info("threatfox_fetch_complete", **metrics)
        return records, metrics

    async def search_ioc(self, ioc_value: str) -> list[dict]:
        """Search ThreatFox for a specific IOC value (on-demand enrichment)."""
        payload = {"query": "search_ioc", "search_term": ioc_value}
        data = await self._post(payload)
        return data.get("data") or []

    # ── Normalisation (lives here so the connector owns the mapping) ──────────

    def normalize_record(self, raw: dict) -> dict | None:
        """
        Map one raw ThreatFox record to the CTIR NormalizedIoc shape.
        Returns None if the record is malformed / missing required fields.
        """
        try:
            ioc_value = raw.get("ioc", "").strip()
            tf_ioc_type = raw.get("ioc_type", "")
            if not ioc_value or not tf_ioc_type:
                return None

            # Strip port from IP:port IOCs (store the bare IP)
            ioc_type = _map_ioc_type(tf_ioc_type)
            if tf_ioc_type == "ip:port" and ":" in ioc_value:
                ioc_value = ioc_value.rsplit(":", 1)[0]

            confidence: int = int(raw.get("confidence_level", 50))
            tags_raw = raw.get("tags") or []
            tags = [t for t in tags_raw if isinstance(t, str)]

            return {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "malware_family": raw.get("malware") or raw.get("malware_alias"),
                "threat_type": raw.get("threat_type"),
                "confidence": min(max(confidence, 0), 100),
                "severity": _confidence_to_severity(confidence),
                "tags": tags,
                "source_ioc_id": str(raw.get("id", "")),
                "first_seen_at": _parse_ts(raw.get("first_seen")),
                "last_seen_at": _parse_ts(raw.get("last_seen") or raw.get("first_seen")),
                "expires_at": None,
            }
        except Exception as exc:
            logger.warning("normalize_record_failed", error=str(exc), raw=raw)
            return None