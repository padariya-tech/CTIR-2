"""
CTIR Adapter — IOC JSON (v1.1 and v2.0)
Generic JSON IOC format understood by BSP platforms and custom REST clients.
Supports both v1.1 (flat array) and v2.0 (envelope + pagination) schemas.
"""

import json
from datetime import datetime
from typing import Any

from fastapi.responses import Response

from app.adapters.base import register_adapter
from app.adapters.query_filter import AdapterQueryFilter
from app.core.logging import get_logger

logger = get_logger(__name__)


def _ts(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _to_ioc_dict(ioc, type_name: str, feed_name: str) -> dict:
    return {
        "id": ioc.id,
        "value": ioc.ioc_value,
        "type": type_name,
        "malware": ioc.malware_family,
        "threat_type": ioc.threat_type,
        "confidence": ioc.confidence,
        "severity": ioc.severity,
        "tags": ioc.tags or [],
        "sources": {
            "feed": feed_name,
            "source_count": ioc.source_count,
        },
        "timestamps": {
            "first_seen": _ts(ioc.first_seen_at),
            "last_seen": _ts(ioc.last_seen_at),
            "expires_at": _ts(ioc.expires_at),
            "created_at": _ts(ioc.created_at),
        },
        "active": ioc.is_active,
    }


class IocJsonV1Adapter:
    name = "iocjson_v1"
    media_type = "application/json"
    description = "IOC JSON v1.1 — flat array format for BSP and legacy clients"

    def serialize(
        self,
        iocs: list,
        meta: dict[str, Any],
        query_filter: AdapterQueryFilter,
    ) -> Response:
        type_map: dict[int, str] = meta.get("type_map", {})
        feed_map: dict[int, str] = meta.get("feed_map", {})

        items = [
            _to_ioc_dict(
                ioc,
                type_map.get(ioc.ioc_type_id, "other"),
                feed_map.get(ioc.primary_feed_id, "unknown"),
            )
            for ioc in iocs
        ]

        logger.info("iocjson_v1_serialized", ioc_count=len(iocs))
        return Response(
            content=json.dumps(items, default=str),
            media_type="application/json",
            headers={"X-CTIR-Format": "ioc-json-v1.1"},
        )


class IocJsonV2Adapter:
    name = "iocjson_v2"
    media_type = "application/json"
    description = "IOC JSON v2.0 — paginated envelope format for BSP and custom clients"

    def serialize(
        self,
        iocs: list,
        meta: dict[str, Any],
        query_filter: AdapterQueryFilter,
    ) -> Response:
        type_map: dict[int, str] = meta.get("type_map", {})
        feed_map: dict[int, str] = meta.get("feed_map", {})

        items = [
            _to_ioc_dict(
                ioc,
                type_map.get(ioc.ioc_type_id, "other"),
                feed_map.get(ioc.primary_feed_id, "unknown"),
            )
            for ioc in iocs
        ]

        payload = {
            "version": "2.0",
            "schema": "ctir-ioc-v2",
            "pagination": {
                "total": meta.get("total", len(iocs)),
                "page": meta.get("page", query_filter.page),
                "page_size": meta.get("page_size", query_filter.page_size),
                "has_next": (meta.get("page", 1) * meta.get("page_size", query_filter.page_size))
                            < meta.get("total", len(iocs)),
            },
            "filter": query_filter.model_dump(exclude_none=True),
            "iocs": items,
        }

        logger.info("iocjson_v2_serialized", ioc_count=len(iocs))
        return Response(
            content=json.dumps(payload, default=str),
            media_type="application/json",
            headers={"X-CTIR-Format": "ioc-json-v2.0"},
        )


register_adapter(IocJsonV1Adapter())
register_adapter(IocJsonV2Adapter())