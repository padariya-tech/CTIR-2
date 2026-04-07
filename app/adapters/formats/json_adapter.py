"""
CTIR Adapter — JSON REST
Produces a paginated JSON envelope consumable by BSP and custom REST clients.
Supports configurable field projection via `fields` query parameter.
"""

import json
from datetime import datetime
from typing import Any

from fastapi import Query
from fastapi.responses import Response

from app.adapters.base import register_adapter
from app.adapters.query_filter import AdapterQueryFilter
from app.core.logging import get_logger

logger = get_logger(__name__)

# All possible output fields
_ALL_FIELDS = {
    "id", "ioc_value", "ioc_type", "malware_family", "threat_type",
    "confidence", "severity", "tags", "source_count", "first_seen_at",
    "last_seen_at", "expires_at", "is_active", "created_at", "updated_at",
    "feed_name",
}

_DEFAULT_FIELDS = {
    "id", "ioc_value", "ioc_type", "malware_family", "threat_type",
    "confidence", "severity", "tags", "first_seen_at", "last_seen_at",
}


def _serialize_value(v: Any) -> Any:
    if isinstance(v, datetime):
        return v.isoformat()
    return v


def _project(ioc, type_name: str, feed_name: str, fields: set[str]) -> dict:
    full = {
        "id": ioc.id,
        "ioc_value": ioc.ioc_value,
        "ioc_type": type_name,
        "malware_family": ioc.malware_family,
        "threat_type": ioc.threat_type,
        "confidence": ioc.confidence,
        "severity": ioc.severity,
        "tags": ioc.tags or [],
        "source_count": ioc.source_count,
        "first_seen_at": ioc.first_seen_at,
        "last_seen_at": ioc.last_seen_at,
        "expires_at": ioc.expires_at,
        "is_active": ioc.is_active,
        "created_at": ioc.created_at,
        "updated_at": ioc.updated_at,
        "feed_name": feed_name,
    }
    selected = fields & _ALL_FIELDS
    return {k: _serialize_value(v) for k, v in full.items() if k in selected}


class JsonRestAdapter:
    name = "json"
    media_type = "application/json"
    description = "JSON REST — paginated envelope with configurable field projection (BSP / custom clients)"

    def serialize(
        self,
        iocs: list,
        meta: dict[str, Any],
        query_filter: AdapterQueryFilter,
        fields: set[str] | None = None,
    ) -> Response:
        type_map: dict[int, str] = meta.get("type_map", {})
        feed_map: dict[int, str] = meta.get("feed_map", {})
        active_fields = fields or _DEFAULT_FIELDS

        items = [
            _project(
                ioc,
                type_map.get(ioc.ioc_type_id, "other"),
                feed_map.get(ioc.primary_feed_id, "unknown"),
                active_fields,
            )
            for ioc in iocs
        ]

        payload = {
            "meta": {
                "total": meta.get("total", len(iocs)),
                "page": meta.get("page", query_filter.page),
                "page_size": meta.get("page_size", query_filter.page_size),
                "format": "ctir-json-v1",
                "fields": sorted(active_fields),
                "filter": query_filter.model_dump(exclude_none=True),
            },
            "data": items,
        }

        logger.info("json_serialized", ioc_count=len(iocs))
        return Response(
            content=json.dumps(payload, default=str),
            media_type="application/json",
            headers={"X-CTIR-Format": "json-rest-v1"},
        )


register_adapter(JsonRestAdapter())