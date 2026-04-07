"""
CTIR Adapter — STIX 2.1 JSON
Produces a STIX Bundle containing:
  • Indicator objects  (one per IOC)
  • Malware objects    (one per distinct malware family)
  • Relationship objects (Indicator → indicates → Malware)
  • Identity object    (CTIR as the producer)

Spec: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi.responses import Response

from app.adapters.base import register_adapter
from app.adapters.query_filter import AdapterQueryFilter
from app.core.logging import get_logger

logger = get_logger(__name__)

# STIX type-map: CTIR ioc_type → STIX pattern prefix
_STIX_PATTERN: dict[str, str] = {
    "ip":          "ipv4-addr:value",
    "domain":      "domain-name:value",
    "url":         "url:value",
    "hash_md5":    "file:hashes.MD5",
    "hash_sha1":   "file:hashes.'SHA-1'",
    "hash_sha256": "file:hashes.'SHA-256'",
    "email":       "email-addr:value",
    "filename":    "file:name",
    "other":       "artifact:payload_bin",
}

_CTIR_IDENTITY_ID = "identity--ctir-central-threat-intelligence-repository"

_IDENTITY_OBJECT = {
    "type": "identity",
    "spec_version": "2.1",
    "id": _CTIR_IDENTITY_ID,
    "name": "CTIR — Central Threat Intelligence Repository",
    "identity_class": "system",
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
}


def _stix_ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _make_indicator(ioc, type_name: str) -> dict:
    pattern_field = _STIX_PATTERN.get(type_name, "artifact:payload_bin")
    pattern = f"[{pattern_field} = '{ioc.ioc_value}']"

    labels = []
    if ioc.threat_type:
        labels.append(ioc.threat_type)
    if ioc.tags:
        labels.extend(ioc.tags[:5])

    obj: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'ctir:{type_name}:{ioc.ioc_value}')}",
        "name": ioc.ioc_value,
        "description": (
            f"Malware: {ioc.malware_family}" if ioc.malware_family else "CTIR IOC"
        ),
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": _stix_ts(ioc.first_seen_at),
        "created": _stix_ts(ioc.created_at),
        "modified": _stix_ts(ioc.updated_at),
        "created_by_ref": _CTIR_IDENTITY_ID,
        "confidence": ioc.confidence,
        "labels": labels or ["malicious-activity"],
        "external_references": [
            {
                "source_name": "CTIR",
                "external_id": str(ioc.id),
            }
        ],
        "extensions": {
            "x-ctir-ioc": {
                "ioc_type": type_name,
                "severity": ioc.severity,
                "source_count": ioc.source_count,
                "last_seen": _stix_ts(ioc.last_seen_at),
            }
        },
    }
    if ioc.expires_at:
        obj["valid_until"] = _stix_ts(ioc.expires_at)

    return obj


def _make_malware(family: str) -> dict:
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": f"malware--{uuid.uuid5(uuid.NAMESPACE_URL, f'ctir:malware:{family}')}",
        "name": family,
        "malware_types": ["trojan"],
        "is_family": True,
        "created_by_ref": _CTIR_IDENTITY_ID,
        "created": "2024-01-01T00:00:00.000Z",
        "modified": "2024-01-01T00:00:00.000Z",
    }


def _make_relationship(indicator_id: str, malware_id: str) -> dict:
    rel_id = uuid.uuid5(uuid.NAMESPACE_URL, f"rel:{indicator_id}:{malware_id}")
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{rel_id}",
        "relationship_type": "indicates",
        "source_ref": indicator_id,
        "target_ref": malware_id,
        "created_by_ref": _CTIR_IDENTITY_ID,
        "created": "2024-01-01T00:00:00.000Z",
        "modified": "2024-01-01T00:00:00.000Z",
    }


class StixAdapter:
    name = "stix"
    media_type = "application/json"
    description = "STIX 2.1 Bundle — Indicators, Malware, Relationships (C3iHub / SIEM / ISAC)"

    def serialize(
        self,
        iocs: list,
        meta: dict[str, Any],
        query_filter: AdapterQueryFilter,
    ) -> Response:
        type_map: dict[int, str] = meta.get("type_map", {})

        objects: list[dict] = [_IDENTITY_OBJECT]
        malware_cache: dict[str, dict] = {}

        for ioc in iocs:
            type_name = type_map.get(ioc.ioc_type_id, "other")
            indicator = _make_indicator(ioc, type_name)
            objects.append(indicator)

            if ioc.malware_family:
                family = ioc.malware_family
                if family not in malware_cache:
                    mal_obj = _make_malware(family)
                    malware_cache[family] = mal_obj
                    objects.append(mal_obj)

                objects.append(
                    _make_relationship(indicator["id"], malware_cache[family]["id"])
                )

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "created": _stix_ts(datetime.now(timezone.utc)),
            "objects": objects,
            "x_ctir_meta": {
                "total": meta.get("total", len(iocs)),
                "page": meta.get("page", 1),
                "page_size": meta.get("page_size", len(iocs)),
                "filter_applied": query_filter.model_dump(exclude_none=True),
            },
        }

        logger.info("stix_serialized", object_count=len(objects), ioc_count=len(iocs))
        return Response(
            content=json.dumps(bundle, default=str),
            media_type="application/json",
            headers={"X-CTIR-Format": "stix-2.1"},
        )


register_adapter(StixAdapter())