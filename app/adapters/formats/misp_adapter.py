"""
CTIR Adapter — MISP JSON
Produces a MISP Event JSON payload consumable by MISP instances via PyMISP.
Reference: https://www.misp-project.org/openapi/

Produces:
  • One MISP Event wrapping all selected IOCs
  • MISP Attributes (type-mapped from CTIR ioc_type)
  • MISP Tags from severity + malware family
  • GalaxyCluster stubs for malware families
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

# CTIR ioc_type → MISP attribute type
_MISP_TYPE_MAP: dict[str, str] = {
    "ip":          "ip-dst",
    "domain":      "domain",
    "url":         "url",
    "hash_md5":    "md5",
    "hash_sha1":   "sha1",
    "hash_sha256": "sha256",
    "email":       "email-dst",
    "filename":    "filename",
    "other":       "text",
}

# CTIR severity → MISP threat level id (1=High … 4=Undefined)
_SEVERITY_THREAT_LEVEL: dict[str, str] = {
    "critical": "1",
    "high":     "1",
    "medium":   "2",
    "low":      "3",
    "info":     "4",
}

# CTIR severity → MISP colour tags
_SEVERITY_TAG: dict[str, str] = {
    "critical": "tlp:red",
    "high":     "tlp:amber",
    "medium":   "tlp:green",
    "low":      "tlp:white",
    "info":     "tlp:white",
}


def _ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return str(int(dt.timestamp()))


def _misp_attribute(ioc, type_name: str, seq: int) -> dict:
    misp_type = _MISP_TYPE_MAP.get(type_name, "text")

    tags: list[dict] = []
    if ioc.severity:
        tlp = _SEVERITY_TAG.get(ioc.severity, "tlp:white")
        tags.append({"name": tlp, "exportable": True})
    for tag in (ioc.tags or []):
        tags.append({"name": tag, "exportable": True})
    if ioc.malware_family:
        tags.append({"name": f"misp-galaxy:malware=\"{ioc.malware_family}\"", "exportable": True})

    return {
        "id": str(seq),
        "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"ctir:attr:{type_name}:{ioc.ioc_value}")),
        "type": misp_type,
        "category": _category(misp_type),
        "value": ioc.ioc_value,
        "to_ids": True,
        "distribution": "5",       # inherit from event
        "comment": ioc.threat_type or "",
        "timestamp": _ts(ioc.last_seen_at),
        "first_seen": ioc.first_seen_at.isoformat() if ioc.first_seen_at else None,
        "last_seen": ioc.last_seen_at.isoformat() if ioc.last_seen_at else None,
        "confidence": ioc.confidence,
        "deleted": not ioc.is_active,
        "Tag": tags,
        "ShadowAttribute": [],
    }


def _category(misp_type: str) -> str:
    mapping = {
        "ip-dst": "Network activity",
        "ip-src": "Network activity",
        "domain": "Network activity",
        "url": "Network activity",
        "md5": "Payload delivery",
        "sha1": "Payload delivery",
        "sha256": "Payload delivery",
        "filename": "Artifacts dropped",
        "email-dst": "Payload delivery",
        "text": "External analysis",
    }
    return mapping.get(misp_type, "External analysis")


class MispAdapter:
    name = "misp"
    media_type = "application/json"
    description = "MISP JSON Event — compatible with MISP PyMISP and direct MISP import"

    def serialize(
        self,
        iocs: list,
        meta: dict[str, Any],
        query_filter: AdapterQueryFilter,
    ) -> Response:
        type_map: dict[int, str] = meta.get("type_map", {})
        feed_map: dict[int, str] = meta.get("feed_map", {})

        # Determine overall threat level from worst severity
        all_severities = {ioc.severity for ioc in iocs}
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in all_severities:
                threat_level = _SEVERITY_THREAT_LEVEL[sev]
                break
        else:
            threat_level = "4"

        attributes = [
            _misp_attribute(ioc, type_map.get(ioc.ioc_type_id, "other"), seq)
            for seq, ioc in enumerate(iocs, start=1)
        ]

        # Collect unique malware families for galaxy stubs
        families = list({ioc.malware_family for ioc in iocs if ioc.malware_family})
        galaxy_clusters = [
            {
                "type": "misp-galaxy:malware",
                "name": fam,
                "description": f"Malware family: {fam}",
                "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"ctir:malware:{fam}")),
            }
            for fam in families
        ]

        event = {
            "Event": {
                "id": str(abs(hash(str(query_filter.model_dump()))) % 100000),
                "uuid": str(uuid.uuid4()),
                "info": "CTIR IOC Export",
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "threat_level_id": threat_level,
                "analysis": "2",       # completed
                "distribution": "1",   # community
                "published": False,
                "timestamp": _ts(datetime.now(timezone.utc)),
                "Org": {"name": "CTIR", "uuid": _ts(datetime.now(timezone.utc))},
                "Orgc": {"name": "CTIR"},
                "Attribute": attributes,
                "Galaxy": [{"GalaxyCluster": galaxy_clusters}] if galaxy_clusters else [],
                "Tag": [
                    {"name": "tlp:amber", "exportable": True},
                    {"name": "ctir:export", "exportable": True},
                ],
                "x_ctir_meta": {
                    "total": meta.get("total", len(iocs)),
                    "page": meta.get("page", 1),
                    "filter": query_filter.model_dump(exclude_none=True),
                },
            }
        }

        logger.info("misp_serialized", ioc_count=len(iocs), families=len(families))
        return Response(
            content=json.dumps(event, default=str),
            media_type="application/json",
            headers={"X-CTIR-Format": "misp-json-v1"},
        )


register_adapter(MispAdapter())