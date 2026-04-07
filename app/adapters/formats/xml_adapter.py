"""
CTIR Adapter — Generic XML
Produces a configurable XML document consumable by enterprise SIEMs.
Field names / element structure can be adjusted via query params.
"""

import uuid
from datetime import datetime, timezone
from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom

from fastapi.responses import Response

from app.adapters.base import register_adapter
from app.adapters.query_filter import AdapterQueryFilter
from app.core.logging import get_logger

logger = get_logger(__name__)


def _ts(dt: datetime) -> str:
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _prettify(element: Element) -> str:
    raw = tostring(element, encoding="unicode")
    return minidom.parseString(raw).toprettyxml(indent="  ")


class XmlAdapter:
    name = "xml"
    media_type = "application/xml"
    description = "Generic XML — configurable schema mapping for enterprise SIEMs"

    def serialize(
        self,
        iocs: list,
        meta: dict[str, Any],
        query_filter: AdapterQueryFilter,
    ) -> Response:
        type_map: dict[int, str] = meta.get("type_map", {})
        feed_map: dict[int, str] = meta.get("feed_map", {})

        root = Element("CTIRExport")
        root.set("xmlns:ctir", "https://ctir.example.com/schema/v1")
        root.set("exportId", str(uuid.uuid4()))
        root.set("generatedAt", _ts(datetime.now(timezone.utc)))

        # <Meta>
        meta_el = SubElement(root, "Meta")
        SubElement(meta_el, "Total").text = str(meta.get("total", len(iocs)))
        SubElement(meta_el, "Page").text = str(meta.get("page", 1))
        SubElement(meta_el, "PageSize").text = str(meta.get("page_size", len(iocs)))

        # <Filters>
        filters_el = SubElement(meta_el, "Filters")
        for k, v in query_filter.model_dump(exclude_none=True).items():
            f_el = SubElement(filters_el, "Filter")
            f_el.set("name", k)
            f_el.text = str(v)

        # <IOCs>
        iocs_el = SubElement(root, "IOCs")

        for ioc in iocs:
            type_name = type_map.get(ioc.ioc_type_id, "other")
            feed_name = feed_map.get(ioc.primary_feed_id, "unknown")

            ioc_el = SubElement(iocs_el, "IOC")
            ioc_el.set("id", str(ioc.id))
            ioc_el.set("type", type_name)
            ioc_el.set("severity", ioc.severity)

            SubElement(ioc_el, "Value").text = ioc.ioc_value
            SubElement(ioc_el, "Confidence").text = str(ioc.confidence)

            if ioc.malware_family:
                SubElement(ioc_el, "MalwareFamily").text = ioc.malware_family
            if ioc.threat_type:
                SubElement(ioc_el, "ThreatType").text = ioc.threat_type

            SubElement(ioc_el, "Feed").text = feed_name
            SubElement(ioc_el, "SourceCount").text = str(ioc.source_count)
            SubElement(ioc_el, "FirstSeen").text = _ts(ioc.first_seen_at)
            SubElement(ioc_el, "LastSeen").text = _ts(ioc.last_seen_at)

            if ioc.tags:
                tags_el = SubElement(ioc_el, "Tags")
                for tag in (ioc.tags or []):
                    SubElement(tags_el, "Tag").text = tag

        xml_out = _prettify(root)
        logger.info("xml_serialized", ioc_count=len(iocs))
        return Response(
            content=xml_out,
            media_type="application/xml",
            headers={"X-CTIR-Format": "xml-v1"},
        )


register_adapter(XmlAdapter())