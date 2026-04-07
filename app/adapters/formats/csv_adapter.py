"""
CTIR Adapter — CSV / TSV
Flat file output for analyst tooling.
Configurable column list via ?columns= query parameter.
"""

import csv
import io
from datetime import datetime
from typing import Any

from fastapi.responses import Response

from app.adapters.base import register_adapter
from app.adapters.query_filter import AdapterQueryFilter
from app.core.logging import get_logger

logger = get_logger(__name__)

# All available columns in default order
ALL_COLUMNS = [
    "id", "ioc_value", "ioc_type", "malware_family", "threat_type",
    "confidence", "severity", "tags", "source_count", "feed_name",
    "first_seen_at", "last_seen_at", "expires_at", "is_active",
]

DEFAULT_COLUMNS = [
    "ioc_value", "ioc_type", "malware_family", "threat_type",
    "confidence", "severity", "tags", "first_seen_at", "last_seen_at",
]


def _ts(dt: datetime | None) -> str:
    return dt.isoformat() if dt else ""


def _row(ioc, type_name: str, feed_name: str, columns: list[str]) -> list[str]:
    full = {
        "id": str(ioc.id),
        "ioc_value": ioc.ioc_value,
        "ioc_type": type_name,
        "malware_family": ioc.malware_family or "",
        "threat_type": ioc.threat_type or "",
        "confidence": str(ioc.confidence),
        "severity": ioc.severity,
        "tags": "|".join(ioc.tags or []),
        "source_count": str(ioc.source_count),
        "feed_name": feed_name,
        "first_seen_at": _ts(ioc.first_seen_at),
        "last_seen_at": _ts(ioc.last_seen_at),
        "expires_at": _ts(ioc.expires_at),
        "is_active": str(ioc.is_active),
    }
    return [full.get(c, "") for c in columns]


class CsvAdapter:
    name = "csv"
    media_type = "text/csv"
    description = "CSV — configurable columns for analyst tooling and spreadsheets"

    def serialize(
        self,
        iocs: list,
        meta: dict[str, Any],
        query_filter: AdapterQueryFilter,
        columns: list[str] | None = None,
        delimiter: str = ",",
    ) -> Response:
        type_map: dict[int, str] = meta.get("type_map", {})
        feed_map: dict[int, str] = meta.get("feed_map", {})
        active_cols = columns or DEFAULT_COLUMNS

        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=delimiter)
        writer.writerow(active_cols)

        for ioc in iocs:
            writer.writerow(
                _row(
                    ioc,
                    type_map.get(ioc.ioc_type_id, "other"),
                    feed_map.get(ioc.primary_feed_id, "unknown"),
                    active_cols,
                )
            )

        ext = "tsv" if delimiter == "\t" else "csv"
        logger.info("csv_serialized", ioc_count=len(iocs), delimiter=repr(delimiter))
        return Response(
            content=buf.getvalue(),
            media_type=self.media_type,
            headers={
                "Content-Disposition": f'attachment; filename="ctir_export.{ext}"',
                "X-CTIR-Format": f"{ext}-v1",
            },
        )


class TsvAdapter(CsvAdapter):
    name = "tsv"
    media_type = "text/tab-separated-values"
    description = "TSV — tab-separated flat file for analyst tooling"

    def serialize(self, iocs, meta, query_filter, columns=None, delimiter="\t"):
        return super().serialize(iocs, meta, query_filter, columns, delimiter="\t")


register_adapter(CsvAdapter())
register_adapter(TsvAdapter())