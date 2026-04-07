"""
CTIR Adapter — TXT Plain Text
One IOC value per line.
Suitable for direct import into firewalls, proxies, DNS blocklist tools.
Optionally prefixes lines with a comment header.
"""

from datetime import datetime, timezone
from typing import Any

from fastapi.responses import Response

from app.adapters.base import register_adapter
from app.adapters.query_filter import AdapterQueryFilter
from app.core.logging import get_logger

logger = get_logger(__name__)


class TxtAdapter:
    name = "txt"
    media_type = "text/plain"
    description = "TXT flat list — one IOC value per line for firewall/proxy/DNS blocklist import"

    def serialize(
        self,
        iocs: list,
        meta: dict[str, Any],
        query_filter: AdapterQueryFilter,
        include_comments: bool = True,
    ) -> Response:
        lines: list[str] = []

        if include_comments:
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            lines += [
                f"# CTIR IOC Export — {now}",
                f"# Total: {meta.get('total', len(iocs))}",
                f"# Page: {meta.get('page', 1)} / page_size: {meta.get('page_size', len(iocs))}",
            ]
            applied = {
                k: v
                for k, v in query_filter.model_dump().items()
                if v is not None and k not in ("page", "page_size")
            }
            if applied:
                lines.append(f"# Filters: {applied}")
            lines.append("#")

        for ioc in iocs:
            lines.append(ioc.ioc_value)

        content = "\n".join(lines) + "\n"
        logger.info("txt_serialized", ioc_count=len(iocs))
        return Response(
            content=content,
            media_type="text/plain",
            headers={
                "Content-Disposition": 'attachment; filename="ctir_blocklist.txt"',
                "X-CTIR-Format": "txt-v1",
            },
        )


register_adapter(TxtAdapter())