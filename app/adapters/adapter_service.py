"""
CTIR Adapter Service
Ties together:
  1. AdapterIocRepository  — filtered DB query
  2. AdapterBase registry  — format serialiser lookup
  3. Meta hydration        — type_map, feed_map caches
"""

from typing import Any

from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import get_adapter
from app.adapters.ioc_query import AdapterIocRepository
from app.adapters.query_filter import AdapterQueryFilter
from app.models.models import IocType, Feed
from app.core.logging import get_logger

logger = get_logger(__name__)


async def _build_type_map(session: AsyncSession) -> dict[int, str]:
    rows = (await session.execute(select(IocType.id, IocType.name))).all()
    return {r[0]: r[1] for r in rows}


async def _build_feed_map(session: AsyncSession) -> dict[int, str]:
    rows = (await session.execute(select(Feed.id, Feed.name))).all()
    return {r[0]: r[1] for r in rows}


async def export(
    session: AsyncSession,
    fmt: str,
    query_filter: AdapterQueryFilter,
    extra_kwargs: dict[str, Any] | None = None,
) -> Response:
    """
    Main entry point for all adapter exports.

    Parameters
    ----------
    session      : AsyncSession
    fmt          : adapter name key (e.g. "stix", "csv", "misp")
    query_filter : AdapterQueryFilter assembled from request
    extra_kwargs : format-specific overrides (e.g. fields, columns, delimiter)
    """
    adapter = get_adapter(fmt)
    repo = AdapterIocRepository(session)

    # Hydrate lookup maps once — shared across all records
    type_map = await _build_type_map(session)
    feed_map = await _build_feed_map(session)

    # Fetch paginated rows
    total, iocs = await repo.fetch(query_filter)

    meta: dict[str, Any] = {
        "total": total,
        "page": query_filter.page,
        "page_size": query_filter.page_size,
        "type_map": type_map,
        "feed_map": feed_map,
    }

    logger.info(
        "adapter_export",
        format=fmt,
        total=total,
        returned=len(iocs),
        filter=query_filter.model_dump(exclude_none=True),
    )

    kwargs = extra_kwargs or {}
    return adapter.serialize(iocs, meta, query_filter, **kwargs)


async def bulk_export(
    session: AsyncSession,
    fmt: str,
    query_filter: AdapterQueryFilter,
    extra_kwargs: dict[str, Any] | None = None,
) -> Response:
    """
    Same as export() but fetches ALL pages — intended for dump formats
    like txt, csv, tsv, xml where consumers expect the complete dataset.
    """
    adapter = get_adapter(fmt)
    repo = AdapterIocRepository(session)

    type_map = await _build_type_map(session)
    feed_map = await _build_feed_map(session)

    # Total count for meta
    total, _ = await repo.fetch(query_filter.model_copy(update={"page": 1, "page_size": 1}))
    iocs = await repo.fetch_all_pages(query_filter)

    meta = {
        "total": total,
        "page": 1,
        "page_size": total,
        "type_map": type_map,
        "feed_map": feed_map,
    }

    logger.info("adapter_bulk_export", format=fmt, total=total)
    kwargs = extra_kwargs or {}
    return adapter.serialize(iocs, meta, query_filter, **kwargs)