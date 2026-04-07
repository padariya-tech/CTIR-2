"""
CTIR Adapter Layer — IOC Query Repository
Applies AdapterQueryFilter to the iocs table and returns raw ORM rows.
All adapters share this single query engine; only the output serialiser differs.
"""

from sqlalchemy import and_, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.query_filter import AdapterQueryFilter
from app.models.models import Ioc, IocType, Feed
from app.core.logging import get_logger

logger = get_logger(__name__)


class AdapterIocRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._db = session

    async def _build_query(self, f: AdapterQueryFilter):
        """Compose a SQLAlchemy SELECT with all active filters."""
        conditions = [Ioc.is_active == f.is_active]

        # IOC type join filter
        if f.ioc_type:
            type_result = await self._db.execute(
                select(IocType.id).where(IocType.name == f.ioc_type)
            )
            type_id = type_result.scalar_one_or_none()
            if type_id is not None:
                conditions.append(Ioc.ioc_type_id == type_id)

        # Severity
        if f.severity:
            conditions.append(Ioc.severity == f.severity.lower())

        # Malware family (partial)
        if f.malware_family:
            conditions.append(Ioc.malware_family.ilike(f"%{f.malware_family}%"))

        # Threat type (partial)
        if f.threat_type:
            conditions.append(Ioc.threat_type.ilike(f"%{f.threat_type}%"))

        # Confidence range
        conditions.append(Ioc.confidence >= f.min_confidence)
        conditions.append(Ioc.confidence <= f.max_confidence)

        # Time ranges
        if f.first_seen_after:
            conditions.append(Ioc.first_seen_at >= f.first_seen_after)
        if f.first_seen_before:
            conditions.append(Ioc.first_seen_at <= f.first_seen_before)
        if f.last_seen_after:
            conditions.append(Ioc.last_seen_at >= f.last_seen_after)
        if f.last_seen_before:
            conditions.append(Ioc.last_seen_at <= f.last_seen_before)

        # Source feed
        if f.source_feed_id:
            conditions.append(Ioc.primary_feed_id == f.source_feed_id)

        # Tag (JSON array contains exact string)
        if f.tag:
            conditions.append(
                func.json_contains(Ioc.tags, f'"{f.tag}"') == 1
            )

        return select(Ioc).where(and_(*conditions))

    async def fetch(
        self, f: AdapterQueryFilter
    ) -> tuple[int, list[Ioc]]:
        """Return (total_count, paginated_rows) matching the filter."""
        base_q = await self._build_query(f)

        # Count
        count_q = select(func.count()).select_from(base_q.subquery())
        total: int = (await self._db.execute(count_q)).scalar_one()

        # Paginated rows
        paged_q = (
            base_q
            .order_by(Ioc.last_seen_at.desc())
            .offset((f.page - 1) * f.page_size)
            .limit(f.page_size)
        )
        rows = list((await self._db.execute(paged_q)).scalars().all())

        logger.debug(
            "adapter_query",
            total=total,
            returned=len(rows),
            page=f.page,
            page_size=f.page_size,
        )
        return total, rows

    async def fetch_all_pages(self, f: AdapterQueryFilter) -> list[Ioc]:
        """
        Convenience: fetch every matching IOC across all pages.
        Used by bulk export adapters (CSV, TXT, XML, etc.).
        """
        all_rows: list[Ioc] = []
        page = 1
        while True:
            f_copy = f.model_copy(update={"page": page, "page_size": 1000})
            total, rows = await self.fetch(f_copy)
            all_rows.extend(rows)
            if len(all_rows) >= total or not rows:
                break
            page += 1
        return all_rows

    async def get_type_name(self, type_id: int) -> str:
        result = await self._db.execute(
            select(IocType.name).where(IocType.id == type_id)
        )
        return result.scalar_one_or_none() or "other"

    async def get_feed_name(self, feed_id: int) -> str:
        result = await self._db.execute(
            select(Feed.name).where(Feed.id == feed_id)
        )
        return result.scalar_one_or_none() or "unknown"