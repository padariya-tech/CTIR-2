from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    JSON,
    SmallInteger,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.mysql import TINYINT
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class IocType(Base):
    __tablename__ = "ioc_types"

    id: Mapped[int] = mapped_column(TINYINT(unsigned=True), primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(String(255))

    iocs: Mapped[list["Ioc"]] = relationship(back_populates="ioc_type")


class Feed(Base):
    __tablename__ = "feeds"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    feed_url: Mapped[Optional[str]] = mapped_column(String(512))
    auth_type: Mapped[str] = mapped_column(
        Enum("none", "api_key", "oauth", "taxii"), default="none"
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    iocs: Mapped[list["Ioc"]] = relationship(back_populates="primary_feed")
    jobs: Mapped[list["IngestionJob"]] = relationship(back_populates="feed")


class Ioc(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ioc_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    ioc_type_id: Mapped[int] = mapped_column(
        TINYINT(unsigned=True), ForeignKey("ioc_types.id"), nullable=False
    )
    ioc_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    malware_family: Mapped[Optional[str]] = mapped_column(String(128))
    threat_type: Mapped[Optional[str]] = mapped_column(String(128))
    confidence: Mapped[int] = mapped_column(TINYINT(unsigned=True), default=50)
    severity: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", "info"), default="medium"
    )
    tags: Mapped[Optional[dict]] = mapped_column(JSON)

    primary_feed_id: Mapped[int] = mapped_column(SmallInteger, ForeignKey("feeds.id"))
    source_ioc_id: Mapped[Optional[str]] = mapped_column(String(128))
    source_count: Mapped[int] = mapped_column(SmallInteger, default=1)
    merged_sources: Mapped[Optional[list]] = mapped_column(JSON)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    ioc_type: Mapped["IocType"] = relationship(back_populates="iocs")
    primary_feed: Mapped["Feed"] = relationship(back_populates="iocs")

    __table_args__ = (
        Index("idx_ioc_value", "ioc_value", mysql_length=255),
        Index("idx_ioc_type", "ioc_type_id"),
        Index("idx_severity", "severity"),
        Index("idx_malware_family", "malware_family"),
        Index("idx_last_seen", "last_seen_at"),
        Index("idx_is_active", "is_active"),
    )


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    feed_id: Mapped[int] = mapped_column(SmallInteger, ForeignKey("feeds.id"), nullable=False)
    triggered_by: Mapped[str] = mapped_column(
        Enum("scheduler", "manual"), default="scheduler"
    )
    status: Mapped[str] = mapped_column(
        Enum("running", "success", "partial", "failed"), default="running"
    )

    records_fetched: Mapped[int] = mapped_column(default=0)
    records_parsed: Mapped[int] = mapped_column(default=0)
    records_valid: Mapped[int] = mapped_column(default=0)
    records_invalid: Mapped[int] = mapped_column(default=0)
    records_new: Mapped[int] = mapped_column(default=0)
    records_updated: Mapped[int] = mapped_column(default=0)
    records_dupes: Mapped[int] = mapped_column(default=0)

    started_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    latency_ms: Mapped[Optional[int]] = mapped_column()
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    feed: Mapped["Feed"] = relationship(back_populates="jobs")
    parse_errors: Mapped[list["ParseError"]] = relationship(back_populates="job")

    __table_args__ = (
        Index("idx_feed_status", "feed_id", "status"),
        Index("idx_started_at", "started_at"),
    )


class ParseError(Base):
    __tablename__ = "parse_errors"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("ingestion_jobs.id", ondelete="CASCADE"))
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON)
    error_type: Mapped[Optional[str]] = mapped_column(String(128))
    error_msg: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    job: Mapped["IngestionJob"] = relationship(back_populates="parse_errors")