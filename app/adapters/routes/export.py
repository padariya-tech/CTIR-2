"""
CTIR Adapter Layer — API Routes
All format endpoints live under /api/v1/export/{format}.

Paginated (returns page):   stix, json, iocjson_v1, iocjson_v2, misp
Bulk (returns full dataset): csv, tsv, txt, xml, openioc
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.adapter_service import bulk_export, export
from app.adapters.base import list_adapters
from app.adapters.query_filter import AdapterQueryFilter, adapter_query_params
from app.db.database import get_db

# Import all adapters so they self-register on module load
import app.adapters.formats.stix_adapter        # noqa: F401
import app.adapters.formats.openioc_adapter      # noqa: F401
import app.adapters.formats.json_adapter         # noqa: F401
import app.adapters.formats.xml_adapter          # noqa: F401
import app.adapters.formats.csv_adapter          # noqa: F401
import app.adapters.formats.txt_adapter          # noqa: F401
import app.adapters.formats.misp_adapter         # noqa: F401
import app.adapters.formats.iocjson_adapter      # noqa: F401

router = APIRouter(prefix="/export", tags=["Adapter — Export"])

# Formats that stream the full dataset in one shot (no server-side pagination)
_BULK_FORMATS = {"csv", "tsv", "txt", "xml", "openioc"}


@router.get("/formats")
async def list_formats():
    """List all available output adapters with their media types."""
    return {"adapters": list_adapters()}


# ── Per-format convenience endpoints ─────────────────────────────────────────

@router.get("/stix", summary="STIX 2.1 Bundle")
async def export_stix(
    q: AdapterQueryFilter = Depends(adapter_query_params),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as a STIX 2.1 Bundle (Indicators + Malware + Relationships)."""
    return await export(db, "stix", q)


@router.get("/misp", summary="MISP JSON Event")
async def export_misp(
    q: AdapterQueryFilter = Depends(adapter_query_params),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as a MISP Event JSON (compatible with PyMISP)."""
    return await export(db, "misp", q)


@router.get("/json", summary="JSON REST")
async def export_json(
    fields: Optional[str] = Query(
        None,
        description="Comma-separated field list. Default: all core fields.",
        example="ioc_value,ioc_type,severity,confidence",
    ),
    q: AdapterQueryFilter = Depends(adapter_query_params),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as paginated JSON with optional field projection."""
    field_set = set(fields.split(",")) if fields else None
    return await export(db, "json", q, extra_kwargs={"fields": field_set})


@router.get("/iocjson/v1", summary="IOC JSON v1.1")
async def export_iocjson_v1(
    q: AdapterQueryFilter = Depends(adapter_query_params),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as a flat IOC JSON array (v1.1)."""
    return await export(db, "iocjson_v1", q)


@router.get("/iocjson/v2", summary="IOC JSON v2.0")
async def export_iocjson_v2(
    q: AdapterQueryFilter = Depends(adapter_query_params),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as a paginated IOC JSON envelope (v2.0)."""
    return await export(db, "iocjson_v2", q)


@router.get("/xml", summary="Generic XML")
async def export_xml(
    q: AdapterQueryFilter = Depends(adapter_query_params),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as generic XML (full dataset, enterprise SIEM ingest)."""
    return await bulk_export(db, "xml", q)


@router.get("/openioc", summary="OpenIOC 1.1 XML")
async def export_openioc(
    q: AdapterQueryFilter = Depends(adapter_query_params),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as OpenIOC 1.1 XML (IPA / legacy SIEM)."""
    return await bulk_export(db, "openioc", q)


@router.get("/csv", summary="CSV")
async def export_csv(
    columns: Optional[str] = Query(
        None,
        description="Comma-separated column list. Default: core fields.",
        example="ioc_value,ioc_type,severity,confidence,malware_family",
    ),
    q: AdapterQueryFilter = Depends(adapter_query_params),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as CSV (full dataset, analyst tooling)."""
    col_list = columns.split(",") if columns else None
    return await bulk_export(db, "csv", q, extra_kwargs={"columns": col_list})


@router.get("/tsv", summary="TSV")
async def export_tsv(
    q: AdapterQueryFilter = Depends(adapter_query_params),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as TSV (tab-separated, analyst tooling)."""
    return await bulk_export(db, "tsv", q)


@router.get("/txt", summary="Plain text blocklist")
async def export_txt(
    comments: bool = Query(True, description="Include comment header lines"),
    q: AdapterQueryFilter = Depends(adapter_query_params),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOC values as a plain text list — one value per line."""
    return await bulk_export(db, "txt", q, extra_kwargs={"include_comments": comments})


# ── Generic dispatch endpoint ─────────────────────────────────────────────────

@router.get("/{fmt}", summary="Generic format dispatch")
async def export_generic(
    fmt: str,
    q: AdapterQueryFilter = Depends(adapter_query_params),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """
    Generic export endpoint — dispatches to any registered adapter by name.
    Use the named endpoints above for format-specific options.
    """
    try:
        if fmt in _BULK_FORMATS:
            return await bulk_export(db, fmt, q)
        return await export(db, fmt, q)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown format '{fmt}'. GET /api/v1/export/formats for available formats.",
        )