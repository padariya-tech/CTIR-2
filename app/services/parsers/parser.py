"""
Parsing & Normalization layer.
Validates raw normalized dicts against the NormalizedIoc pydantic schema
and collects structured parse errors.
"""

from typing import Any

from pydantic import ValidationError

from app.core.logging import get_logger
from app.schemas.schemas import NormalizedIoc

logger = get_logger(__name__)


class ParseResult:
    __slots__ = ("valid", "invalid", "errors")

    def __init__(self) -> None:
        self.valid: list[NormalizedIoc] = []
        self.invalid: list[dict[str, Any]] = []   # [{raw, error_type, error_msg}]
        self.errors: list[dict[str, Any]] = []


def parse_and_validate(
    raw_records: list[dict[str, Any]],
    connector_normalize_fn,
) -> ParseResult:
    """
    1. Run each raw record through connector's normalize_fn.
    2. Validate the normalized dict against NormalizedIoc.
    3. Return a ParseResult with valid IOCs and structured error list.
    """
    result = ParseResult()

    for raw in raw_records:
        # Step 1: connector-level normalization
        try:
            normalized_dict = connector_normalize_fn(raw)
        except Exception as exc:
            _record_error(result, raw, "NormalizationError", str(exc))
            continue

        if normalized_dict is None:
            _record_error(result, raw, "NormalizationError", "normalize_record returned None")
            continue

        # Step 2: schema validation
        try:
            ioc = NormalizedIoc(**normalized_dict)
            result.valid.append(ioc)
        except ValidationError as exc:
            _record_error(result, raw, "ValidationError", exc.json())
        except Exception as exc:
            _record_error(result, raw, "UnexpectedError", str(exc))

    logger.info(
        "parse_complete",
        total=len(raw_records),
        valid=len(result.valid),
        invalid=len(result.invalid),
    )
    return result


def _record_error(
    result: ParseResult,
    raw: dict,
    error_type: str,
    error_msg: str,
) -> None:
    entry = {"raw": raw, "error_type": error_type, "error_msg": error_msg}
    result.invalid.append(entry)
    result.errors.append(entry)
    logger.debug("parse_error", error_type=error_type, error_msg=error_msg[:200])