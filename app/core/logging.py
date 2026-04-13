import logging
import sys
from pathlib import Path

import structlog

from app.core.config import get_settings


def setup_logging() -> None:
    settings = get_settings()
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    Path(settings.LOG_FILE).parent.mkdir(parents=True, exist_ok=True)

    shared_processors = [  # functions that run for all loggers
        structlog.contextvars.merge_contextvars, # add contextvars to log entries (e.g. request_id)
        structlog.stdlib.add_log_level, # add log level to log entries
        structlog.stdlib.add_logger_name, # add logger name to log entries
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )

    # stdout handler
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)

    # file handler
    file_handler = logging.FileHandler(settings.LOG_FILE)
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(stream_handler)
    root_logger.addHandler(file_handler)


def get_logger(name: str = __name__):
    return structlog.get_logger(name)