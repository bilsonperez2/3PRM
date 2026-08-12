"""Application logging.

Deliberately separate from scan evidence: operational logs configured here go to
stdout for the app/worker processes. Scan evidence (raw DNS records, certificate
data, API responses backing a Finding) is never written through this logger — it
is persisted only in Finding.evidence so operational logs can be shipped/rotated
without ever containing intelligence evidence, and evidence is never lost to log
rotation.
"""

import logging
import sys

from app.core.config import get_settings


def configure_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        stream=sys.stdout,
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
