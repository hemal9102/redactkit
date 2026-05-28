import logging
from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from redactkit.url_query import redact_url_query

logger = logging.getLogger(__name__)


class RedactingLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        raw_url = str(request.url)
        redacted_url = redact_url_query(raw_url)
        logger.info(f"Incoming request: {request.method} {redacted_url}")

        return await call_next(request)
