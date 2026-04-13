"""FastAPI exception handlers for auth errors."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse

from oidc_authkit.domain.errors import ForbiddenError, UnauthorizedError


def register_exception_handlers(app: FastAPI, login_path: str = "/oidc/login") -> None:
    """Register exception handlers that convert auth errors to HTTP responses."""

    @app.exception_handler(UnauthorizedError)
    async def _unauthorized(request: Request, exc: UnauthorizedError) -> RedirectResponse:
        return_to = request.url.path
        if request.url.query:
            return_to += f"?{request.url.query}"
        return RedirectResponse(
            url=f"{login_path}?return_to={return_to}", status_code=302
        )

    @app.exception_handler(ForbiddenError)
    async def _forbidden(request: Request, exc: ForbiddenError) -> JSONResponse:
        return JSONResponse(
            {"error": "Forbidden", "detail": str(exc)}, status_code=403
        )
