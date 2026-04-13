"""FastAPI auth routes — login, callback, logout."""

from __future__ import annotations

import base64
import json
import logging

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, JSONResponse

from oidc_authkit.application.auth_manager import AuthManager
from oidc_authkit.config.models import AuthConfig
from oidc_authkit.domain.errors import AuthError

logger = logging.getLogger(__name__)

_FLOW_COOKIE = "oidc_authkit_flow"


def _encode_flow(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


def _decode_flow(value: str) -> dict | None:
    try:
        return json.loads(base64.urlsafe_b64decode(value.encode()))
    except Exception:
        return None


def create_auth_router(manager: AuthManager, config: AuthConfig) -> APIRouter:
    """Create a FastAPI router with login, callback, and logout endpoints."""
    router = APIRouter(tags=["auth"])
    redirect_strategy = manager.redirect_strategy

    @router.get(config.login_path)
    async def login(request: Request) -> RedirectResponse:
        # Determine return_to from query param
        return_to_raw = request.query_params.get("return_to", "/")
        return_to = redirect_strategy.validate_redirect_target(
            return_to_raw, config.base_url
        )

        login_data = await manager.initiate_login(return_to=return_to)

        # Store flow data in a short-lived base64-encoded cookie
        flow_value = _encode_flow({
            "state": login_data["state"],
            "nonce": login_data["nonce"],
            "return_to": login_data["return_to"],
        })

        response = RedirectResponse(
            url=login_data["authorization_url"], status_code=302
        )
        response.set_cookie(
            key=_FLOW_COOKIE,
            value=flow_value,
            max_age=600,
            httponly=True,
            secure=config.cookie_secure,
            samesite="lax",
        )
        return response

    @router.get(config.callback_path)
    async def callback(request: Request) -> RedirectResponse:
        # Extract code and state from query params
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        if not code or not state:
            return JSONResponse(
                {"error": "Missing code or state parameter"}, status_code=400
            )

        # Retrieve flow data from cookie
        flow_cookie = request.cookies.get(_FLOW_COOKIE)
        if not flow_cookie:
            return JSONResponse(
                {"error": "Missing auth flow data"}, status_code=400
            )

        flow_data = _decode_flow(flow_cookie)
        if flow_data is None:
            return JSONResponse(
                {"error": "Invalid auth flow data"}, status_code=400
            )

        try:
            result = await manager.handle_callback(
                code=code,
                state=state,
                stored_state=flow_data.get("state", ""),
                stored_nonce=flow_data.get("nonce", ""),
                stored_return_to=flow_data.get("return_to"),
            )
        except AuthError as exc:
            logger.warning("Callback error, redirecting to login: %s", exc)
            return_to = flow_data.get("return_to", "/")
            return RedirectResponse(
                url=f"{config.login_path}?return_to={return_to}", status_code=302
            )

        session_data = result["session_data"]
        response = RedirectResponse(url=result["redirect_to"], status_code=302)

        # Set session cookie
        response.set_cookie(
            key=session_data["cookie_name"],
            value=session_data["cookie_value"],
            max_age=session_data["max_age"],
            httponly=session_data["httponly"],
            secure=session_data["secure"],
            samesite=session_data["samesite"],
        )
        # Clear flow cookie
        response.delete_cookie(key=_FLOW_COOKIE, httponly=True, samesite="lax")

        return response

    @router.get(config.logout_path)
    async def logout(request: Request) -> RedirectResponse:
        cookie_value = request.cookies.get(config.cookie_name)
        session_data = {"cookie_value": cookie_value} if cookie_value else None
        result = await manager.logout(session_data=session_data)

        response = RedirectResponse(url=result["redirect_to"], status_code=302)
        response.delete_cookie(
            key=result["clear_cookie"],
            httponly=config.cookie_http_only,
            secure=config.cookie_secure,
            samesite=config.same_site,
        )
        return response

    return router
