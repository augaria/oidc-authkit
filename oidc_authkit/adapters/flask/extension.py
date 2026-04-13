"""Flask adapter for oidc-authkit."""

from __future__ import annotations

import base64
import functools
import json
import logging
from typing import Any, Callable

from flask import Flask, redirect, request, make_response, jsonify, g

from oidc_authkit.application.auth_manager import AuthManager
from oidc_authkit.config.models import AuthConfig
from oidc_authkit.domain.errors import AuthError, ForbiddenError, UnauthorizedError
from oidc_authkit.domain.models import UserContext
from oidc_authkit.hooks.events import AuthEventHooks
from oidc_authkit.infrastructure.utils.urls import SafeRedirectStrategy

logger = logging.getLogger(__name__)

_FLOW_COOKIE = "oidc_authkit_flow"


class FlaskAuth:
    """Flask integration for oidc-authkit.

    Usage:
        auth = FlaskAuth(
            issuer="https://auth.example.com",
            client_id="myapp",
            client_secret="secret",
            base_url="https://myapp.example.com",
            secret_key="session-secret-key-here",
        )
        auth.init_app(app)
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str,
        base_url: str,
        secret_key: str,
        *,
        user_store: Any | None = None,
        hooks: AuthEventHooks | None = None,
        redirect_strategy: SafeRedirectStrategy | None = None,
        **kwargs: Any,
    ) -> None:
        config = AuthConfig(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            secret_key=secret_key,
            **kwargs,
        )
        self._manager = AuthManager(
            config=config,
            user_store=user_store,
            hooks=hooks,
            redirect_strategy=redirect_strategy,
        )
        self._config = config
        self._app: Flask | None = None

    @property
    def manager(self) -> AuthManager:
        return self._manager

    def init_app(self, app: Flask) -> None:
        """Register auth routes and error handlers on a Flask application."""
        self._app = app
        self._register_routes(app)
        self._register_error_handlers(app)
        logger.info("FlaskAuth initialized")

    def _register_routes(self, app: Flask) -> None:
        import asyncio

        config = self._config
        manager = self._manager

        def _encode_flow(data: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()

        def _decode_flow(value: str) -> dict | None:
            try:
                return json.loads(base64.urlsafe_b64decode(value.encode()))
            except Exception:
                return None

        @app.route(config.login_path)
        def _login():
            return_to_raw = request.args.get("return_to", "/")
            return_to = manager.redirect_strategy.validate_redirect_target(
                return_to_raw, config.base_url
            )

            loop = asyncio.new_event_loop()
            try:
                login_data = loop.run_until_complete(
                    manager.initiate_login(return_to=return_to)
                )
            finally:
                loop.close()

            flow_value = _encode_flow({
                "state": login_data["state"],
                "nonce": login_data["nonce"],
                "return_to": login_data["return_to"],
            })

            response = make_response(redirect(login_data["authorization_url"], 302))
            response.set_cookie(
                key=_FLOW_COOKIE,
                value=flow_value,
                max_age=600,
                httponly=True,
                secure=config.cookie_secure,
                samesite="Lax",
            )
            return response

        @app.route(config.callback_path)
        def _callback():
            code = request.args.get("code")
            state = request.args.get("state")

            if not code or not state:
                return jsonify({"error": "Missing code or state parameter"}), 400

            flow_cookie = request.cookies.get(_FLOW_COOKIE)
            if not flow_cookie:
                return jsonify({"error": "Missing auth flow data"}), 400

            flow_data = _decode_flow(flow_cookie)
            if flow_data is None:
                return jsonify({"error": "Invalid auth flow data"}), 400

            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(manager.handle_callback(
                    code=code,
                    state=state,
                    stored_state=flow_data.get("state", ""),
                    stored_nonce=flow_data.get("nonce", ""),
                    stored_return_to=flow_data.get("return_to"),
                ))
            except AuthError as exc:
                logger.warning("Callback error, redirecting to login: %s", exc)
                return_to = flow_data.get("return_to", "/")
                return redirect(f"{config.login_path}?return_to={return_to}", 302)
            except Exception as exc:
                logger.error("Unexpected callback error: %s", exc)
                return jsonify({"error": "Authentication failed"}), 500
            finally:
                loop.close()

            session_data = result["session_data"]
            response = make_response(redirect(result["redirect_to"], 302))
            response.set_cookie(
                key=session_data["cookie_name"],
                value=session_data["cookie_value"],
                max_age=session_data["max_age"],
                httponly=session_data["httponly"],
                secure=session_data["secure"],
                samesite=session_data["samesite"].capitalize(),
            )
            response.delete_cookie(_FLOW_COOKIE, httponly=True, samesite="Lax")
            return response

        @app.route(config.logout_path)
        def _logout():
            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(manager.logout())
            finally:
                loop.close()

            response = make_response(redirect(result["redirect_to"], 302))
            response.delete_cookie(
                result["clear_cookie"],
                httponly=config.cookie_http_only,
                secure=config.cookie_secure,
                samesite=config.same_site.capitalize(),
            )
            return response

    def _register_error_handlers(self, app: Flask) -> None:
        @app.errorhandler(UnauthorizedError)
        def _unauthorized(exc: UnauthorizedError):
            return_to = request.path
            if request.query_string:
                return_to += f"?{request.query_string.decode()}"
            return redirect(f"{self._config.login_path}?return_to={return_to}", 302)

        @app.errorhandler(ForbiddenError)
        def _forbidden(exc: ForbiddenError):
            return jsonify({"error": "Forbidden", "detail": str(exc)}), 403

    def current_user(self) -> UserContext:
        """Get the current user from the request session (synchronous)."""
        import asyncio

        cookie_value = request.cookies.get(self._config.cookie_name)
        session_data = {"cookie_value": cookie_value} if cookie_value else {}

        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                self._manager.get_current_user(session_data)
            )
        finally:
            loop.close()

    def login_required(self) -> Callable:
        """Decorator that requires an authenticated user."""
        def decorator(f: Callable) -> Callable:
            @functools.wraps(f)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                user = self.current_user()
                if not user.is_authenticated:
                    raise UnauthorizedError("Authentication required")
                g.current_user = user
                return f(*args, **kwargs)
            return wrapper
        return decorator

    def require_group(self, group: str) -> Callable:
        """Decorator that requires user to be in a specific group."""
        def decorator(f: Callable) -> Callable:
            @functools.wraps(f)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                user = self.current_user()
                if not user.is_authenticated:
                    raise UnauthorizedError("Authentication required")
                if group not in user.groups:
                    raise ForbiddenError(f"Group '{group}' required")
                g.current_user = user
                return f(*args, **kwargs)
            return wrapper
        return decorator
