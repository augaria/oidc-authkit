"""Cookie-based session store using itsdangerous for signing."""

from __future__ import annotations

import logging
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from oidc_authkit.config.models import SessionConfig
from oidc_authkit.domain.models import SessionPrincipal

logger = logging.getLogger(__name__)


class CookieSessionStore:
    """Session store implemented via signed cookies."""

    def __init__(self, config: SessionConfig) -> None:
        self._config = config
        self._serializer = URLSafeTimedSerializer(config.secret_key)

    async def get(self, session_data: dict[str, Any]) -> SessionPrincipal | None:
        """Deserialize session principal from cookie value."""
        cookie_value = session_data.get("cookie_value")
        if not cookie_value:
            return None

        try:
            data = self._serializer.loads(
                cookie_value, max_age=self._config.max_age_seconds
            )
        except (BadSignature, SignatureExpired):
            logger.debug("Invalid or expired session cookie")
            return None

        try:
            return SessionPrincipal(
                local_user_id=data["uid"],
                issuer=data["iss"],
                subject=data["sub"],
                auth_time=data["at"],
                session_version=data.get("sv", 1),
                id_token=data.get("idt"),
            )
        except (KeyError, TypeError):
            logger.debug("Malformed session data")
            return None

    async def save(self, principal: SessionPrincipal) -> dict[str, Any]:
        """Serialize principal to cookie data."""
        data = {
            "uid": principal.local_user_id,
            "iss": principal.issuer,
            "sub": principal.subject,
            "at": principal.auth_time,
            "sv": principal.session_version,
        }
        if principal.id_token:
            data["idt"] = principal.id_token
        cookie_value = self._serializer.dumps(data)
        return {
            "cookie_value": cookie_value,
            "cookie_name": self._config.cookie_name,
            "max_age": self._config.max_age_seconds,
            "httponly": self._config.http_only,
            "secure": self._config.secure,
            "samesite": self._config.same_site,
        }
