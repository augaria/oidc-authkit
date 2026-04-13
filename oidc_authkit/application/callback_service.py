"""Callback service — handles OIDC callback and establishes session."""

from __future__ import annotations

import logging
import time

from oidc_authkit.config.models import AuthConfig
from oidc_authkit.domain.errors import StateMismatchError
from oidc_authkit.domain.models import SessionPrincipal
from oidc_authkit.hooks.events import AuthEventHooks
from oidc_authkit.infrastructure.oidc.authlib_client import AuthlibOIDCClient
from oidc_authkit.infrastructure.session.cookie_store import CookieSessionStore
from oidc_authkit.infrastructure.utils.urls import SafeRedirectStrategy, build_callback_url
from oidc_authkit.protocol.claims import claims_to_identity
from oidc_authkit.protocol.state import StateManager

logger = logging.getLogger(__name__)


class CallbackService:
    """Handles OIDC callback: validates state, exchanges code, maps user, creates session."""

    def __init__(
        self,
        config: AuthConfig,
        oidc_client: AuthlibOIDCClient,
        state_manager: StateManager,
        session_store: CookieSessionStore,
        user_store: object,  # UserStore protocol
        redirect_strategy: SafeRedirectStrategy,
        hooks: AuthEventHooks,
    ) -> None:
        self._config = config
        self._oidc = oidc_client
        self._state_mgr = state_manager
        self._session_store = session_store
        self._user_store = user_store
        self._redirect = redirect_strategy
        self._hooks = hooks
        self._mapping_config = config.to_user_mapping_config()

    async def handle_callback(
        self,
        code: str,
        state: str,
        stored_state: str,
        stored_nonce: str,
        stored_return_to: str | None = None,
    ) -> dict:
        """Process the OIDC callback.

        Returns dict with:
            - session_data: cookie data to set
            - redirect_to: where to redirect user
            - local_user: the LocalUser object
            - identity: the ExternalIdentity
        """
        # 1. Validate state
        if state != stored_state or not self._state_mgr.validate(state):
            await self._hooks.on_login_failure(reason="state_mismatch")
            raise StateMismatchError("OIDC state parameter mismatch")

        # 2. Exchange code for tokens
        redirect_uri = build_callback_url(self._config.base_url, self._config.callback_path)
        token_set = await self._oidc.exchange_code(code=code, redirect_uri=redirect_uri)

        # 3. Parse and validate id_token
        claims = await self._oidc.parse_id_token(token_set=token_set, nonce=stored_nonce)

        # 4. Optionally fetch userinfo
        if self._config.auto_fetch_userinfo:
            userinfo = await self._oidc.fetch_userinfo(token_set)
            # Merge userinfo into claims raw data
            claims.raw.update(userinfo)
            if userinfo.get("email"):
                claims.email = userinfo["email"]
            if userinfo.get("preferred_username"):
                claims.preferred_username = userinfo["preferred_username"]
            if userinfo.get("name"):
                claims.name = userinfo["name"]

        # 5. Convert to ExternalIdentity
        identity = claims_to_identity(claims, self._mapping_config)

        # 6. Find or create local user
        local_user = await self._user_store.get_by_external_identity(
            identity.issuer, identity.subject
        )

        if local_user is None and self._mapping_config.create_user_if_missing:
            local_user = await self._user_store.create_from_identity(identity)
            await self._hooks.on_user_created(local_user)
            logger.info("Created local user %s for %s", local_user.id, identity.subject)
        elif local_user is not None and self._mapping_config.update_profile_on_login:
            local_user = await self._user_store.update_from_identity(local_user, identity)
            await self._hooks.on_user_updated(local_user)
            logger.info("Updated local user %s", local_user.id)

        if local_user is None:
            await self._hooks.on_login_failure(reason="no_local_user")
            raise StateMismatchError(
                "No local user found and auto-creation is disabled"
            )

        # 7. Create session principal (store id_token for RP-Initiated Logout)
        principal = SessionPrincipal(
            local_user_id=local_user.id,
            issuer=identity.issuer,
            subject=identity.subject,
            auth_time=time.time(),
            id_token=token_set.id_token,
        )
        session_data = await self._session_store.save(principal)

        # 8. Determine redirect target
        redirect_to = self._redirect.validate_redirect_target(
            stored_return_to or "/", self._config.base_url
        )

        await self._hooks.on_login_success(local_user, identity)
        logger.info(
            "Login successful for user %s, redirecting to %s",
            local_user.id,
            redirect_to,
        )

        return {
            "session_data": session_data,
            "redirect_to": redirect_to,
            "local_user": local_user,
            "identity": identity,
        }
