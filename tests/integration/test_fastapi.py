"""Integration tests for FastAPI adapter with mock OIDC provider."""

import base64
import json
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from oidc_authkit.adapters.fastapi import FastAPIAuth, register_exception_handlers
from oidc_authkit.domain.models import Claims, TokenSet
from oidc_authkit.infrastructure.users.memory_store import InMemoryUserStore


def _encode_flow(data: dict) -> str:
    """Encode flow data as base64 for cookie storage."""
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


def _create_app(**kwargs) -> tuple[FastAPI, FastAPIAuth, InMemoryUserStore]:
    app = FastAPI()
    user_store = InMemoryUserStore()

    auth = FastAPIAuth(
        issuer="https://auth.example.com",
        client_id="testapp",
        client_secret="test-secret",
        base_url="https://testapp.example.com",
        secret_key="a-long-enough-secret-key-for-testing",
        user_store=user_store,
        require_https=True,
        **kwargs,
    )
    auth.init_app(app)
    register_exception_handlers(app)

    @app.get("/")
    async def index(request: Request):
        user = await auth.current_user(request)
        return {
            "authenticated": user.is_authenticated,
            "display_name": user.local_user.display_name if user.local_user else None,
        }

    @app.get("/protected")
    async def protected(user=auth.require_user()):
        return {"user_id": user.local_user.id}

    @app.get("/admin")
    async def admin(user=auth.require_group("admins")):
        return {"user_id": user.local_user.id}

    return app, auth, user_store


class TestFastAPILoginFlow:
    def test_login_redirect(self):
        """GET /oidc/login should redirect to OIDC provider."""
        app, auth, _ = _create_app()

        with patch.object(
            auth.manager.oidc_client,
            "get_authorization_url",
            new_callable=AsyncMock,
            return_value="https://auth.example.com/authorize?client_id=testapp",
        ):
            client = TestClient(app, follow_redirects=False)
            response = client.get("/oidc/login?return_to=/settings")

        assert response.status_code == 302
        assert "auth.example.com" in response.headers["location"]
        # Flow cookie should be set
        assert "oidc_authkit_flow" in response.cookies

    def test_login_redirect_with_open_redirect_protection(self):
        """return_to must be validated against open redirect."""
        app, auth, _ = _create_app()

        with patch.object(
            auth.manager.oidc_client,
            "get_authorization_url",
            new_callable=AsyncMock,
            return_value="https://auth.example.com/authorize",
        ):
            client = TestClient(app, follow_redirects=False)
            response = client.get("/oidc/login?return_to=https://evil.com")

        # Flow cookie should contain "/" not the evil URL
        flow_cookie = response.cookies.get("oidc_authkit_flow")
        assert flow_cookie is not None
        flow_data = json.loads(base64.urlsafe_b64decode(flow_cookie.encode()))
        assert flow_data["return_to"] == "/"


class TestFastAPICallback:
    def test_callback_success(self):
        """Full callback flow: code exchange -> user creation -> session."""
        app, auth, user_store = _create_app()
        manager = auth.manager

        # Mock OIDC client methods
        mock_claims = Claims(
            issuer="https://auth.example.com",
            subject="user1",
            email="user@example.com",
            preferred_username="testuser",
            name="Test User",
            groups=["users"],
            raw={
                "iss": "https://auth.example.com",
                "sub": "user1",
                "email": "user@example.com",
                "preferred_username": "testuser",
                "name": "Test User",
                "groups": ["users"],
            },
        )
        mock_token_set = TokenSet(
            access_token="access-token",
            token_type="Bearer",
            id_token="id-token",
            raw={},
        )

        # Generate valid state and nonce
        state = manager.state_manager.generate()
        nonce = manager.nonce_manager.generate()
        flow_data = _encode_flow({
            "state": state,
            "nonce": nonce,
            "return_to": "/settings",
        })

        with (
            patch.object(
                manager.oidc_client,
                "exchange_code",
                new_callable=AsyncMock,
                return_value=mock_token_set,
            ),
            patch.object(
                manager.oidc_client,
                "parse_id_token",
                new_callable=AsyncMock,
                return_value=mock_claims,
            ),
        ):
            client = TestClient(app, follow_redirects=False)
            response = client.get(
                f"/oidc/callback?code=test-code&state={state}",
                cookies={"oidc_authkit_flow": flow_data},
            )

        assert response.status_code == 302
        assert response.headers["location"] == "/settings"
        # Session cookie should be set
        assert "oidc_authkit_session" in response.cookies

    def test_callback_missing_code(self):
        app, _, _ = _create_app()
        client = TestClient(app)
        response = client.get("/oidc/callback?state=abc")
        assert response.status_code == 400

    def test_callback_missing_flow_cookie(self):
        app, _, _ = _create_app()
        client = TestClient(app)
        response = client.get("/oidc/callback?code=abc&state=xyz")
        assert response.status_code == 400

    def test_callback_state_mismatch(self):
        app, auth, _ = _create_app()

        flow_data = _encode_flow({
            "state": "original-state",
            "nonce": "nonce",
            "return_to": "/",
        })

        client = TestClient(app, follow_redirects=False)
        response = client.get(
            "/oidc/callback?code=test-code&state=different-state",
            cookies={"oidc_authkit_flow": flow_data},
        )
        assert response.status_code == 302
        assert "/oidc/login" in response.headers["location"]
        assert "return_to=/" in response.headers["location"]


class TestFastAPIProtectedRoutes:
    def _login_and_get_session(self, app, auth):
        """Helper to simulate login and get session cookie."""
        manager = auth.manager

        mock_claims = Claims(
            issuer="https://auth.example.com",
            subject="user1",
            email="user@example.com",
            preferred_username="testuser",
            name="Test User",
            groups=["users"],
            raw={
                "iss": "https://auth.example.com",
                "sub": "user1",
                "email": "user@example.com",
                "preferred_username": "testuser",
                "name": "Test User",
                "groups": ["users"],
            },
        )
        mock_token_set = TokenSet(
            access_token="access-token",
            token_type="Bearer",
            id_token="id-token",
            raw={},
        )

        state = manager.state_manager.generate()
        nonce = manager.nonce_manager.generate()
        flow_data = _encode_flow({
            "state": state,
            "nonce": nonce,
            "return_to": "/",
        })

        with (
            patch.object(
                manager.oidc_client,
                "exchange_code",
                new_callable=AsyncMock,
                return_value=mock_token_set,
            ),
            patch.object(
                manager.oidc_client,
                "parse_id_token",
                new_callable=AsyncMock,
                return_value=mock_claims,
            ),
        ):
            client = TestClient(app, follow_redirects=False)
            response = client.get(
                f"/oidc/callback?code=code&state={state}",
                cookies={"oidc_authkit_flow": flow_data},
            )
            return response.cookies.get("oidc_authkit_session")

    def test_anonymous_access(self):
        app, auth, _ = _create_app()
        client = TestClient(app)
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is False

    def test_authenticated_access(self):
        app, auth, _ = _create_app()
        session_cookie = self._login_and_get_session(app, auth)
        assert session_cookie is not None

        client = TestClient(app)
        response = client.get("/", cookies={"oidc_authkit_session": session_cookie})
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is True
        assert data["display_name"] == "Test User"

    def test_protected_without_auth_redirects(self):
        app, auth, _ = _create_app()
        client = TestClient(app, follow_redirects=False)
        response = client.get("/protected")
        assert response.status_code == 302
        assert "/oidc/login" in response.headers["location"]

    def test_protected_with_auth(self):
        app, auth, _ = _create_app()
        session_cookie = self._login_and_get_session(app, auth)

        client = TestClient(app)
        response = client.get(
            "/protected", cookies={"oidc_authkit_session": session_cookie}
        )
        assert response.status_code == 200
        assert "user_id" in response.json()

    def test_group_check_fails(self):
        app, auth, _ = _create_app()
        session_cookie = self._login_and_get_session(app, auth)

        client = TestClient(app)
        response = client.get(
            "/admin", cookies={"oidc_authkit_session": session_cookie}
        )
        assert response.status_code == 403


class TestFastAPILogout:
    def test_logout(self):
        app, _, _ = _create_app()
        client = TestClient(app, follow_redirects=False)
        response = client.get("/oidc/logout")
        assert response.status_code == 302
        assert response.headers["location"] == "/"
