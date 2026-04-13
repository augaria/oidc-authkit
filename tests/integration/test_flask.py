"""Integration tests for Flask adapter with mock OIDC provider."""

import base64
import json
from unittest.mock import AsyncMock, patch

from flask import Flask

from oidc_authkit.adapters.flask import FlaskAuth
from oidc_authkit.domain.models import Claims, TokenSet
from oidc_authkit.infrastructure.users.memory_store import InMemoryUserStore


def _encode_flow(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


def _create_app(**kwargs) -> tuple[Flask, FlaskAuth, InMemoryUserStore]:
    app = Flask(__name__)
    app.testing = True
    user_store = InMemoryUserStore()

    auth = FlaskAuth(
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

    @app.route("/")
    def index():
        user = auth.current_user()
        return {
            "authenticated": user.is_authenticated,
            "display_name": user.local_user.display_name if user.local_user else None,
        }

    @app.route("/protected")
    @auth.login_required()
    def protected():
        from flask import g

        return {"user_id": g.current_user.local_user.id}

    @app.route("/admin")
    @auth.require_group("admins")
    def admin():
        from flask import g

        return {"user_id": g.current_user.local_user.id}

    return app, auth, user_store


class TestFlaskLoginFlow:
    def test_login_redirect(self):
        app, auth, _ = _create_app()

        with patch.object(
            auth.manager.oidc_client,
            "get_authorization_url",
            new_callable=AsyncMock,
            return_value="https://auth.example.com/authorize?client_id=testapp",
        ):
            with app.test_client() as client:
                response = client.get("/oidc/login?return_to=/settings")

        assert response.status_code == 302
        assert "auth.example.com" in response.headers["location"]


class TestFlaskCallback:
    def test_callback_missing_code(self):
        app, _, _ = _create_app()
        with app.test_client() as client:
            response = client.get("/oidc/callback?state=abc")
        assert response.status_code == 400

    def test_callback_success(self):
        app, auth, user_store = _create_app()
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
            with app.test_client() as client:
                client.set_cookie(
                    key="oidc_authkit_flow",
                    value=flow_data,
                    domain="localhost",
                )
                response = client.get(
                    f"/oidc/callback?code=test-code&state={state}"
                )

        assert response.status_code == 302
        assert "/settings" in response.headers["location"]


class TestFlaskProtectedRoutes:
    def test_anonymous_access(self):
        app, _, _ = _create_app()
        with app.test_client() as client:
            response = client.get("/")
        assert response.status_code == 200
        data = response.get_json()
        assert data["authenticated"] is False

    def test_protected_without_auth_redirects(self):
        app, _, _ = _create_app()
        with app.test_client() as client:
            response = client.get("/protected")
        assert response.status_code == 302
        assert "/oidc/login" in response.headers["location"]


class TestFlaskLogout:
    def test_logout(self):
        app, _, _ = _create_app()
        with app.test_client() as client:
            response = client.get("/oidc/logout")
        assert response.status_code == 302
