"""Minimal FastAPI example with oidc-authkit."""

from fastapi import FastAPI, Request
from oidc_authkit.adapters.fastapi import FastAPIAuth, register_exception_handlers

app = FastAPI(title="FastAPI + oidc-authkit Example")

auth = FastAPIAuth(
    issuer="https://auth.example.com",
    client_id="example-app",
    client_secret="YOUR_CLIENT_SECRET",
    base_url="https://myapp.example.com",
    secret_key="your-session-secret-key-at-least-16-chars",
)

auth.init_app(app)
register_exception_handlers(app)


@app.get("/")
async def index(request: Request):
    """Public page — anonymous access allowed."""
    user = await auth.current_user(request)
    return {
        "message": "Welcome!",
        "authenticated": user.is_authenticated,
        "display_name": user.local_user.display_name if user.local_user else "Guest",
    }


@app.get("/profile")
async def profile(user=auth.require_user()):
    """Protected page — requires authentication."""
    return {
        "user_id": user.local_user.id,
        "name": user.local_user.display_name,
        "email": user.local_user.email,
    }


@app.get("/admin")
async def admin(user=auth.require_group("admins")):
    """Admin page — requires 'admins' group."""
    return {
        "user_id": user.local_user.id,
        "message": "Welcome, admin!",
    }
