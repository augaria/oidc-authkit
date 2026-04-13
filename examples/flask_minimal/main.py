"""Minimal Flask example with oidc-authkit."""

from flask import Flask
from oidc_authkit.adapters.flask import FlaskAuth

app = Flask(__name__)

auth = FlaskAuth(
    issuer="https://auth.example.com",
    client_id="example-app",
    client_secret="YOUR_CLIENT_SECRET",
    base_url="https://myapp.example.com",
    secret_key="your-session-secret-key-at-least-16-chars",
)

auth.init_app(app)


@app.route("/")
def index():
    """Public page — anonymous access allowed."""
    user = auth.current_user()
    return {
        "message": "Welcome!",
        "authenticated": user.is_authenticated,
        "display_name": user.local_user.display_name if user.local_user else "Guest",
    }


@app.route("/profile")
@auth.login_required()
def profile():
    """Protected page — requires authentication."""
    user = auth.current_user()
    return {
        "user_id": user.local_user.id,
        "name": user.local_user.display_name,
        "email": user.local_user.email,
    }


@app.route("/admin")
@auth.require_group("admins")
def admin():
    """Admin page — requires 'admins' group."""
    user = auth.current_user()
    return {
        "user_id": user.local_user.id,
        "message": "Welcome, admin!",
    }
