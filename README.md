# oidc-authkit

[中文文档](README.zh-CN.md)

A universal Python OIDC authentication package that integrates Python web applications with OIDC providers such as Authelia.

## Features

- Login / callback / logout via OIDC
- Current user identification (`current_user`)
- Automatic local user mapping (find or create)
- Login-required decorators / dependency injection
- Group-based permission checks
- Anonymous access support
- FastAPI and Flask adapters
- Cookie-based signed sessions
- Extensible architecture (custom UserStore, SessionStore, OIDCClient)

## Installation

```bash
# FastAPI support
pip install oidc-authkit[fastapi]

# Flask support
pip install oidc-authkit[flask]

# All optional dependencies
pip install oidc-authkit[all]
```

## Quick Start

### FastAPI

```python
from fastapi import FastAPI, Request
from oidc_authkit.adapters.fastapi import FastAPIAuth, register_exception_handlers

app = FastAPI()

auth = FastAPIAuth(
    issuer="https://auth.example.com",
    client_id="myapp",
    client_secret="YOUR_SECRET",
    base_url="https://myapp.example.com",
    secret_key="your-session-secret-key-at-least-16-chars",
)

auth.init_app(app)
register_exception_handlers(app)

# Public page
@app.get("/")
async def index(request: Request):
    user = await auth.current_user(request)
    return {"authenticated": user.is_authenticated}

# Requires login
@app.get("/profile")
async def profile(user=auth.require_user()):
    return {"name": user.local_user.display_name}

# Requires specific group
@app.get("/admin")
async def admin(user=auth.require_group("admins")):
    return {"message": "Welcome, admin!"}
```

### Flask

```python
from flask import Flask
from oidc_authkit.adapters.flask import FlaskAuth

app = Flask(__name__)

auth = FlaskAuth(
    issuer="https://auth.example.com",
    client_id="myapp",
    client_secret="YOUR_SECRET",
    base_url="https://myapp.example.com",
    secret_key="your-session-secret-key-at-least-16-chars",
)

auth.init_app(app)

# Public page
@app.route("/")
def index():
    user = auth.current_user()
    return {"authenticated": user.is_authenticated}

# Requires login
@app.route("/profile")
@auth.login_required()
def profile():
    user = auth.current_user()
    return {"name": user.local_user.display_name}

# Requires specific group
@app.route("/admin")
@auth.require_group("admins")
def admin():
    user = auth.current_user()
    return {"message": "Welcome, admin!"}
```

## Authelia Client Configuration

Register an OIDC client in Authelia for your application:

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: myapp
        client_secret: 'YOUR_HASHED_SECRET'
        token_endpoint_auth_method: client_secret_basic
        authorization_policy: two_factor
        redirect_uris:
          - https://myapp.example.com/oidc/callback
        scopes:
          - openid
          - profile
          - email
          - groups
```

**Important**: `redirect_uris` must exactly match `base_url + callback_path`.

## Retrieving the Username (preferred_username)

**By default, Authelia only returns `sub` (UUID) in the ID token and does not include `preferred_username`.**
If you need the username in `UserStore.create_from_identity` (e.g., to match existing accounts), you must enable `auto_fetch_userinfo=True`. This makes oidc_authkit send an additional request to the userinfo endpoint during callback and merge fields like `preferred_username` into `identity.claims`.

```python
auth = FastAPIAuth(
    issuer="...",
    client_id="...",
    client_secret="...",
    base_url="...",
    secret_key="...",
    auto_fetch_userinfo=True,   # Required, otherwise identity.username is None
)
```

Once enabled, `identity.username` (i.e., `identity.claims.preferred_username`) will contain the Authelia username and can be used directly for database matching:

```python
async def create_from_identity(self, identity: ExternalIdentity) -> LocalUser:
    username = identity.username  # Available when auto_fetch_userinfo is enabled
    user = db.query(User).filter(User.username == username).first()
    ...
```

Without `auto_fetch_userinfo`, `identity.claims.raw` only contains `sub` (UUID format), which cannot be used to match usernames in your application.

---

## Configuration

### Core

| Parameter | Description | Default |
|-----------|-------------|---------|
| `issuer` | OIDC Provider URL | Required |
| `client_id` | OIDC Client ID | Required |
| `client_secret` | OIDC Client Secret | Required |
| `base_url` | Application external URL | Required |
| `secret_key` | Session signing key (>=16 chars) | Required |
| `auto_fetch_userinfo` | Fetch userinfo endpoint on callback, merging `preferred_username`, `email`, `name` into claims | `False` |
| `callback_path` | Callback path | `/oidc/callback` |
| `login_path` | Login path | `/oidc/login` |
| `logout_path` | Logout path | `/oidc/logout` |
| `scopes` | OIDC scopes | `["openid", "profile", "email", "groups"]` |
| `token_endpoint_auth_method` | Token endpoint auth method: `client_secret_basic` or `client_secret_post` | `client_secret_basic` |
| `allow_anonymous` | Allow anonymous access | `True` |

### Session / Cookie

| Parameter | Description | Default |
|-----------|-------------|---------|
| `cookie_name` | Cookie name | `oidc_authkit_session` |
| `cookie_secure` | Secure flag | `True` |
| `cookie_http_only` | HttpOnly flag | `True` |
| `same_site` | SameSite policy | `lax` |
| `max_age_seconds` | Session max age | `86400` (24h) |

### Local User Mapping

| Parameter | Description | Default |
|-----------|-------------|---------|
| `create_user_if_missing` | Auto-create local user | `True` |
| `update_profile_on_login` | Update profile on login | `True` |
| `username_claim` | Claim used for username | `preferred_username` |
| `email_claim` | Claim used for email | `email` |
| `display_name_claim` | Claim used for display name | `name` |
| `groups_claim` | Claim used for groups | `groups` |

## Custom UserStore

Implement the `UserStore` protocol to replace the default `InMemoryUserStore`:

```python
from oidc_authkit.domain.interfaces import UserStore
from oidc_authkit.domain.models import ExternalIdentity, LocalUser

class MyDatabaseUserStore:
    async def get_by_external_identity(self, issuer: str, subject: str) -> LocalUser | None:
        # Query your database
        ...

    async def create_from_identity(self, identity: ExternalIdentity) -> LocalUser:
        # Create a user record
        ...

    async def update_from_identity(self, user: LocalUser, identity: ExternalIdentity) -> LocalUser:
        # Update a user record
        ...

    async def get_by_id(self, user_id: str | int) -> LocalUser | None:
        # Look up by ID
        ...

# Pass it during initialization
auth = FastAPIAuth(
    ...,
    user_store=MyDatabaseUserStore(),
)
```

## Troubleshooting

### "Invalid auth configuration"
Verify that all required fields are set, especially that `base_url` and `issuer` are valid URLs and `secret_key` is long enough.

### "OIDC state parameter mismatch"
- Check cookie settings (`SameSite`, `Secure`, etc.)
- Check whether the browser is blocking third-party cookies
- Confirm the callback URL matches the Authelia configuration

### "Failed to fetch OIDC discovery document"
Verify that the `issuer` URL is reachable and the OIDC Discovery endpoint is responding.

### Login succeeds but `identity.username` is None
Authelia does not include `preferred_username` in the ID token by default. Enable `auto_fetch_userinfo=True`. See [Retrieving the Username](#retrieving-the-username-preferred_username).

### User is not redirected back to the original page after login
Check that the `return_to` parameter is a safe same-site path. External URLs are rejected to prevent open redirects.

## Architecture

```
oidc_authkit/
├── config/          # Configuration models and validation
├── domain/          # Domain models, errors, interfaces
├── protocol/        # OIDC protocol handling (state, nonce, claims)
├── application/     # Application services (login, callback, current user)
├── infrastructure/  # Infrastructure (OIDC client, session, user store)
├── adapters/        # Framework adapters (FastAPI, Flask)
├── permissions/     # Permission checks
└── hooks/           # Lifecycle event hooks
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev,all]"

# Run tests
pytest

# Type checking
mypy oidc_authkit

# Lint
ruff check oidc_authkit tests
```

## License

MIT
