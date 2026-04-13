"""FastAPI adapter public API."""

from oidc_authkit.adapters.fastapi.manager import FastAPIAuth
from oidc_authkit.adapters.fastapi.middleware import register_exception_handlers

__all__ = ["FastAPIAuth", "register_exception_handlers"]
