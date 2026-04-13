"""State parameter management for OIDC flows."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time


class StateManager:
    """Generates and validates OIDC state parameters.

    The state is a signed token containing a random value and a timestamp,
    protecting against CSRF and replay attacks.
    """

    def __init__(self, secret_key: str, max_age_seconds: int = 600) -> None:
        self._secret = secret_key.encode("utf-8")
        self._max_age = max_age_seconds

    def generate(self) -> str:
        """Generate a new signed state value."""
        random_part = secrets.token_urlsafe(32)
        timestamp = str(int(time.time()))
        payload = f"{random_part}.{timestamp}"
        signature = self._sign(payload)
        return f"{payload}.{signature}"

    def validate(self, state: str) -> bool:
        """Validate a state value: check signature and expiration."""
        parts = state.split(".")
        if len(parts) != 3:
            return False

        random_part, timestamp_str, signature = parts
        payload = f"{random_part}.{timestamp_str}"

        # Verify signature
        expected = self._sign(payload)
        if not hmac.compare_digest(signature, expected):
            return False

        # Verify age
        try:
            timestamp = int(timestamp_str)
        except ValueError:
            return False

        if time.time() - timestamp > self._max_age:
            return False

        return True

    def _sign(self, payload: str) -> str:
        return hmac.new(
            self._secret, payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:32]
