"""URL utilities for redirect validation and URL building."""

from __future__ import annotations

from urllib.parse import urlparse


class SafeRedirectStrategy:
    """Redirect strategy that prevents open redirect attacks.

    Only allows relative paths or same-origin URLs.
    """

    def validate_redirect_target(self, target: str, base_url: str) -> str:
        """Validate redirect target. Returns '/' if target is unsafe."""
        if not target:
            return "/"

        # Allow relative paths starting with /
        if target.startswith("/") and not target.startswith("//"):
            return target

        # Allow same-origin absolute URLs
        parsed_target = urlparse(target)
        parsed_base = urlparse(base_url)

        if (
            parsed_target.scheme == parsed_base.scheme
            and parsed_target.netloc == parsed_base.netloc
        ):
            return parsed_target.path or "/"

        # Reject everything else
        return "/"


def build_callback_url(base_url: str, callback_path: str) -> str:
    """Build the full callback URL from base_url and callback_path."""
    return base_url.rstrip("/") + callback_path
