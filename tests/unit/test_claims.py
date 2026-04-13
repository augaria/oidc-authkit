"""Tests for claims extraction and mapping."""

from oidc_authkit.config.models import UserMappingConfig
from oidc_authkit.protocol.claims import claims_to_identity, extract_claims


class TestExtractClaims:
    def test_basic(self):
        raw = {
            "iss": "https://auth.example.com",
            "sub": "user1",
            "email": "user@example.com",
            "email_verified": True,
            "preferred_username": "user1",
            "name": "User One",
            "groups": ["admins", "users"],
        }
        claims = extract_claims(raw)
        assert claims.issuer == "https://auth.example.com"
        assert claims.subject == "user1"
        assert claims.email == "user@example.com"
        assert claims.email_verified is True
        assert claims.preferred_username == "user1"
        assert claims.name == "User One"
        assert claims.groups == ["admins", "users"]
        assert claims.raw == raw

    def test_missing_optional_fields(self):
        raw = {"iss": "https://auth.example.com", "sub": "user1"}
        claims = extract_claims(raw)
        assert claims.email is None
        assert claims.name is None
        assert claims.groups == []

    def test_groups_as_string(self):
        raw = {
            "iss": "https://auth.example.com",
            "sub": "user1",
            "groups": "admins",
        }
        claims = extract_claims(raw)
        assert claims.groups == ["admins"]


class TestClaimsToIdentity:
    def test_default_mapping(self):
        raw = {
            "iss": "https://auth.example.com",
            "sub": "user1",
            "email": "user@example.com",
            "preferred_username": "user1",
            "name": "User One",
            "groups": ["admins"],
        }
        claims = extract_claims(raw)
        config = UserMappingConfig()
        identity = claims_to_identity(claims, config)

        assert identity.issuer == "https://auth.example.com"
        assert identity.subject == "user1"
        assert identity.email == "user@example.com"
        assert identity.username == "user1"
        assert identity.display_name == "User One"
        assert identity.groups == ["admins"]
        assert identity.claims is claims

    def test_custom_claim_names(self):
        raw = {
            "iss": "https://auth.example.com",
            "sub": "user1",
            "custom_email": "custom@example.com",
            "login": "mylogin",
            "full_name": "Full Name",
            "roles": ["editor"],
        }
        claims = extract_claims(raw)
        config = UserMappingConfig(
            email_claim="custom_email",
            username_claim="login",
            display_name_claim="full_name",
            groups_claim="roles",
        )
        identity = claims_to_identity(claims, config)

        assert identity.email == "custom@example.com"
        assert identity.username == "mylogin"
        assert identity.display_name == "Full Name"
        assert identity.groups == ["editor"]
