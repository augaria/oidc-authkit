"""Tests for state and nonce management."""

from oidc_authkit.protocol.state import StateManager
from oidc_authkit.protocol.nonce import NonceManager


class TestStateManager:
    def test_generate_and_validate(self):
        mgr = StateManager("test-secret-key-1234")
        state = mgr.generate()
        assert mgr.validate(state) is True

    def test_invalid_state_rejected(self):
        mgr = StateManager("test-secret-key-1234")
        assert mgr.validate("invalid-state") is False

    def test_tampered_state_rejected(self):
        mgr = StateManager("test-secret-key-1234")
        state = mgr.generate()
        tampered = state[:-1] + ("a" if state[-1] != "a" else "b")
        assert mgr.validate(tampered) is False

    def test_different_secret_rejects(self):
        mgr1 = StateManager("secret-one-1234567")
        mgr2 = StateManager("secret-two-1234567")
        state = mgr1.generate()
        assert mgr2.validate(state) is False

    def test_expired_state_rejected(self):
        mgr = StateManager("test-secret-key-1234", max_age_seconds=0)
        state = mgr.generate()
        # state is immediately expired with max_age_seconds=0
        # Need to wait at least 1 second
        import time
        time.sleep(1)
        assert mgr.validate(state) is False

    def test_state_uniqueness(self):
        mgr = StateManager("test-secret-key-1234")
        states = {mgr.generate() for _ in range(10)}
        assert len(states) == 10


class TestNonceManager:
    def test_generate(self):
        mgr = NonceManager()
        nonce = mgr.generate()
        assert isinstance(nonce, str)
        assert len(nonce) > 20

    def test_uniqueness(self):
        mgr = NonceManager()
        nonces = {mgr.generate() for _ in range(10)}
        assert len(nonces) == 10
