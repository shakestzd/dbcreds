# tests/test_core/test_rotation.py
"""
Tests for CredentialManager.rotate_password.

Rotation spans two systems, so the interesting cases are the ones where they
can disagree. A fake server and a fake store both hold real state here, and
every test asserts where *both* ended up -- an assertion on only one of them
would pass in exactly the situation this feature exists to prevent.
"""

import re
import tempfile

import pytest

from dbcreds.backends.base import CredentialBackend
from dbcreds.core.adapters import DatabaseAdapter, DorisAdapter
from dbcreds.core.exceptions import RotationError
from dbcreds.core.manager import CredentialManager
from dbcreds.core.models import DatabaseType

ORIGINAL_PASSWORD = "ORIGINALpass123"


class FakeServer:
    """A database that knows one password."""

    def __init__(self, password: str):
        self.password = password


class FakeAdapter(DatabaseAdapter):
    """Adapter over FakeServer, with injectable failures."""

    database_type = DatabaseType.DORIS
    scheme = "fake"
    default_port = 9030

    def __init__(self, server: FakeServer, fail_execute: bool = False,
                 ignore_execute: bool = False):
        self.server = server
        self.fail_execute = fail_execute
        # ignore_execute models a server that accepts the statement but does
        # not actually change anything.
        self.ignore_execute = ignore_execute

    def connect(self, creds, connect_timeout: int = 10):
        raise NotImplementedError("tests use check_connection/execute directly")

    def check_connection(self, creds, connect_timeout: int = 10) -> bool:
        return creds.password.get_secret_value() == self.server.password

    def execute(self, creds, statement: str, connect_timeout: int = 10) -> None:
        if self.fail_execute:
            raise RuntimeError("SET PASSWORD rejected")
        if creds.password.get_secret_value() != self.server.password:
            raise RuntimeError("access denied")
        if self.ignore_execute:
            return
        match = re.search(r"PASSWORD\('([^']+)'\)", statement)
        assert match, f"unexpected statement: {statement}"
        self.server.password = match.group(1)

    def password_change_statement(self, username, new_password, user_host="%"):
        return DorisAdapter().password_change_statement(
            username, new_password, user_host=user_host
        )


class StoreBackend(CredentialBackend):
    """Secret-capable store, with an injectable write failure."""

    stores_secrets = True

    def __init__(self, fail_write: bool = False):
        self.storage = {}
        self.fail_write = fail_write

    def is_available(self) -> bool:
        return True

    def get_credential(self, key: str):
        return self.storage.get(key)

    def set_credential(self, key, username, password, metadata) -> bool:
        if self.fail_write:
            return False
        self.storage[key] = (username, password, metadata)
        return True

    def delete_credential(self, key: str) -> bool:
        return self.storage.pop(key, None) is not None


@pytest.fixture
def rotation_env(monkeypatch):
    """
    A manager, a store and a server that all start in agreement.

    Yields a helper exposing both sides so tests can assert on each.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        server = FakeServer(ORIGINAL_PASSWORD)
        store = StoreBackend()

        manager = CredentialManager(config_dir=tmpdir)
        manager._ensure_initialized()
        manager.backends = [store]
        manager.add_environment("prod", DatabaseType.DORIS)
        manager.set_credentials(
            "prod", "db.example.internal", 9030, "analytics", "dbuser",
            ORIGINAL_PASSWORD, password_expires_days=180,
        )

        adapter = FakeAdapter(server)
        monkeypatch.setattr(
            "dbcreds.core.adapters.get_adapter", lambda _type: adapter
        )

        class Harness:
            def __init__(self):
                self.manager = manager
                self.server = server
                self.store = store
                self.adapter = adapter

            def stored_password(self):
                return manager.get_credentials("prod", check_expiry=False) \
                    .password.get_secret_value()

        yield Harness()


class TestRotationSucceeds:
    """The happy path must leave both sides holding the same new password."""

    def test_both_sides_updated(self, rotation_env):
        new_password = rotation_env.manager.rotate_password("prod")

        assert new_password != ORIGINAL_PASSWORD
        assert rotation_env.server.password == new_password
        assert rotation_env.stored_password() == new_password

    def test_generated_password_length(self, rotation_env):
        assert len(rotation_env.manager.rotate_password("prod", length=48)) == 48

    def test_expiry_policy_is_preserved(self, rotation_env):
        """
        Rotating must not silently reset a 180-day policy to the default.
        """
        rotation_env.manager.rotate_password("prod")

        creds = rotation_env.manager.get_credentials("prod", check_expiry=False)
        window = creds.password_expires_at - creds.password_updated_at
        assert window.days == 180

    def test_other_fields_survive(self, rotation_env):
        rotation_env.manager.rotate_password("prod")

        creds = rotation_env.manager.get_credentials("prod", check_expiry=False)
        assert creds.host == "db.example.internal"
        assert creds.port == 9030
        assert creds.database == "analytics"
        assert creds.username == "dbuser"


class TestRotationFailsSafely:
    """Every failure must leave the two systems in agreement."""

    def test_database_change_fails_changes_nothing(self, rotation_env):
        rotation_env.adapter.fail_execute = True

        with pytest.raises(RotationError, match="Nothing changed"):
            rotation_env.manager.rotate_password("prod")

        assert rotation_env.server.password == ORIGINAL_PASSWORD
        assert rotation_env.stored_password() == ORIGINAL_PASSWORD

    def test_store_write_fails_rolls_database_back(self, rotation_env):
        """
        The database changed but the store could not record it, so the database
        is put back rather than left holding a password nothing knows.
        """
        rotation_env.store.fail_write = True

        with pytest.raises(RotationError, match="Rolled the database back"):
            rotation_env.manager.rotate_password("prod")

        assert rotation_env.server.password == ORIGINAL_PASSWORD
        assert rotation_env.stored_password() == ORIGINAL_PASSWORD

    def test_stale_store_is_refused_up_front(self, rotation_env):
        """
        The store and database already disagree, so no rotation is attempted.

        This is the state a half-finished rotation leaves behind; attempting to
        rotate out of it would fail at the point of no return instead.
        """
        rotation_env.server.password = "SOMETHING-ELSE"

        with pytest.raises(RotationError, match="does not work against"):
            rotation_env.manager.rotate_password("prod")

        assert rotation_env.server.password == "SOMETHING-ELSE"
        assert rotation_env.stored_password() == ORIGINAL_PASSWORD

    def test_server_ignores_change_reports_nothing_changed(self, rotation_env):
        """A server that accepts the statement but ignores it is detected."""
        rotation_env.adapter.ignore_execute = True

        with pytest.raises(RotationError, match="did not accept the new password"):
            rotation_env.manager.rotate_password("prod")

        assert rotation_env.server.password == ORIGINAL_PASSWORD
        assert rotation_env.stored_password() == ORIGINAL_PASSWORD


class TestUnrecoverableRotation:
    """
    The one case where state is genuinely lost.

    If the database took the new password and it could neither be saved nor
    rolled back, the error must carry the password so the caller can show it --
    it is the only remaining copy.
    """

    def test_error_carries_password_when_rollback_impossible(self, rotation_env):
        rotation_env.store.fail_write = True
        # A one-way server: the change applies, but rolling back fails.
        original_execute = rotation_env.adapter.execute
        calls = {"n": 0}

        def execute_once(creds, statement, connect_timeout=10):
            calls["n"] += 1
            if calls["n"] > 1:
                raise RuntimeError("rollback refused")
            original_execute(creds, statement, connect_timeout)

        rotation_env.adapter.execute = execute_once

        with pytest.raises(RotationError) as exc_info:
            rotation_env.manager.rotate_password("prod")

        error = exc_info.value
        assert error.applied is True
        assert error.new_password
        # The password it reports must be the one the server actually has.
        assert error.new_password == rotation_env.server.password
