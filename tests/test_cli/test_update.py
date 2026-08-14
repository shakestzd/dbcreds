# tests/test_cli/test_update.py
"""Tests for the 'dbcreds update' command."""

import pytest
from typer.testing import CliRunner

from dbcreds.backends.base import CredentialBackend
from dbcreds.cli import app
from dbcreds.core.manager import CredentialManager
from dbcreds.core.models import DatabaseType

runner = CliRunner()

ORIGINAL_PASSWORD = "OldPass123-original"
ORIGINAL_EXPIRY_DAYS = 180


class DictBackend(CredentialBackend):
    """Secret-capable in-memory backend."""

    def __init__(self):
        self.storage = {}

    def is_available(self) -> bool:
        return True

    def get_credential(self, key: str):
        return self.storage.get(key)

    def set_credential(
        self, key: str, username: str, password: str, metadata: dict
    ) -> bool:
        self.storage[key] = (username, password, metadata)
        return True

    def delete_credential(self, key: str) -> bool:
        return self.storage.pop(key, None) is not None


@pytest.fixture
def cli_manager(temp_config_dir):
    """
    Seed the CredentialManager singleton the CLI will pick up.

    CredentialManager is a singleton, so constructing it here with a mock backend
    means the in-process CLI invocation below operates on this same instance
    instead of the real keyring.
    """
    manager = CredentialManager(config_dir=temp_config_dir)
    manager._ensure_initialized()
    manager.backends = [DictBackend()]
    manager.add_environment("dev", DatabaseType.POSTGRESQL)
    manager.set_credentials(
        "dev",
        "old-host",
        5432,
        "olddb",
        "olduser",
        ORIGINAL_PASSWORD,
        password_expires_days=ORIGINAL_EXPIRY_DAYS,
        connect_timeout=10,
    )
    return manager


def _stored(manager):
    """Read the credentials back the way a later process would."""
    return manager.get_credentials("dev", check_expiry=False)


class TestUpdateExpiry:
    """--expires-days used to be silently ignored on its own."""

    def test_expiry_only_update_succeeds(self, cli_manager):
        """Updating just the expiry no longer prints 'not implemented'."""
        result = runner.invoke(app, ["update", "dev", "--expires-days", "30"])

        assert result.exit_code == 0
        assert "not implemented" not in result.stdout
        assert "expiry" in result.stdout

        creds = _stored(cli_manager)
        window = creds.password_expires_at - creds.password_updated_at
        assert window.days == 30

    def test_expiry_only_update_preserves_password(self, cli_manager):
        """Changing expiry must not disturb the stored secret."""
        runner.invoke(app, ["update", "dev", "--expires-days", "30"])

        assert _stored(cli_manager).password.get_secret_value() == ORIGINAL_PASSWORD

    def test_expiry_only_update_preserves_rotation_date(self, cli_manager):
        """
        The password did not change, so its 'last updated' date must not move.

        Otherwise a policy tweak would misreport when the password was rotated.
        """
        before = _stored(cli_manager).password_updated_at

        runner.invoke(app, ["update", "dev", "--expires-days", "30"])

        assert _stored(cli_manager).password_updated_at == before

    def test_zero_disables_expiry(self, cli_manager):
        """--expires-days 0 clears expiry (the old 'expires_days or 90' forced 90)."""
        result = runner.invoke(app, ["update", "dev", "--expires-days", "0"])

        assert result.exit_code == 0
        creds = _stored(cli_manager)
        assert creds.password_expires_at is None
        assert not creds.is_password_expired()


class TestUpdateFields:
    """Connection detail updates used to print 'not implemented yet'."""

    def test_updates_host_and_port(self, cli_manager):
        """Host and port are applied and reported."""
        result = runner.invoke(
            app, ["update", "dev", "--host", "new-host", "--port", "6543"]
        )

        assert result.exit_code == 0
        creds = _stored(cli_manager)
        assert creds.host == "new-host"
        assert creds.port == 6543
        assert "host" in result.stdout and "port" in result.stdout

    def test_updates_database_and_username(self, cli_manager):
        """Database and username are applied."""
        result = runner.invoke(
            app, ["update", "dev", "--database", "newdb", "--username", "newuser"]
        )

        assert result.exit_code == 0
        creds = _stored(cli_manager)
        assert creds.database == "newdb"
        assert creds.username == "newuser"

    def test_field_update_preserves_password_and_untouched_fields(self, cli_manager):
        """Only the named fields change; everything else survives."""
        runner.invoke(app, ["update", "dev", "--host", "new-host"])

        creds = _stored(cli_manager)
        assert creds.password.get_secret_value() == ORIGINAL_PASSWORD
        assert creds.port == 5432
        assert creds.database == "olddb"
        assert creds.username == "olduser"

    def test_field_update_preserves_options(self, cli_manager):
        """
        Connection options must survive an update.

        set_credentials() rebuilds the record from scratch, so options have to be
        passed back in explicitly or they are dropped.
        """
        runner.invoke(app, ["update", "dev", "--host", "new-host"])

        assert _stored(cli_manager).options.get("connect_timeout") == 10


class TestUpdateRotation:
    """Rotation must not quietly reset an environment's expiry policy."""

    def test_generate_rotates_password(self, cli_manager):
        """--generate replaces the stored password."""
        result = runner.invoke(app, ["update", "dev", "--generate"])

        assert result.exit_code == 0
        assert _stored(cli_manager).password.get_secret_value() != ORIGINAL_PASSWORD

    def test_rotation_keeps_existing_expiry_policy(self, cli_manager):
        """
        Rotating without --expires-days keeps the configured window.

        The old code passed 'expires_days or 90', so a 180-day policy silently
        became 90 days on every rotation.
        """
        runner.invoke(app, ["update", "dev", "--generate"])

        creds = _stored(cli_manager)
        window = creds.password_expires_at - creds.password_updated_at
        assert window.days == ORIGINAL_EXPIRY_DAYS

    def test_rotation_with_field_change(self, cli_manager):
        """Password and connection details can change in one call."""
        result = runner.invoke(
            app, ["update", "dev", "--generate", "--host", "new-host"]
        )

        assert result.exit_code == 0
        creds = _stored(cli_manager)
        assert creds.host == "new-host"
        assert creds.password.get_secret_value() != ORIGINAL_PASSWORD

    def test_rotation_advances_rotation_date(self, cli_manager):
        """A real rotation does stamp a new password_updated_at."""
        before = _stored(cli_manager).password_updated_at

        runner.invoke(app, ["update", "dev", "--generate"])

        assert _stored(cli_manager).password_updated_at > before


class TestUpdateNoOp:
    """A call that asks for nothing should say so rather than pretend."""

    def test_no_flags_reports_nothing_to_update(self, cli_manager):
        """Bare 'update <env>' exits non-zero with guidance."""
        result = runner.invoke(app, ["update", "dev"])

        assert result.exit_code == 1
        assert "Nothing to update" in result.stdout

    def test_no_flags_changes_nothing(self, cli_manager):
        """The no-op path must not rewrite the record."""
        before = _stored(cli_manager)

        runner.invoke(app, ["update", "dev"])

        after = _stored(cli_manager)
        assert after.password.get_secret_value() == before.password.get_secret_value()
        assert after.password_updated_at == before.password_updated_at
        assert after.host == before.host
