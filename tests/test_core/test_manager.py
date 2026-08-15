# tests/test_core/test_manager.py
"""Tests for the CredentialManager class."""

import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from dbcreds.backends.base import CredentialBackend
from dbcreds.core.exceptions import (
    CredentialError,
    CredentialNotFoundError,
    PasswordExpiredError,
)
from dbcreds.core.manager import CredentialManager
from dbcreds.core.models import DatabaseType


class MockBackend(CredentialBackend):
    """Mock backend for testing."""

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
        if key in self.storage:
            del self.storage[key]
            return True
        return False


class MetadataOnlyBackend(CredentialBackend):
    """
    Backend that accepts writes but drops the password.

    Mirrors ConfigFileBackend: set_credential() reports success while
    deliberately discarding the secret, so get_credential() can only ever
    hand back an empty password.
    """

    stores_secrets = False

    def __init__(self):
        self.storage = {}

    def is_available(self) -> bool:
        return True

    def get_credential(self, key: str):
        if key in self.storage:
            username, metadata = self.storage[key]
            return (username, "", metadata)
        return None

    def set_credential(
        self, key: str, username: str, password: str, metadata: dict
    ) -> bool:
        # Password intentionally not persisted -- this is the whole point.
        self.storage[key] = (username, metadata)
        return True

    def delete_credential(self, key: str) -> bool:
        if key in self.storage:
            del self.storage[key]
            return True
        return False


@pytest.fixture
def temp_config_dir():
    """Create a temporary config directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def mock_backend():
    """Create a mock backend."""
    return MockBackend()


def _manager_with_backends(config_dir, backends):
    """
    Build a CredentialManager backed only by the given backends.

    Initialization is forced first: backends are set up lazily on first use, so
    assigning the list beforehand would just get the real system backends
    appended to it -- including the live keyring.
    """
    manager = CredentialManager(config_dir=config_dir)
    manager._ensure_initialized()
    manager.backends = list(backends)
    return manager


@pytest.fixture
def manager(temp_config_dir, mock_backend):
    """Create a CredentialManager with mocked backends."""
    return _manager_with_backends(temp_config_dir, [mock_backend])


@pytest.fixture
def sample_credentials():
    """Sample credential data for testing."""
    return {
        "host": "localhost",
        "port": 5432,
        "database": "testdb",
        "username": "testuser",
        "password": "testpass123",
    }


class TestCredentialManager:
    """Test cases for CredentialManager."""

    def test_add_environment(self, manager):
        """Test adding a new environment."""
        env = manager.add_environment(
            "test-env", DatabaseType.POSTGRESQL, "Test environment"
        )

        assert env.name == "test-env"
        assert env.database_type == DatabaseType.POSTGRESQL
        assert env.description == "Test environment"
        assert not env.is_production

        # Verify environment is stored
        assert "test-env" in manager.environments

    def test_add_duplicate_environment(self, manager):
        """Test adding a duplicate environment raises error."""
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        with pytest.raises(CredentialError, match="already exists"):
            manager.add_environment("test-env", DatabaseType.MYSQL)

    def test_set_and_get_credentials(self, manager, sample_credentials):
        """Test storing and retrieving credentials."""
        # Add environment
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        # Set credentials
        creds = manager.set_credentials("test-env", **sample_credentials)

        assert creds.host == sample_credentials["host"]
        assert creds.port == sample_credentials["port"]
        assert creds.database == sample_credentials["database"]
        assert creds.username == sample_credentials["username"]

        # Get credentials
        retrieved = manager.get_credentials("test-env")
        assert retrieved.host == sample_credentials["host"]
        assert retrieved.port == sample_credentials["port"]
        assert retrieved.database == sample_credentials["database"]
        assert retrieved.username == sample_credentials["username"]
        assert retrieved.password.get_secret_value() == sample_credentials["password"]

    def test_get_nonexistent_credentials(self, manager):
        """Test getting credentials for nonexistent environment."""
        with pytest.raises(CredentialNotFoundError):
            manager.get_credentials("nonexistent")

    def test_password_expiry(self, manager, sample_credentials):
        """Test password expiry functionality."""
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        # Set credentials with already expired password
        # First set normal credentials
        manager.set_credentials(
            "test-env", **sample_credentials, password_expires_days=90
        )

        # Now manually update the backend storage to have expired credentials
        mock_backend = manager.backends[0]

        # Get the current stored data
        username, password, metadata = mock_backend.storage["dbcreds:test-env"]

        # Update the expiry date to be in the past
        expired_date = datetime.now(timezone.utc) - timedelta(days=1)
        metadata["password_expires_at"] = expired_date.isoformat()

        # Store back with updated metadata
        mock_backend.storage["dbcreds:test-env"] = (username, password, metadata)

        # Should raise password expired error
        with pytest.raises(PasswordExpiredError):
            manager.get_credentials("test-env")

    def test_password_expiry_disabled(self, manager, sample_credentials):
        """Test credentials with no expiry."""
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        # Set credentials without expiry
        manager.set_credentials(
            "test-env", **sample_credentials, password_expires_days=None
        )

        # Should not raise error
        creds = manager.get_credentials("test-env")
        assert creds.password_expires_at is None
        assert not creds.is_password_expired()

    def test_remove_environment(self, manager, sample_credentials):
        """Test removing an environment."""
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)
        manager.set_credentials("test-env", **sample_credentials)

        # Verify it exists
        assert "test-env" in manager.environments

        # Remove it
        manager.remove_environment("test-env")

        # Verify it's gone
        assert "test-env" not in manager.environments

        # Verify credentials are also gone
        with pytest.raises(CredentialNotFoundError):
            manager.get_credentials("test-env")

    def test_list_environments(self, manager):
        """Test listing environments."""
        # Add multiple environments
        manager.add_environment("dev", DatabaseType.POSTGRESQL)
        manager.add_environment("staging", DatabaseType.MYSQL)
        manager.add_environment("prod", DatabaseType.POSTGRESQL, is_production=True)

        envs = manager.list_environments()
        assert len(envs) == 3

        env_names = [env.name for env in envs]
        assert "dev" in env_names
        assert "staging" in env_names
        assert "prod" in env_names

        # Check production flag
        prod_env = next(env for env in envs if env.name == "prod")
        assert prod_env.is_production


class TestRemoveEnvironment:
    """
    Unregistering must not reach into the credential store uninvited.

    The store may be shared and externally owned: deleting a 1Password item
    removes it, and its history, for everyone with access.
    """

    def test_credentials_are_kept_by_default(self, manager, sample_credentials):
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)
        manager.set_credentials("test-env", **sample_credentials)

        manager.remove_environment("test-env")

        assert "test-env" not in manager.environments
        assert "dbcreds:test-env" in manager.backends[0].storage

    def test_credentials_are_deleted_when_asked(self, manager, sample_credentials):
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)
        manager.set_credentials("test-env", **sample_credentials)

        manager.remove_environment("test-env", delete_credentials=True)

        assert "test-env" not in manager.environments
        assert "dbcreds:test-env" not in manager.backends[0].storage

    def test_unknown_environment_still_raises(self, manager):
        with pytest.raises(CredentialNotFoundError):
            manager.remove_environment("nonexistent")


class TestSslModeSurvives:
    """ssl_mode has no set_credentials parameter, so rewrites used to drop it."""

    def test_round_trips(self, manager, sample_credentials):
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)
        manager.set_credentials("test-env", **sample_credentials, ssl_mode="require")

        assert manager.get_credentials("test-env").ssl_mode == "require"

    def test_not_swallowed_into_options(self, manager, sample_credentials):
        """It is a first-class field, not a connection option."""
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)
        manager.set_credentials("test-env", **sample_credentials, ssl_mode="require")

        creds = manager.get_credentials("test-env")
        assert "ssl_mode" not in creds.options


class TestSingletonConfigDir:
    """A singleton that silently ignores a different config_dir is a trap."""

    def test_warns_when_config_dir_is_ignored(self, temp_config_dir, caplog):
        CredentialManager(config_dir=temp_config_dir)

        with caplog.at_level("WARNING"):
            second = CredentialManager(config_dir="/somewhere/else")

        assert second.config_dir == temp_config_dir

    def test_no_warning_when_config_dir_matches(self, temp_config_dir):
        first = CredentialManager(config_dir=temp_config_dir)
        second = CredentialManager(config_dir=temp_config_dir)

        assert first is second
        assert second.config_dir == temp_config_dir


class TestDatabaseTypeResolution:
    """
    Credentials must know their dialect, whatever backend they came from.

    A backend need not record the type at all -- keyring and env vars do not --
    so the environment registry fills it in. Without this, get_connection_string()
    silently falls back to postgresql:// for every database.
    """

    def test_type_is_filled_in_from_the_environment(self, manager, sample_credentials):
        manager.add_environment("test-env", DatabaseType.MYSQL)
        manager.set_credentials("test-env", **sample_credentials)

        # Simulate a backend that stored nothing about the dialect.
        username, password, metadata = manager.backends[0].storage["dbcreds:test-env"]
        metadata.pop("database_type", None)
        manager.backends[0].storage["dbcreds:test-env"] = (username, password, metadata)

        creds = manager.get_credentials("test-env")

        assert creds.database_type == DatabaseType.MYSQL
        assert creds.get_connection_string().startswith("mysql+pymysql://")

    def test_environment_wins_over_stale_stored_type(self, manager, sample_credentials):
        """An out-of-date value written by another tool must not take over."""
        manager.add_environment("test-env", DatabaseType.DORIS)
        manager.set_credentials("test-env", **sample_credentials)

        username, password, metadata = manager.backends[0].storage["dbcreds:test-env"]
        metadata["database_type"] = "postgresql"
        manager.backends[0].storage["dbcreds:test-env"] = (username, password, metadata)

        assert manager.get_credentials("test-env").database_type == DatabaseType.DORIS

    def test_type_is_recorded_on_write(self, manager, sample_credentials):
        manager.add_environment("test-env", DatabaseType.DORIS)
        manager.set_credentials("test-env", **sample_credentials)

        _, _, metadata = manager.backends[0].storage["dbcreds:test-env"]
        assert metadata["database_type"] == "doris"


class TestSecretStoredOnce:
    """The secret belongs in one store, not scattered across every backend."""

    def test_only_the_first_secret_capable_backend_receives_it(
        self, temp_config_dir, sample_credentials
    ):
        primary, secondary = MockBackend(), MockBackend()
        manager = _manager_with_backends(temp_config_dir, [primary, secondary])
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        manager.set_credentials("test-env", **sample_credentials)

        assert "dbcreds:test-env" in primary.storage
        assert "dbcreds:test-env" not in secondary.storage

    def test_metadata_backends_still_receive_the_record(
        self, temp_config_dir, sample_credentials
    ):
        """Metadata-only backends are not secret stores, so they all get written."""
        primary = MockBackend()
        metadata_only = MetadataOnlyBackend()
        manager = _manager_with_backends(temp_config_dir, [primary, metadata_only])
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        manager.set_credentials("test-env", **sample_credentials)

        assert "dbcreds:test-env" in primary.storage
        assert "dbcreds:test-env" in metadata_only.storage


class FailingSecretBackend(MockBackend):
    """A secret store that is available but rejects writes."""

    def set_credential(self, key, username, password, metadata) -> bool:
        return False


class TestNoFallbackAcrossSecretStores:
    """
    A failed high-priority store must not be papered over by a lower one.

    Reads take the first backend that answers. If the primary store rejects the
    write and a secondary accepts it, the primary keeps returning its old value
    on every read -- so the write looks successful while nothing that reads it
    sees the change.
    """

    def test_raises_rather_than_falling_back(self, temp_config_dir, sample_credentials):
        primary, secondary = FailingSecretBackend(), MockBackend()
        manager = _manager_with_backends(temp_config_dir, [primary, secondary])
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        with pytest.raises(CredentialError, match="shadowing"):
            manager.set_credentials("test-env", **sample_credentials)

    def test_lower_priority_store_is_left_untouched(
        self, temp_config_dir, sample_credentials
    ):
        """The fallback store must not end up holding a secret nothing reads."""
        primary, secondary = FailingSecretBackend(), MockBackend()
        manager = _manager_with_backends(temp_config_dir, [primary, secondary])
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        with pytest.raises(CredentialError):
            manager.set_credentials("test-env", **sample_credentials)

        assert secondary.storage == {}

    def test_error_names_the_backend_that_failed(self, temp_config_dir, sample_credentials):
        primary = FailingSecretBackend()
        manager = _manager_with_backends(temp_config_dir, [primary, MockBackend()])
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        with pytest.raises(CredentialError, match="FailingSecretBackend"):
            manager.set_credentials("test-env", **sample_credentials)


class TestSecretCapableBackendRequired:
    """Regression tests: a metadata-only backend must not be reported as success."""

    @pytest.fixture
    def metadata_only_manager(self, temp_config_dir):
        """Manager whose only available backend cannot store passwords."""
        return _manager_with_backends(temp_config_dir, [MetadataOnlyBackend()])

    def test_set_credentials_raises_when_no_secret_capable_backend(
        self, metadata_only_manager, sample_credentials
    ):
        """
        Storing must fail loudly when only a metadata-only backend is available.

        Previously any backend returning True marked the write as successful, so
        ConfigFileBackend -- which strips the password by design -- made
        set_credentials() report success while the password was unrecoverable.
        """
        metadata_only_manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        with pytest.raises(CredentialError) as exc_info:
            metadata_only_manager.set_credentials("test-env", **sample_credentials)

        message = str(exc_info.value)
        assert "was NOT saved" in message
        assert "MetadataOnlyBackend" in message

    def test_password_is_not_silently_empty_after_failure(
        self, metadata_only_manager, sample_credentials
    ):
        """The failure must surface at write time, not as an empty password later."""
        metadata_only_manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        with pytest.raises(CredentialError):
            metadata_only_manager.set_credentials("test-env", **sample_credentials)

        # Demonstrate what the old behaviour would have handed back: the metadata
        # backend does retain a record, but with no usable password.
        _, password, _ = metadata_only_manager.backends[0].get_credential(
            "dbcreds:test-env"
        )
        assert password == ""

    def test_set_credentials_succeeds_with_secret_capable_backend(
        self, manager, sample_credentials
    ):
        """A secret-capable backend alongside a metadata-only one still succeeds."""
        manager.backends.append(MetadataOnlyBackend())
        manager.add_environment("test-env", DatabaseType.POSTGRESQL)

        creds = manager.set_credentials("test-env", **sample_credentials)

        assert creds.password.get_secret_value() == sample_credentials["password"]

    def test_get_active_backend_name(self, manager):
        """The active backend is the first one that can store passwords."""
        manager.backends.insert(0, MetadataOnlyBackend())

        assert manager.get_active_backend_name() == "MockBackend"

    def test_get_active_backend_name_is_none_without_secret_store(
        self, metadata_only_manager
    ):
        """No secret-capable backend means no active backend to trust."""
        assert metadata_only_manager.get_active_backend_name() is None

    def test_list_backends_reports_capability(self, metadata_only_manager):
        """Backend listing exposes the stores_secrets capability."""
        assert metadata_only_manager.list_backends() == [("MetadataOnlyBackend", False)]

    def test_config_file_backend_is_not_secret_capable(self):
        """ConfigFileBackend must declare that it cannot store passwords."""
        from dbcreds.backends.config import ConfigFileBackend

        assert ConfigFileBackend.stores_secrets is False

    def test_keyring_backend_is_secret_capable(self):
        """KeyringBackend is the real credential store and must count."""
        from dbcreds.backends.keyring import KeyringBackend

        assert KeyringBackend.stores_secrets is True
