# dbcreds/core/manager.py
"""
Core credential manager implementation with lazy initialization.

This module provides the main CredentialManager class that orchestrates
credential storage and retrieval across different backends.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Type

# Lazy imports to speed up module loading
_logger = None
_ValidationError = None
_models_loaded = False
_backends_loaded = False


def _get_logger():
    """Lazy load logger only when needed."""
    global _logger
    if _logger is None:
        from loguru import logger
        _logger = logger
    return _logger


def _load_models():
    """Lazy load models."""
    global _models_loaded, _ValidationError
    if not _models_loaded:
        from pydantic import ValidationError as _VE
        _ValidationError = _VE
        _models_loaded = True


class CredentialManager:
    """
    Main credential management class with lazy initialization.

    Orchestrates credential storage and retrieval across multiple backends,
    manages environments, and handles password expiration.

    Attributes:
        config_dir: Directory for configuration files
        backends: List of available credential backends
        environments: Dictionary of configured environments

    Examples:
        >>> manager = CredentialManager()
        >>> manager.add_environment("dev", DatabaseType.POSTGRESQL)
        >>> manager.set_credentials("dev", "localhost", 5432, "mydb", "user", "pass")
        >>> creds = manager.get_credentials("dev")
    """
    
    _instance = None
    _initialized = False

    def __new__(cls, config_dir: Optional[str] = None):
        """Singleton pattern with lazy initialization."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize the credential manager with lazy loading.

        Args:
            config_dir: Optional custom configuration directory. Defaults to ~/.dbcreds
        """
        # Only initialize once
        if self._initialized:
            return

        self.config_dir = config_dir or os.path.expanduser("~/.dbcreds")
        self.backends: List = []  # Avoid importing types
        self.environments: Dict[str, object] = {}  # Avoid importing Environment

        # Don't do anything heavy yet!
        self._initialized = True
        self._backends_initialized = False
        self._environments_loaded = False

    def _ensure_initialized(self):
        """Initialize backends and environments on first real use."""
        if not self._backends_initialized:
            os.makedirs(self.config_dir, exist_ok=True)
            self._initialize_backends()
            self._backends_initialized = True

        if not self._environments_loaded:
            self._load_environments()
            self._environments_loaded = True

    def _initialize_backends(self) -> None:
        """Initialize available credential backends in priority order."""
        # Import these only when actually initializing
        from dbcreds.backends.base import CredentialBackend
        
        backend_classes: List[Type[CredentialBackend]] = []

        # Platform-specific backends first
        if os.name == "nt":
            try:
                from dbcreds.backends.windows import WindowsCredentialBackend
                backend_classes.append(WindowsCredentialBackend)
            except ImportError:
                pass
            
            try:
                from dbcreds.backends.legacy_windows import LegacyWindowsBackend
                backend_classes.append(LegacyWindowsBackend)
            except ImportError:
                pass

        # Cross-platform backends
        try:
            from dbcreds.backends.keyring import KeyringBackend
            backend_classes.append(KeyringBackend)
        except ImportError:
            pass
            
        try:
            from dbcreds.backends.environment import EnvironmentBackend
            backend_classes.append(EnvironmentBackend)
        except ImportError:
            pass
            
        try:
            from dbcreds.backends.config import ConfigFileBackend
            backend_classes.append(ConfigFileBackend)
        except ImportError:
            pass

        for backend_class in backend_classes:
            try:
                backend = backend_class()
                if backend.is_available():
                    self.backends.append(backend)
                    _get_logger().debug(f"Initialized backend: {backend.__class__.__name__}")
            except Exception as e:
                _get_logger().debug(f"Failed to initialize {backend_class.__name__}: {e}")

        if not self.backends:
            _get_logger().warning(
                "No credential backends available, falling back to config file only"
            )
            from dbcreds.backends.config import ConfigFileBackend
            self.backends.append(ConfigFileBackend(self.config_dir))

    def _load_environments(self) -> None:
        """Load environment configurations from disk."""
        from dbcreds.backends.config import ConfigFileBackend
        from dbcreds.core.models import Environment
        
        _load_models()
        
        config_backend = ConfigFileBackend(self.config_dir)
        environments_data = config_backend.load_environments()

        for env_data in environments_data:
            try:
                env = Environment(**env_data)
                self.environments[env.name] = env
            except _ValidationError as e:
                _get_logger().error(f"Invalid environment data: {e}")

    def add_environment(
        self,
        name: str,
        database_type,  # Avoid importing DatabaseType
        description: Optional[str] = None,
        is_production: bool = False,
    ):
        """
        Add a new environment configuration.

        Args:
            name: Environment name (e.g., 'dev', 'prod')
            database_type: Type of database
            description: Optional description
            is_production: Whether this is a production environment

        Returns:
            Created Environment object

        Raises:
            CredentialError: If environment already exists

        Examples:
            >>> manager.add_environment("dev", DatabaseType.POSTGRESQL, "Development database")
        """
        self._ensure_initialized()
        
        from dbcreds.core.exceptions import CredentialError
        from dbcreds.core.models import Environment
        
        if name.lower() in self.environments:
            raise CredentialError(f"Environment '{name}' already exists")

        env = Environment(
            name=name.lower(),
            database_type=database_type,
            description=description,
            is_production=is_production,
        )

        self.environments[env.name] = env
        self._save_environments()

        _get_logger().info(f"Added environment: {env.name}")
        return env

    def remove_environment(self, name: str) -> None:
        """
        Remove an environment and its credentials.

        Args:
            name: Environment name to remove

        Raises:
            CredentialNotFoundError: If environment doesn't exist
        """
        self._ensure_initialized()
        
        from dbcreds.core.exceptions import CredentialNotFoundError
        
        env_name = name.lower()
        if env_name not in self.environments:
            raise CredentialNotFoundError(f"Environment '{name}' not found")

        # Remove credentials from all backends
        for backend in self.backends:
            try:
                backend.delete_credential(f"dbcreds:{env_name}")
            except Exception as e:
                _get_logger().debug(f"Failed to delete from {backend.__class__.__name__}: {e}")

        del self.environments[env_name]
        self._save_environments()

        _get_logger().info(f"Removed environment: {env_name}")

    def set_credentials(
        self,
        environment: str,
        host: str,
        port: int,
        database: str,
        username: str,
        password: str,
        password_expires_days: Optional[int] = 90,
        password_updated_at: Optional[datetime] = None,
        **options,
    ):
        """
        Store credentials for an environment.

        Args:
            environment: Environment name
            host: Database host
            port: Database port
            database: Database name
            username: Database username
            password: Database password
            password_expires_days: Days until password expires (None for no expiry)
            password_updated_at: Optional custom password update timestamp
            **options: Additional connection options

        Returns:
            Created DatabaseCredentials object

        Raises:
            CredentialNotFoundError: If environment doesn't exist

        Examples:
            >>> manager.set_credentials("dev", "localhost", 5432, "mydb", "user", "pass")
        """
        self._ensure_initialized()
        
        from dbcreds.core.exceptions import CredentialNotFoundError, CredentialError
        from dbcreds.core.models import DatabaseCredentials
        
        env_name = environment.lower()
        if env_name not in self.environments:
            raise CredentialNotFoundError(f"Environment '{environment}' not found")

        # Use provided timestamp or current time
        if password_updated_at is None:
            password_updated_at = datetime.now(timezone.utc)
        # Ensure timezone aware
        elif password_updated_at.tzinfo is None:
            password_updated_at = password_updated_at.replace(tzinfo=timezone.utc)

        # Calculate password expiration based on the update timestamp
        password_expires_at = None
        if password_expires_days:
            password_expires_at = password_updated_at + timedelta(
                days=password_expires_days
            )

        # Create credentials object
        creds = DatabaseCredentials(
            environment=env_name,
            host=host,
            port=port,
            database=database,
            username=username,
            password=password,
            options=options,
            password_updated_at=password_updated_at,
            password_expires_at=password_expires_at,
        )

        # Store in backends. Metadata-only backends (e.g. ConfigFileBackend) are
        # still written to, but they must never be mistaken for the password
        # having been saved -- they strip it. Only a backend that durably
        # round-trips the secret counts as a real store.
        secret_stored = False
        metadata_only_stored = []
        _get_logger().debug(f"Storing credentials for {env_name} (dates updated)")
        for backend in self.backends:
            backend_name = backend.__class__.__name__
            try:
                # Prepare metadata without username/password/environment (they're passed separately)
                # Use model_dump with mode='json' to convert datetime objects to ISO strings
                metadata = creds.model_dump(mode='json')
                metadata.pop('username', None)
                metadata.pop('password', None)
                metadata.pop('environment', None)
                if backend.set_credential(
                    f"dbcreds:{env_name}", username, password, metadata
                ):
                    if getattr(backend, "stores_secrets", True):
                        secret_stored = True
                        _get_logger().debug(f"Successfully stored credentials in {backend_name}")
                    else:
                        metadata_only_stored.append(backend_name)
                        _get_logger().debug(f"Stored metadata only in {backend_name}")
            except Exception as e:
                _get_logger().debug(f"Failed to store in {backend_name}: {e}")

        if not secret_stored:
            available = ", ".join(b.__class__.__name__ for b in self.backends) or "none"
            detail = (
                f" Only metadata-only backends accepted it ({', '.join(metadata_only_stored)}), "
                "which do not store passwords."
                if metadata_only_stored
                else ""
            )
            raise CredentialError(
                f"Failed to store the password for environment '{env_name}': no secure "
                f"credential store accepted it.{detail} Available backends: {available}. "
                "Run 'dbcreds backends' to diagnose, then retry -- the credential was NOT saved."
            )

        _get_logger().info(f"Stored credentials for environment: {env_name}")
        return creds

    def get_credentials(
        self, environment: str, check_expiry: bool = True
    ):
        """
        Retrieve credentials for an environment.

        Args:
            environment: Environment name
            check_expiry: Whether to check for password expiration

        Returns:
            DatabaseCredentials object

        Raises:
            CredentialNotFoundError: If credentials not found
            PasswordExpiredError: If password has expired

        Examples:
            >>> creds = manager.get_credentials("dev")
            >>> print(creds.host, creds.port)
        """
        self._ensure_initialized()
        
        from dbcreds.core.exceptions import CredentialNotFoundError, PasswordExpiredError
        from dbcreds.core.models import DatabaseCredentials
        
        env_name = environment.lower()
        if env_name not in self.environments:
            raise CredentialNotFoundError(f"Environment '{environment}' not found")

        # Try each backend
        for backend in self.backends:
            try:
                result = backend.get_credential(f"dbcreds:{env_name}")
                if result:
                    username, password, metadata = result
                    # Remove 'environment' from metadata if it exists to avoid duplicate
                    metadata.pop('environment', None)
                    creds = DatabaseCredentials(
                        environment=env_name,
                        username=username,
                        password=password,
                        **metadata,
                    )

                    if check_expiry and creds.is_password_expired():
                        raise PasswordExpiredError(
                            f"Password for environment '{environment}' has expired"
                        )

                    _get_logger().debug(
                        f"Retrieved credentials from {backend.__class__.__name__}"
                    )
                    return creds
            except PasswordExpiredError:
                # An expired password is a found credential, not a missing one --
                # don't let the fallback loop mask it as "not found".
                raise
            except Exception as e:
                _get_logger().debug(f"Failed to get from {backend.__class__.__name__}: {e}")

        raise CredentialNotFoundError(
            f"No credentials found for environment '{environment}'"
        )

    def list_environments(self):
        """
        List all configured environments.

        Returns:
            List of Environment objects

        Examples:
            >>> envs = manager.list_environments()
            >>> for env in envs:
            ...     print(env.name, env.database_type)
        """
        self._ensure_initialized()
        return list(self.environments.values())

    def get_active_backend_name(self) -> Optional[str]:
        """
        Return the name of the backend that will actually store passwords.

        This is the first available backend that durably round-trips secrets --
        the one a new credential's password would be written to and later read
        back from. Metadata-only backends (e.g. ConfigFileBackend) are ignored.

        Returns:
            Backend class name, or None if no secret-capable backend is available

        Examples:
            >>> manager.get_active_backend_name()
            'KeyringBackend'
        """
        self._ensure_initialized()

        for backend in self.backends:
            if getattr(backend, "stores_secrets", True):
                return str(backend.__class__.__name__)
        return None

    def list_backends(self) -> List[Tuple[str, bool]]:
        """
        List available backends and whether each one stores secrets.

        Returns:
            List of (backend_name, stores_secrets) tuples, in priority order

        Examples:
            >>> manager.list_backends()
            [('KeyringBackend', True), ('ConfigFileBackend', False)]
        """
        self._ensure_initialized()

        return [
            (
                str(backend.__class__.__name__),
                bool(getattr(backend, "stores_secrets", True)),
            )
            for backend in self.backends
        ]

    def test_connection(self, environment: str) -> bool:
        """
        Test database connection for an environment.

        Args:
            environment: Environment name

        Returns:
            True if connection successful, False otherwise

        Examples:
            >>> if manager.test_connection("dev"):
            ...     print("Connection successful!")
        """
        self._ensure_initialized()
        
        from dbcreds.core.models import DatabaseType
        
        try:
            creds = self.get_credentials(environment)
            env = self.environments[environment.lower()]

            # Import appropriate database driver
            if env.database_type == DatabaseType.POSTGRESQL:
                import psycopg2

                conn = psycopg2.connect(
                    host=creds.host,
                    port=creds.port,
                    database=creds.database,
                    user=creds.username,
                    password=creds.password.get_secret_value(),
                )
                conn.close()
                return True
            # Add other database types as needed

        except Exception as e:
            _get_logger().error(f"Connection test failed for '{environment}': {e}")
            return False

    def _save_environments(self) -> None:
        """Save environment configurations to disk."""
        from dbcreds.backends.config import ConfigFileBackend
        
        config_backend = ConfigFileBackend(self.config_dir)
        config_backend.save_environments(
            [env.model_dump() for env in self.environments.values()]
        )
