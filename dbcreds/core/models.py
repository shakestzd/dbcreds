# dbcreds/core/models.py
"""
Pydantic models for database credentials.

This module defines the data models used throughout dbcreds for type safety
and validation.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, SecretStr, field_validator


class DatabaseType(str, Enum):
    """Supported database types."""

    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    # Apache Doris. Speaks the MySQL wire protocol, but its password
    # statement differs from MySQL 8, which removed PASSWORD().
    DORIS = "doris"
    ORACLE = "oracle"
    MSSQL = "mssql"
    SQLITE = "sqlite"


class Environment(BaseModel):
    """
    Database environment configuration.

    Represents a named database environment (e.g., dev, staging, prod) with
    its associated settings.

    Attributes:
        name: Environment name (e.g., 'dev', 'prod')
        database_type: Type of database
        description: Optional description of the environment
        is_production: Whether this is a production environment
        created_at: When the environment was created
        updated_at: When the environment was last updated
    """

    name: str = Field(..., min_length=1, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    database_type: DatabaseType
    description: Optional[str] = None
    is_production: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate environment name."""
        return v.lower()

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def ensure_timezone_aware(cls, v):
        """Ensure datetime fields are timezone-aware."""
        if v is None:
            return v
        if isinstance(v, str):
            # If it's a string, let Pydantic parse it
            return v
        if isinstance(v, datetime) and v.tzinfo is None:
            # If it's a naive datetime, assume UTC
            return v.replace(tzinfo=timezone.utc)
        return v


class DatabaseCredentials(BaseModel):
    """
    Database connection credentials.

    Secure storage model for database connection information.

    Attributes:
        environment: Environment name
        host: Database server hostname or IP
        port: Database server port
        database: Database name
        username: Database username
        password: Database password (stored securely)
        options: Additional connection options
        ssl_mode: SSL connection mode
        password_updated_at: When the password was last updated
        password_expires_at: When the password expires
    """

    environment: str
    host: str
    port: int = Field(..., gt=0, le=65535)
    database: str
    username: str
    password: SecretStr
    # Lets a credential describe its own dialect, so a connection string can be
    # built without consulting the environment registry.
    database_type: Optional[DatabaseType] = None
    options: Dict[str, Any] = Field(default_factory=dict)
    ssl_mode: Optional[str] = None
    password_updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    password_expires_at: Optional[datetime] = None

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int, info) -> int:
        """Set default port based on database type if not specified."""
        if v is None and hasattr(info, "context") and "database_type" in info.context:
            db_type = info.context["database_type"]
            defaults = {
                DatabaseType.POSTGRESQL: 5432,
                DatabaseType.MYSQL: 3306,
                DatabaseType.ORACLE: 1521,
                DatabaseType.MSSQL: 1433,
            }
            return defaults.get(db_type, v)
        return v

    @field_validator("password_updated_at", "password_expires_at", mode="before")
    @classmethod
    def ensure_timezone_aware(cls, v):
        """Ensure datetime fields are timezone-aware."""
        if v is None:
            return v
        if isinstance(v, str):
            # If it's a string, let Pydantic parse it
            return v
        if isinstance(v, datetime) and v.tzinfo is None:
            # If it's a naive datetime, assume UTC
            return v.replace(tzinfo=timezone.utc)
        return v

    def get_connection_string(
        self, include_password: bool = True, driver: Optional[str] = None
    ) -> str:
        """
        Generate a connection string for the database.

        Args:
            include_password: Whether to include the password in the connection string
            driver: Optional driver override for the connection string

        Returns:
            Database connection URI

        Examples:
            >>> creds.get_connection_string()
            'postgresql://user:pass@localhost:5432/mydb'
            >>> creds.get_connection_string(include_password=False)
            'postgresql://user@localhost:5432/mydb'
        """
        from urllib.parse import quote

        from dbcreds.core.adapters import scheme_for

        scheme = driver or scheme_for(self.database_type)

        # Percent-encode: a credential that is legal in the database can still
        # contain characters ('@', ':', '/') that change how the URI parses.
        username = quote(self.username, safe="")
        password_part = (
            f":{quote(self.password.get_secret_value(), safe='')}"
            if include_password
            else ""
        )
        return (
            f"{scheme}://{username}{password_part}"
            f"@{self.host}:{self.port}/{self.database}"
        )

    def is_password_expired(self) -> bool:
        """Check if the password has expired."""
        if self.password_expires_at is None:
            return False

        # Ensure both datetimes are timezone-aware for comparison
        expires_at = self.password_expires_at
        if expires_at.tzinfo is None:
            # If naive, assume it was UTC
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        return datetime.now(timezone.utc) > expires_at

    def days_until_expiry(self) -> Optional[int]:
        """Get the number of days until password expiry."""
        if self.password_expires_at is None:
            return None

        # Ensure both datetimes are timezone-aware for comparison
        expires_at = self.password_expires_at
        if expires_at.tzinfo is None:
            # If naive, assume it was UTC
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        delta = expires_at - datetime.now(timezone.utc)
        return max(0, delta.days)  # Return 0 if already expired


class CredentialMetadata(BaseModel):
    """
    Metadata about stored credentials.

    Tracks additional information about credentials for management purposes.

    Attributes:
        environment: Environment name
        created_by: User who created the credentials
        created_at: When the credentials were created
        last_accessed: When the credentials were last accessed
        access_count: Number of times accessed
        last_tested: When the connection was last tested
        last_test_success: Whether the last test was successful
    """

    environment: str
    created_by: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed: Optional[datetime] = None
    access_count: int = 0
    last_tested: Optional[datetime] = None
    last_test_success: Optional[bool] = None

    @field_validator("created_at", "last_accessed", "last_tested", mode="before")
    @classmethod
    def ensure_timezone_aware(cls, v):
        """Ensure datetime fields are timezone-aware."""
        if v is None:
            return v
        if isinstance(v, str):
            # If it's a string, let Pydantic parse it
            return v
        if isinstance(v, datetime) and v.tzinfo is None:
            # If it's a naive datetime, assume UTC
            return v.replace(tzinfo=timezone.utc)
        return v
