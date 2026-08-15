# dbcreds/core/adapters.py
"""
Database adapters.

A backend answers "where does the secret live"; an adapter answers "what does
the credential authenticate to, and how is it changed there". Rotation needs
both, which is why it belongs in the manager rather than in either one.

Drivers are imported lazily so importing dbcreds never pulls in a database
driver that the caller does not need.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type

from dbcreds.core.exceptions import ValidationError
from dbcreds.core.models import DatabaseType

# Characters that would terminate or escape a SQL string literal. Passwords are
# embedded in DDL, which takes no bind parameters, so anything containing these
# is rejected rather than escaped -- guessing an escaping scheme per dialect is
# how injection bugs happen.
_SQL_UNSAFE = "'\"\\`"


def _reject_unsafe(value: str, what: str) -> str:
    """Reject values that cannot be embedded safely in a SQL literal."""
    if any(char in value for char in _SQL_UNSAFE):
        raise ValidationError(
            f"{what} contains a quote or backslash and cannot be used in a "
            "password-change statement"
        )
    if any(ord(char) < 32 for char in value):
        raise ValidationError(f"{what} contains a control character")
    return value


class DatabaseAdapter(ABC):
    """
    Per-dialect knowledge: how to connect, and how to change a password.

    Attributes:
        database_type: The DatabaseType this adapter serves
        scheme: SQLAlchemy URL scheme, e.g. 'mysql+pymysql'
        default_port: Port used when the environment does not specify one
    """

    database_type: DatabaseType
    scheme: str
    default_port: int

    @abstractmethod
    def connect(self, creds: Any, connect_timeout: int = 10) -> Any:
        """
        Open a connection using the given credentials.

        Args:
            creds: DatabaseCredentials to connect with
            connect_timeout: Seconds to wait for the connection

        Returns:
            An open DB-API connection, which the caller must close
        """

    @abstractmethod
    def password_change_statement(
        self, username: str, new_password: str, user_host: str = "%"
    ) -> str:
        """
        Build the statement that changes this user's password.

        Args:
            username: Account whose password changes
            new_password: The new password
            user_host: Host part of the account identity, where the dialect has
                one (MySQL-family 'user'@'host'); ignored otherwise

        Returns:
            A single SQL statement

        Raises:
            ValidationError: If a value cannot be embedded safely
        """

    def check_connection(self, creds: Any, connect_timeout: int = 10) -> bool:
        """
        Report whether these credentials can authenticate.

        Returns:
            True if a connection was established, False otherwise
        """
        from dbcreds.core.manager import _get_logger

        try:
            conn = self.connect(creds, connect_timeout=connect_timeout)
        except Exception as e:  # noqa: BLE001 -- any driver error means "no"
            _get_logger().debug(f"Connection check failed: {e}")
            return False

        try:
            conn.close()
        except Exception:  # noqa: BLE001 -- already connected, close is best effort
            pass
        return True

    def execute(self, creds: Any, statement: str, connect_timeout: int = 10) -> None:
        """
        Run a single statement, committing if the driver requires it.

        Args:
            creds: Credentials to connect with
            statement: SQL to execute
            connect_timeout: Seconds to wait for the connection
        """
        conn = self.connect(creds, connect_timeout=connect_timeout)
        try:
            cursor = conn.cursor()
            try:
                cursor.execute(statement)
            finally:
                cursor.close()
            # DDL is autocommitted by some drivers and not others.
            try:
                conn.commit()
            except Exception:  # noqa: BLE001 -- autocommit connections have no commit
                pass
        finally:
            conn.close()


class PostgreSQLAdapter(DatabaseAdapter):
    """PostgreSQL, via psycopg2."""

    database_type = DatabaseType.POSTGRESQL
    scheme = "postgresql"
    default_port = 5432

    def connect(self, creds: Any, connect_timeout: int = 10) -> Any:
        import psycopg2  # type: ignore[import-untyped]

        return psycopg2.connect(
            host=creds.host,
            port=creds.port,
            database=creds.database,
            user=creds.username,
            password=creds.password.get_secret_value(),
            connect_timeout=connect_timeout,
        )

    def password_change_statement(
        self, username: str, new_password: str, user_host: str = "%"
    ) -> str:
        """PostgreSQL accounts have no host part, so user_host is ignored."""
        _reject_unsafe(username, "username")
        _reject_unsafe(new_password, "password")
        return f"ALTER USER \"{username}\" WITH PASSWORD '{new_password}'"


class MySQLAdapter(DatabaseAdapter):
    """MySQL, via PyMySQL (falling back to mysqlclient)."""

    database_type = DatabaseType.MYSQL
    scheme = "mysql+pymysql"
    default_port = 3306

    def connect(self, creds: Any, connect_timeout: int = 10) -> Any:
        try:
            import pymysql  # type: ignore[import-untyped]

            return pymysql.connect(
                host=creds.host,
                port=creds.port,
                database=creds.database,
                user=creds.username,
                password=creds.password.get_secret_value(),
                connect_timeout=connect_timeout,
            )
        except ImportError:
            import MySQLdb  # type: ignore[import-untyped]

            return MySQLdb.connect(
                host=creds.host,
                port=creds.port,
                db=creds.database,
                user=creds.username,
                passwd=creds.password.get_secret_value(),
                connect_timeout=connect_timeout,
            )

    def password_change_statement(
        self, username: str, new_password: str, user_host: str = "%"
    ) -> str:
        """MySQL 8 removed PASSWORD(), so ALTER USER is the portable form."""
        _reject_unsafe(username, "username")
        _reject_unsafe(new_password, "password")
        _reject_unsafe(user_host, "user host")
        return (
            f"ALTER USER '{username}'@'{user_host}' "
            f"IDENTIFIED BY '{new_password}'"
        )


class DorisAdapter(MySQLAdapter):
    """
    Apache Doris / Doris.

    Wire-compatible with MySQL, so it reuses the connection logic, but it still
    uses the pre-8.0 SET PASSWORD form rather than ALTER USER.
    """

    database_type = DatabaseType.DORIS
    scheme = "mysql+pymysql"
    default_port = 9030

    def password_change_statement(
        self, username: str, new_password: str, user_host: str = "%"
    ) -> str:
        _reject_unsafe(username, "username")
        _reject_unsafe(new_password, "password")
        _reject_unsafe(user_host, "user host")
        return (
            f"SET PASSWORD FOR {username}@'{user_host}' "
            f"= PASSWORD('{new_password}')"
        )


_ADAPTERS: Dict[DatabaseType, Type[DatabaseAdapter]] = {
    DatabaseType.POSTGRESQL: PostgreSQLAdapter,
    DatabaseType.MYSQL: MySQLAdapter,
    DatabaseType.DORIS: DorisAdapter,
}

# Schemes for types that have no adapter yet, so connection strings still work.
_EXTRA_SCHEMES: Dict[DatabaseType, str] = {
    DatabaseType.ORACLE: "oracle+oracledb",
    DatabaseType.MSSQL: "mssql+pyodbc",
    DatabaseType.SQLITE: "sqlite",
}


def get_adapter(database_type: Optional[DatabaseType]) -> DatabaseAdapter:
    """
    Return the adapter for a database type.

    Args:
        database_type: Type to look up

    Returns:
        An adapter instance

    Raises:
        ValidationError: If no adapter implements this type yet

    Examples:
        >>> get_adapter(DatabaseType.DORIS).default_port
        9030
    """
    adapter_class = _ADAPTERS.get(database_type) if database_type else None
    if adapter_class is None:
        raise ValidationError(
            f"No database adapter for '{getattr(database_type, 'value', database_type)}'. "
            f"Supported: {', '.join(sorted(t.value for t in _ADAPTERS))}"
        )
    return adapter_class()


def scheme_for(database_type: Optional[DatabaseType]) -> str:
    """
    Return the URL scheme for a database type.

    Defaults to PostgreSQL when the type is unknown, preserving the behaviour of
    credentials stored before database_type was recorded.

    Examples:
        >>> scheme_for(DatabaseType.DORIS)
        'mysql+pymysql'
    """
    if database_type is None:
        return "postgresql"
    adapter_class = _ADAPTERS.get(database_type)
    if adapter_class is not None:
        return adapter_class.scheme
    return _EXTRA_SCHEMES.get(database_type, "postgresql")
