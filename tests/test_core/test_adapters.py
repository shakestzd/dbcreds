# tests/test_core/test_adapters.py
"""Tests for per-dialect database adapters."""

import pytest

from dbcreds.core.adapters import (
    DorisAdapter,
    MySQLAdapter,
    PostgreSQLAdapter,
    get_adapter,
    scheme_for,
)
from dbcreds.core.exceptions import ValidationError
from dbcreds.core.models import DatabaseType


class TestPasswordChangeStatements:
    """Each dialect needs its own statement; they are not interchangeable."""

    def test_doris_uses_set_password(self):
        """
        Doris keeps the pre-8.0 form.

        This is the statement the database administrator supplied, matched
        exactly -- it is known to work against Doris.
        """
        statement = DorisAdapter().password_change_statement("dbuser", "NewPass123")

        assert statement == "SET PASSWORD FOR dbuser@'%' = PASSWORD('NewPass123')"

    def test_mysql_uses_alter_user(self):
        """MySQL 8 removed PASSWORD(), so ALTER USER is the portable form."""
        statement = MySQLAdapter().password_change_statement("app", "NewPass123")

        assert statement == "ALTER USER 'app'@'%' IDENTIFIED BY 'NewPass123'"

    def test_postgresql_has_no_host_part(self):
        """PostgreSQL roles are not host-qualified, so user_host is ignored."""
        statement = PostgreSQLAdapter().password_change_statement(
            "app", "NewPass123", user_host="10.0.0.1"
        )

        assert statement == "ALTER USER \"app\" WITH PASSWORD 'NewPass123'"

    def test_user_host_is_honoured(self):
        """A non-wildcard account identity is respected."""
        statement = DorisAdapter().password_change_statement(
            "dbuser", "NewPass123", user_host="10.0.0.1"
        )

        assert "dbuser@'10.0.0.1'" in statement

    @pytest.mark.parametrize("adapter", [DorisAdapter(), MySQLAdapter(), PostgreSQLAdapter()])
    @pytest.mark.parametrize("bad", ["pass'word", 'pass"word', "pass\\word", "pass`word"])
    def test_rejects_sql_unsafe_passwords(self, adapter, bad):
        """
        Quotes and backslashes are refused rather than escaped.

        These statements take no bind parameters, so a password containing a
        quote could terminate the literal. Refusing beats guessing at a
        per-dialect escaping scheme.
        """
        with pytest.raises(ValidationError, match="quote or backslash"):
            adapter.password_change_statement("app", bad)

    def test_rejects_unsafe_username(self):
        """The same applies to the account name."""
        with pytest.raises(ValidationError):
            DorisAdapter().password_change_statement("ap'p", "GoodPass123")

    def test_rejects_control_characters(self):
        """Newlines would allow a second statement to be appended."""
        with pytest.raises(ValidationError, match="control character"):
            DorisAdapter().password_change_statement("app", "good\npassword")


class TestAdapterLookup:
    """get_adapter and scheme_for."""

    @pytest.mark.parametrize(
        "db_type,expected",
        [
            (DatabaseType.POSTGRESQL, PostgreSQLAdapter),
            (DatabaseType.MYSQL, MySQLAdapter),
            (DatabaseType.DORIS, DorisAdapter),
        ],
    )
    def test_returns_matching_adapter(self, db_type, expected):
        assert isinstance(get_adapter(db_type), expected)

    def test_unsupported_type_names_what_is_supported(self):
        """The error should tell you which types do work."""
        with pytest.raises(ValidationError, match="No database adapter"):
            get_adapter(DatabaseType.ORACLE)

    def test_doris_defaults_to_9030(self):
        """Doris' query port, not MySQL's 3306."""
        assert get_adapter(DatabaseType.DORIS).default_port == 9030

    @pytest.mark.parametrize(
        "db_type,expected",
        [
            (DatabaseType.POSTGRESQL, "postgresql"),
            (DatabaseType.MYSQL, "mysql+pymysql"),
            (DatabaseType.DORIS, "mysql+pymysql"),
            (DatabaseType.ORACLE, "oracle+oracledb"),
            (DatabaseType.MSSQL, "mssql+pyodbc"),
            (None, "postgresql"),
        ],
    )
    def test_scheme_for(self, db_type, expected):
        """Unknown/None falls back to PostgreSQL, matching legacy records."""
        assert scheme_for(db_type) == expected
