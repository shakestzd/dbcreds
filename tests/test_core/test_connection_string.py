# tests/test_core/test_connection_string.py
"""Tests for type-aware connection strings."""

from urllib.parse import urlsplit

import pytest

from dbcreds.core.models import DatabaseCredentials, DatabaseType


def creds(database_type=None, password="pass", username="user"):
    return DatabaseCredentials(
        environment="test",
        database_type=database_type,
        host="db.example.internal",
        port=9030,
        database="analytics",
        username=username,
        password=password,
    )


class TestScheme:
    """The scheme used to be hardcoded to postgresql:// for every type."""

    @pytest.mark.parametrize(
        "db_type,expected",
        [
            (DatabaseType.POSTGRESQL, "postgresql"),
            (DatabaseType.MYSQL, "mysql+pymysql"),
            (DatabaseType.DORIS, "mysql+pymysql"),
            (DatabaseType.ORACLE, "oracle+oracledb"),
            (DatabaseType.MSSQL, "mssql+pyodbc"),
        ],
    )
    def test_scheme_follows_database_type(self, db_type, expected):
        assert creds(db_type).get_connection_string().startswith(f"{expected}://")

    def test_unset_type_falls_back_to_postgresql(self):
        """Credentials stored before database_type existed still work."""
        assert creds(None).get_connection_string().startswith("postgresql://")

    def test_explicit_driver_wins(self):
        uri = creds(DatabaseType.DORIS).get_connection_string(driver="mysql+mysqldb")

        assert uri.startswith("mysql+mysqldb://")


class TestComposition:
    def test_full_uri(self):
        uri = creds(DatabaseType.DORIS).get_connection_string()

        assert uri == "mysql+pymysql://user:pass@db.example.internal:9030/analytics"

    def test_password_can_be_omitted(self):
        uri = creds(DatabaseType.DORIS).get_connection_string(include_password=False)

        assert uri == "mysql+pymysql://user@db.example.internal:9030/analytics"
        assert "pass" not in uri


class TestEscaping:
    """
    A password legal in the database can still be illegal in a URI.

    Without encoding, '@' or '/' silently changes which host and database the
    URI points at, rather than failing loudly.
    """

    @pytest.mark.parametrize("password", ["p@ssword", "pa/ss", "pa:ss", "pa?ss", "pa#ss"])
    def test_special_characters_round_trip(self, password):
        uri = creds(DatabaseType.DORIS, password=password).get_connection_string()
        parsed = urlsplit(uri)

        assert parsed.hostname == "db.example.internal"
        assert parsed.port == 9030
        assert parsed.path == "/analytics"

    def test_at_sign_does_not_move_the_host(self):
        uri = creds(DatabaseType.DORIS, password="p@evil.example.com").get_connection_string()

        assert urlsplit(uri).hostname == "db.example.internal"

    def test_username_is_encoded_too(self):
        uri = creds(DatabaseType.DORIS, username="do\\main\\user").get_connection_string()

        assert urlsplit(uri).hostname == "db.example.internal"
