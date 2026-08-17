# tests/conftest.py
"""Shared test fixtures."""

import tempfile

import pytest
from fastapi.testclient import TestClient

from dbcreds.core.manager import CredentialManager
from dbcreds.web.main import app


@pytest.fixture(autouse=True)
def isolate_dbcreds_config(tmp_path, monkeypatch):
    """
    Point dbcreds' settings file at a temp directory for every test.

    Without this, tests read whatever the developer has configured on their own
    machine, so a real `dbcreds config set` makes assertions about defaults fail.
    """
    monkeypatch.setattr(
        "dbcreds.core.config._DEFAULT_CONFIG_DIR", str(tmp_path / "dbcreds")
    )
    for name in ("DBCREDS_OP_VAULT", "DBCREDS_OP_ITEM_TITLE", "DBCREDS_OP_ACCOUNT"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def reset_manager_singleton():
    """
    Reset the CredentialManager singleton around every test.

    CredentialManager caches a single instance, so without this the first test
    to build one pins its config_dir and leaks its environments into every
    later test.
    """
    CredentialManager._instance = None
    yield
    CredentialManager._instance = None


@pytest.fixture
def temp_config_dir():
    """Create a temporary configuration directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def manager(temp_config_dir):
    """Create a credential manager with temporary storage."""
    return CredentialManager(config_dir=temp_config_dir)


@pytest.fixture
def test_client():
    """Create a test client for the web interface."""
    return TestClient(app)


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
