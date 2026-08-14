# tests/conftest.py
"""Shared test fixtures."""

import tempfile

import pytest
from fastapi.testclient import TestClient

from dbcreds.core.manager import CredentialManager
from dbcreds.web.main import app


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
