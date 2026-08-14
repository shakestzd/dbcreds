# tests/test_core/test_security.py
"""Tests for security utilities, including password generation."""

import string
from urllib.parse import quote, urlsplit

import pytest

from dbcreds.core.exceptions import ValidationError
from dbcreds.core.security import (
    DEFAULT_PASSWORD_LENGTH,
    EXTRA_SYMBOLS,
    MIN_PASSWORD_LENGTH,
    URI_SAFE_SYMBOLS,
    generate_password,
)

# Enough draws to catch a class that is only occasionally missing.
SAMPLES = 200


class TestGeneratePassword:
    """Test cases for generate_password."""

    def test_default_length(self):
        """Default length matches the documented default."""
        assert len(generate_password()) == DEFAULT_PASSWORD_LENGTH == 32

    @pytest.mark.parametrize("length", [8, 12, 16, 32, 64, 128])
    def test_custom_length(self, length):
        """Requested length is honoured exactly."""
        assert len(generate_password(length)) == length

    @pytest.mark.parametrize("length", [0, 1, 7, -5])
    def test_rejects_too_short(self, length):
        """Lengths below the minimum raise rather than yielding a weak password."""
        with pytest.raises(ValidationError, match="at least"):
            generate_password(length)

    def test_minimum_length_is_accepted(self):
        """The documented minimum is itself valid."""
        assert len(generate_password(MIN_PASSWORD_LENGTH)) == MIN_PASSWORD_LENGTH

    def test_always_contains_every_character_class(self):
        """Every password satisfies the usual complexity policies."""
        for _ in range(SAMPLES):
            password = generate_password(MIN_PASSWORD_LENGTH)
            assert any(c in string.ascii_lowercase for c in password)
            assert any(c in string.ascii_uppercase for c in password)
            assert any(c in string.digits for c in password)
            assert any(c in URI_SAFE_SYMBOLS for c in password)

    def test_uri_safe_alphabet_only(self):
        """URI-safe passwords stay within the unreserved character set."""
        allowed = set(string.ascii_letters + string.digits + URI_SAFE_SYMBOLS)
        for _ in range(SAMPLES):
            assert set(generate_password()) <= allowed

    def test_passwords_are_unique(self):
        """Generation is random, not deterministic."""
        passwords = {generate_password() for _ in range(SAMPLES)}
        assert len(passwords) == SAMPLES

    def test_non_uri_safe_widens_alphabet(self):
        """Opting out of URI safety draws from the wider symbol set."""
        seen = set()
        for _ in range(SAMPLES):
            seen.update(generate_password(64, uri_safe=False))

        assert seen & set(EXTRA_SYMBOLS), "expected at least one extra symbol"
        # Quotes and backslashes stay out regardless -- they break shell quoting.
        assert not seen & set("'\"`\\")

    def test_survives_connection_uri_round_trip(self):
        """
        A generated password must not corrupt the URIs dbcreds emits.

        get_connection_string() builds postgresql://user:password@host:port/db,
        so a password containing '@', ':' or '/' would silently change how the
        URI parses. This is the constraint uri_safe exists to guarantee.
        """
        for _ in range(SAMPLES):
            password = generate_password()
            uri = f"postgresql://svc_user:{password}@db.example.internal:5432/prod"
            parsed = urlsplit(uri)

            assert parsed.password == password
            assert parsed.username == "svc_user"
            assert parsed.hostname == "db.example.internal"
            assert parsed.port == 5432
            assert parsed.path == "/prod"
            # No percent-encoding needed, so the raw and quoted forms agree.
            assert quote(password, safe="") == password
