# tests/test_cli/test_generate.py
"""Tests for the 'dbcreds generate' command."""

import string

from typer.testing import CliRunner

from dbcreds.cli import app
from dbcreds.core.security import DEFAULT_PASSWORD_LENGTH, URI_SAFE_SYMBOLS

runner = CliRunner()

ALLOWED = set(string.ascii_letters + string.digits + URI_SAFE_SYMBOLS)


class TestGenerateCommand:
    """The generate command must emit a bare, pipeable password."""

    def test_prints_password_of_default_length(self):
        """Output is exactly the password, so it can be piped to pbcopy."""
        result = runner.invoke(app, ["generate"])

        assert result.exit_code == 0
        password = result.stdout.strip()
        assert len(password) == DEFAULT_PASSWORD_LENGTH
        assert set(password) <= ALLOWED

    def test_respects_length_option(self):
        """--length changes the generated length."""
        result = runner.invoke(app, ["generate", "--length", "48"])

        assert result.exit_code == 0
        assert len(result.stdout.strip()) == 48

    def test_short_length_is_rejected(self):
        """Too-short lengths fail loudly instead of producing a weak password."""
        result = runner.invoke(app, ["generate", "--length", "4"])

        assert result.exit_code == 1
        assert "at least" in result.stdout

    def test_no_uri_safe_still_succeeds(self):
        """--no-uri-safe is accepted and still produces the requested length."""
        result = runner.invoke(app, ["generate", "--no-uri-safe", "--length", "40"])

        assert result.exit_code == 0
        assert len(result.stdout.strip()) == 40

    def test_successive_runs_differ(self):
        """Each invocation produces a fresh password."""
        first = runner.invoke(app, ["generate"]).stdout.strip()
        second = runner.invoke(app, ["generate"]).stdout.strip()

        assert first != second

    def test_generate_flag_is_offered_by_add_and_update(self):
        """--generate is wired into both add and update."""
        assert "--generate" in runner.invoke(app, ["add", "--help"]).stdout
        assert "--generate" in runner.invoke(app, ["update", "--help"]).stdout
