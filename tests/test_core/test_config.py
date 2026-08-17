# tests/test_core/test_config.py
"""Tests for dbcreds' own settings file."""

import json
import os
import stat

import pytest

from dbcreds.core.config import (
    config_path,
    get_setting,
    load_config,
    save_config,
    set_setting,
    unset_setting,
)


class TestResolutionOrder:
    """
    A setting can come from four places, and the order matters.

    Explicit code wins, then the environment for a one-shell override, then the
    file dbcreds manages, then the caller's default.
    """

    def test_file_is_used_when_no_environment_variable(self, temp_config_dir):
        set_setting("onepassword", "vault", "FromFile", temp_config_dir)

        assert (
            get_setting("onepassword", "vault", env_var="DBCREDS_OP_VAULT",
                        config_dir=temp_config_dir)
            == "FromFile"
        )

    def test_environment_overrides_the_file(self, temp_config_dir, monkeypatch):
        set_setting("onepassword", "vault", "FromFile", temp_config_dir)
        monkeypatch.setenv("DBCREDS_OP_VAULT", "FromEnv")

        assert (
            get_setting("onepassword", "vault", env_var="DBCREDS_OP_VAULT",
                        config_dir=temp_config_dir)
            == "FromEnv"
        )

    def test_default_when_nothing_is_set(self, temp_config_dir):
        assert (
            get_setting("onepassword", "vault", default="Fallback",
                        config_dir=temp_config_dir)
            == "Fallback"
        )

    def test_empty_environment_variable_does_not_win(self, temp_config_dir, monkeypatch):
        """An exported-but-empty variable is not a value."""
        set_setting("onepassword", "vault", "FromFile", temp_config_dir)
        monkeypatch.setenv("DBCREDS_OP_VAULT", "")

        assert (
            get_setting("onepassword", "vault", env_var="DBCREDS_OP_VAULT",
                        config_dir=temp_config_dir)
            == "FromFile"
        )


class TestPersistence:
    def test_round_trips(self, temp_config_dir):
        set_setting("onepassword", "vault", "MyVault", temp_config_dir)
        set_setting("onepassword", "item_title", "{env}", temp_config_dir)

        assert load_config(temp_config_dir) == {
            "onepassword": {"vault": "MyVault", "item_title": "{env}"}
        }

    def test_missing_file_is_not_an_error(self, temp_config_dir):
        """dbcreds works with no config at all, so absence must be silent."""
        assert load_config(temp_config_dir) == {}

    def test_unreadable_file_is_ignored(self, temp_config_dir):
        """Malformed JSON must not break every command that reads a setting."""
        path = config_path(temp_config_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json")

        assert load_config(temp_config_dir) == {}

    def test_written_owner_only(self, temp_config_dir):
        """Pointers, not secrets -- but still nobody else's business."""
        set_setting("onepassword", "vault", "MyVault", temp_config_dir)

        mode = os.stat(config_path(temp_config_dir)).st_mode
        assert not mode & stat.S_IRGRP
        assert not mode & stat.S_IROTH

    def test_unset_removes_the_key_and_empty_section(self, temp_config_dir):
        set_setting("onepassword", "vault", "MyVault", temp_config_dir)

        assert unset_setting("onepassword", "vault", temp_config_dir) is True
        assert load_config(temp_config_dir) == {}

    def test_unset_reports_when_absent(self, temp_config_dir):
        assert unset_setting("onepassword", "vault", temp_config_dir) is False

    def test_save_creates_the_directory(self, tmp_path):
        target = str(tmp_path / "does-not-exist-yet")
        save_config({"onepassword": {"vault": "MyVault"}}, target)

        assert json.loads(config_path(target).read_text()) == {
            "onepassword": {"vault": "MyVault"}
        }


class TestBackendUsesConfig:
    """The 1Password backend must read settings rather than hard-code them."""

    def test_vault_comes_from_the_config_file(self, temp_config_dir, monkeypatch):
        from dbcreds.backends.onepassword import OnePasswordBackend

        set_setting("onepassword", "vault", "ConfiguredVault", temp_config_dir)
        # The backend consults the default config dir, so point that at ours.
        monkeypatch.setattr(
            "dbcreds.core.config._DEFAULT_CONFIG_DIR", temp_config_dir
        )
        monkeypatch.delenv("DBCREDS_OP_VAULT", raising=False)

        assert OnePasswordBackend().vault == "ConfiguredVault"

    def test_explicit_argument_beats_configuration(self, temp_config_dir, monkeypatch):
        from dbcreds.backends.onepassword import OnePasswordBackend

        set_setting("onepassword", "vault", "ConfiguredVault", temp_config_dir)
        monkeypatch.setattr(
            "dbcreds.core.config._DEFAULT_CONFIG_DIR", temp_config_dir
        )

        assert OnePasswordBackend(vault="Explicit").vault == "Explicit"

    def test_title_template_falls_back_to_the_default(self, temp_config_dir, monkeypatch):
        from dbcreds.backends.onepassword import OnePasswordBackend

        monkeypatch.setattr(
            "dbcreds.core.config._DEFAULT_CONFIG_DIR", temp_config_dir
        )
        monkeypatch.delenv("DBCREDS_OP_ITEM_TITLE", raising=False)

        assert OnePasswordBackend().item_title("dbcreds:prod") == "prod"


def test_no_installation_specific_defaults_in_the_source():
    """
    dbcreds is open source and must not carry one installation's names.

    A vault name, account, or hostname belonging to whoever wrote the code is
    configuration, and configuration lives in the config file -- not in a default,
    a docstring example, or a test fixture.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "dbcreds"
    sources = "\n".join(
        path.read_text() for path in root.rglob("*.py")
    )

    for name in ("MyVault", "example-org", "example-db", "example-schema"):
        assert name not in sources, f"{name!r} is installation-specific"
