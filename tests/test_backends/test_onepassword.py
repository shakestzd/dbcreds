# tests/test_backends/test_onepassword.py
"""Tests for the 1Password backend, with a fake `op` CLI."""

import json
import subprocess

import pytest

from dbcreds.backends.onepassword import OnePasswordBackend

SECRET = "S3cret-value_do.not~leak"


class FakeOp:
    """
    Stand-in for the op CLI.

    Records every invocation so tests can assert on what was passed as command
    arguments versus what was piped in.
    """

    def __init__(self, items=None, account_configured=True):
        self.items = items or {}
        self.account_configured = account_configured
        self.calls = []

    def __call__(self, cmd, input=None, **kwargs):
        self.calls.append({"cmd": cmd, "input": input})
        args = cmd[1:]  # drop 'op'

        def done(code=0, out="", err=""):
            return subprocess.CompletedProcess(cmd, code, out, err)

        if args[:2] == ["account", "list"]:
            return done(0, "example.1password.com\n") if self.account_configured else done(1)

        if args[:2] == ["item", "get"]:
            title = args[2]
            if title not in self.items:
                return done(1, err="item not found")
            return done(0, json.dumps(self.items[title]))

        if args[:2] == ["item", "create"]:
            title = cmd[cmd.index("--title") + 1]
            self.items[title] = json.loads(input)
            return done(0)

        if args[:2] == ["item", "edit"]:
            self.items[args[2]] = json.loads(input)
            return done(0)

        if args[:2] == ["item", "delete"]:
            return done(0) if self.items.pop(args[2], None) is not None else done(1)

        return done(1, err=f"unexpected: {args}")

    def all_command_args(self):
        """Every command argument ever passed, flattened."""
        return [arg for call in self.calls for arg in call["cmd"]]


def item(fields):
    return {"fields": fields}


@pytest.fixture
def fake_op(monkeypatch):
    fake = FakeOp()
    monkeypatch.setattr("dbcreds.backends.onepassword.subprocess.run", fake)
    return fake


class TestItemTitle:
    """The title template is how existing items get reused."""

    def test_default_template_is_the_environment_name(self):
        assert OnePasswordBackend().item_title("dbcreds:prod") == "prod"

    @pytest.mark.parametrize("env", ["prod", "warehouse-prod", "analytics_stage"])
    def test_default_title_is_valid_in_a_secret_reference(self, env):
        """
        Titles must be addressable as op://vault/item/field.

        ':' and '/' are structural in a secret reference, so a title containing
        one cannot be read with `op read` or `op run` -- which is how everything
        other than dbcreds itself gets at the secret. A 'dbcreds:{env}' default
        looks tidy and breaks exactly that.
        """
        title = OnePasswordBackend().item_title(f"dbcreds:{env}")

        assert ":" not in title
        assert "/" not in title

    def test_warns_when_template_breaks_secret_references(self, caplog):
        """A custom template that is unusable with op read should say so."""
        backend = OnePasswordBackend(title_template="dbcreds:{env}")

        title = backend.item_title("dbcreds:prod")

        assert title == "dbcreds:prod"  # honoured, but flagged

    def test_custom_template(self):
        backend = OnePasswordBackend(title_template="Doris {env}")

        assert backend.item_title("dbcreds:prod") == "Doris prod"
        assert backend.item_title("dbcreds:stage") == "Doris stage"

    def test_template_from_environment(self, monkeypatch):
        monkeypatch.setenv("DBCREDS_OP_ITEM_TITLE", "Doris {env}")

        assert OnePasswordBackend().item_title("dbcreds:prod") == "Doris prod"


class TestAvailability:
    def test_available_when_account_configured(self, fake_op):
        assert OnePasswordBackend().is_available() is True

    def test_unavailable_without_account(self, fake_op):
        fake_op.account_configured = False

        assert OnePasswordBackend().is_available() is False

    def test_unavailable_when_op_missing(self, monkeypatch):
        def missing(*args, **kwargs):
            raise FileNotFoundError("op")

        monkeypatch.setattr("dbcreds.backends.onepassword.subprocess.run", missing)

        assert OnePasswordBackend().is_available() is False

    def test_availability_does_not_require_a_session(self, fake_op):
        """
        Availability must not trigger an unlock prompt.

        Backends are enumerated on nearly every command, so checking for an
        unlocked session here would prompt constantly.
        """
        OnePasswordBackend().is_available()

        assert all(call["cmd"][1:3] != ["vault", "list"] for call in fake_op.calls)
        assert all("read" not in call["cmd"] for call in fake_op.calls)


class TestGetCredential:
    def test_maps_native_fields(self, fake_op):
        fake_op.items["prod"] = item([
            {"id": "username", "label": "username", "value": "dbuser"},
            {"id": "password", "label": "password", "value": SECRET},
            {"id": "hostname", "label": "server", "value": "db.example.internal"},
            {"id": "port", "label": "port", "value": "9030"},
            {"id": "database", "label": "database", "value": "analytics"},
        ])

        username, password, metadata = OnePasswordBackend().get_credential("dbcreds:prod")

        assert username == "dbuser"
        assert password == SECRET
        assert metadata["host"] == "db.example.internal"
        assert metadata["port"] == 9030          # coerced to int
        assert metadata["database"] == "analytics"

    def test_merges_sidecar_metadata(self, fake_op):
        """Fields with no native home ride along as JSON."""
        fake_op.items["prod"] = item([
            {"id": "username", "label": "username", "value": "dbuser"},
            {"id": "password", "label": "password", "value": SECRET},
            {"id": "x", "label": "dbcreds_metadata",
             "value": json.dumps({"password_expires_at": "2026-11-12T00:00:00Z"})},
        ])

        _, _, metadata = OnePasswordBackend().get_credential("dbcreds:prod")

        assert metadata["password_expires_at"] == "2026-11-12T00:00:00Z"

    def test_missing_item_returns_none(self, fake_op):
        assert OnePasswordBackend().get_credential("dbcreds:nope") is None

    def test_item_without_password_returns_none(self, fake_op):
        """A metadata-only item is not a usable credential."""
        fake_op.items["prod"] = item([
            {"id": "username", "label": "username", "value": "dbuser"},
        ])

        assert OnePasswordBackend().get_credential("dbcreds:prod") is None

    def test_malformed_sidecar_is_ignored(self, fake_op):
        """Bad JSON in the sidecar must not lose the credential itself."""
        fake_op.items["prod"] = item([
            {"id": "username", "label": "username", "value": "dbuser"},
            {"id": "password", "label": "password", "value": SECRET},
            {"id": "x", "label": "dbcreds_metadata", "value": "{not json"},
        ])

        username, password, _ = OnePasswordBackend().get_credential("dbcreds:prod")

        assert (username, password) == ("dbuser", SECRET)


class TestSetCredential:
    METADATA = {"host": "db.example.internal", "port": 9030, "database": "analytics",
                "password_expires_at": "2026-11-12T00:00:00Z"}

    def test_creates_item_when_absent(self, fake_op):
        assert OnePasswordBackend().set_credential(
            "dbcreds:prod", "dbuser", SECRET, dict(self.METADATA)
        ) is True

        stored = fake_op.items["prod"]
        values = {f["label"]: f["value"] for f in stored["fields"]}
        assert values["username"] == "dbuser"
        assert values["password"] == SECRET
        assert values["server"] == "db.example.internal"
        assert values["port"] == "9030"
        assert values["database"] == "analytics"

    def test_leftover_metadata_goes_to_sidecar(self, fake_op):
        OnePasswordBackend().set_credential(
            "dbcreds:prod", "dbuser", SECRET, dict(self.METADATA)
        )

        values = {f["label"]: f["value"] for f in fake_op.items["prod"]["fields"]}
        assert json.loads(values["dbcreds_metadata"])["password_expires_at"]

    def test_round_trips(self, fake_op):
        backend = OnePasswordBackend()
        backend.set_credential("dbcreds:prod", "dbuser", SECRET, dict(self.METADATA))

        username, password, metadata = backend.get_credential("dbcreds:prod")

        assert username == "dbuser"
        assert password == SECRET
        assert metadata["host"] == self.METADATA["host"]
        assert metadata["port"] == 9030
        assert metadata["password_expires_at"] == self.METADATA["password_expires_at"]

    def test_database_type_round_trips(self, fake_op):
        """
        The dialect must survive a write/read cycle.

        Without it a stored credential cannot say which scheme its connection
        string needs, and everything silently falls back to PostgreSQL.
        """
        from dbcreds.core.models import DatabaseType

        backend = OnePasswordBackend()
        backend.set_credential(
            "dbcreds:prod", "dbuser", SECRET,
            {"host": "h", "port": 9030, "database": "analytics",
             "database_type": DatabaseType.DORIS},
        )

        fields = {f["label"]: f for f in fake_op.items["prod"]["fields"]}
        # Written as the item's native MENU field, not buried in the sidecar.
        assert fields["type"]["value"] == "doris"
        assert fields["type"]["type"] == "MENU"
        assert fields["type"]["id"] == "database_type"
        assert "dbcreds_metadata" not in fields

        _, _, metadata = backend.get_credential("dbcreds:prod")
        assert metadata["database_type"] == "doris"

    def test_server_field_uses_hostname_id(self, fake_op):
        """1Password's database category calls the field 'hostname', not 'server'."""
        OnePasswordBackend().set_credential(
            "dbcreds:prod", "dbuser", SECRET, {"host": "db.example.internal"}
        )

        fields = {f["label"]: f for f in fake_op.items["prod"]["fields"]}
        assert fields["server"]["id"] == "hostname"

    def test_updates_existing_item_preserving_other_fields(self, fake_op):
        """A partial update must not drop fields dbcreds does not manage."""
        fake_op.items["prod"] = item([
            {"id": "username", "label": "username", "value": "dbuser"},
            {"id": "password", "label": "password", "value": "old"},
            {"id": "notesPlain", "label": "notesPlain", "value": "hand-written note"},
        ])

        OnePasswordBackend().set_credential(
            "dbcreds:prod", "dbuser", "new-secret", {"host": "h", "port": 1, "database": "d"}
        )

        values = {f["label"]: f["value"] for f in fake_op.items["prod"]["fields"]}
        assert values["password"] == "new-secret"
        assert values["notesPlain"] == "hand-written note"

    def test_password_never_passed_as_a_command_argument(self, fake_op):
        """
        The secret must travel over stdin only.

        Command arguments are visible in `ps` and in shell history, which is why
        1Password's own CLI documentation recommends a piped template.
        """
        OnePasswordBackend().set_credential(
            "dbcreds:prod", "dbuser", SECRET, dict(self.METADATA)
        )

        assert SECRET not in fake_op.all_command_args()
        assert any(call["input"] and SECRET in call["input"] for call in fake_op.calls)


class TestDeleteCredential:
    def test_deletes(self, fake_op):
        fake_op.items["prod"] = item([])

        assert OnePasswordBackend().delete_credential("dbcreds:prod") is True
        assert "prod" not in fake_op.items

    def test_missing_item_is_false(self, fake_op):
        assert OnePasswordBackend().delete_credential("dbcreds:nope") is False


def test_declares_that_it_stores_secrets():
    """It must count toward set_credentials' success check."""
    assert OnePasswordBackend.stores_secrets is True


class TestVaultAndAccount:
    def test_vault_is_passed_through(self, fake_op):
        OnePasswordBackend(vault="MyVault").get_credential("dbcreds:prod")

        assert ["--vault", "MyVault"] == [
            a for a in fake_op.calls[0]["cmd"] if a in ("--vault", "MyVault")
        ]

    def test_no_vault_flag_when_unset(self, fake_op):
        OnePasswordBackend().get_credential("dbcreds:prod")

        assert "--vault" not in fake_op.calls[0]["cmd"]

    def test_account_is_passed_through(self, fake_op):
        OnePasswordBackend(account="example").get_credential("dbcreds:prod")

        assert fake_op.calls[0]["cmd"][:3] == ["op", "--account", "example"]
