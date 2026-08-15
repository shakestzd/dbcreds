# dbcreds/backends/onepassword.py
"""
1Password backend, via the `op` CLI.

Keeps 1Password as the system of record for the secret itself: nothing is
copied into the local keyring, so there is only ever one place to rotate,
revoke, or share from.

Secrets are never passed as process arguments. Items are written by piping a
JSON template to `op` on stdin, which is also what 1Password's own CLI help
recommends for sensitive values.

Configuration:
    DBCREDS_OP_VAULT       Vault to use (default: op's own default vault)
    DBCREDS_OP_ITEM_TITLE  Item title template (default: 'dbcreds:{env}')
    DBCREDS_OP_ACCOUNT     Account shorthand, for multi-account setups
"""

import json
import os
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from dbcreds.backends.base import CredentialBackend

# Built-in fields of 1Password's "database" category, mapped to the credential
# fields dbcreds cares about. Keeping these native means the item stays useful
# in the 1Password UI rather than being an opaque blob.
_FIELD_TO_META = {
    "server": "host",
    "port": "port",
    "database": "database",
    "type": "database_type",
}

# Writing needs the item's field ids and types, which do not follow from the
# labels: the server field is id 'hostname', and type is a MENU.
_META_TO_FIELD = {
    "host": ("hostname", "server", "STRING"),
    "port": ("port", "port", "STRING"),
    "database": ("database", "database", "STRING"),
    "database_type": ("database_type", "type", "MENU"),
}

# Everything else dbcreds tracks (expiry timestamps, options) has no native
# home in that category, so it rides along as JSON in one custom field. A
# dedicated field rather than the notes, so user-written notes are never
# clobbered.
_METADATA_FIELD = "dbcreds_metadata"

_DEFAULT_TITLE_TEMPLATE = "dbcreds:{env}"


class OnePasswordBackend(CredentialBackend):
    """
    Store credentials as 1Password Database items through the `op` CLI.

    Examples:
        >>> backend = OnePasswordBackend(vault="MyVault")
        >>> backend.is_available()
        True
    """

    stores_secrets = True

    def __init__(
        self,
        vault: Optional[str] = None,
        title_template: Optional[str] = None,
        account: Optional[str] = None,
        timeout: int = 60,
    ):
        """
        Initialize the backend.

        Args:
            vault: Vault name; defaults to DBCREDS_OP_VAULT, else op's default
            title_template: Item title with an '{env}' placeholder
            account: Account shorthand for multi-account setups
            timeout: Seconds to allow each op invocation, which may prompt for
                biometric or password unlock
        """
        self.vault = vault or os.environ.get("DBCREDS_OP_VAULT")
        self.title_template = (
            title_template
            or os.environ.get("DBCREDS_OP_ITEM_TITLE")
            or _DEFAULT_TITLE_TEMPLATE
        )
        self.account = account or os.environ.get("DBCREDS_OP_ACCOUNT")
        self.timeout = timeout

    # -- helpers ---------------------------------------------------------

    def _base_command(self) -> List[str]:
        command = ["op"]
        if self.account:
            command += ["--account", self.account]
        return command

    def _vault_args(self) -> List[str]:
        return ["--vault", self.vault] if self.vault else []

    def _run(
        self, args: List[str], stdin: Optional[str] = None
    ) -> subprocess.CompletedProcess:
        """Run an op command. Secrets go through stdin, never through args."""
        return subprocess.run(
            self._base_command() + args,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )

    def item_title(self, key: str) -> str:
        """
        Map a dbcreds key to a 1Password item title.

        Args:
            key: Credential key, e.g. 'dbcreds:prod'

        Returns:
            Item title, e.g. 'dbcreds:prod' or 'Doris prod'

        Examples:
            >>> OnePasswordBackend(title_template="Doris {env}").item_title("dbcreds:prod")
            'Doris prod'
        """
        environment = key.split(":", 1)[1] if ":" in key else key
        return self.title_template.format(env=environment)

    # -- CredentialBackend ------------------------------------------------

    def is_available(self) -> bool:
        """
        Check that op is installed and an account is configured.

        Deliberately does not verify an unlocked session: that would prompt for
        authentication every time any backend list is built. A locked session
        surfaces on first real use instead.
        """
        try:
            result = self._run(["account", "list"])
            return result.returncode == 0 and bool(result.stdout.strip())
        except (OSError, subprocess.SubprocessError) as e:
            logger.debug(f"1Password CLI not available: {e}")
            return False

    def get_credential(self, key: str) -> Optional[Tuple[str, str, Dict[str, Any]]]:
        """Read a credential from 1Password."""
        title = self.item_title(key)
        result = self._run(
            ["item", "get", title, *self._vault_args(), "--format", "json"]
        )
        if result.returncode != 0:
            logger.debug(f"1Password item '{title}' not readable: {result.stderr.strip()}")
            return None

        try:
            item = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Could not parse 1Password item '{title}': {e}")
            return None

        username = ""
        password = ""
        metadata: Dict[str, Any] = {}

        for field in item.get("fields", []):
            label = field.get("label") or field.get("id")
            value = field.get("value")
            if value in (None, ""):
                continue

            if label == "username":
                username = value
            elif label == "password":
                password = value
            elif label == _METADATA_FIELD:
                try:
                    metadata.update(json.loads(value))
                except json.JSONDecodeError:
                    logger.warning(f"Ignoring malformed {_METADATA_FIELD} on '{title}'")
            elif label in _FIELD_TO_META:
                metadata[_FIELD_TO_META[label]] = value

        if "port" in metadata:
            try:
                metadata["port"] = int(metadata["port"])
            except (TypeError, ValueError):
                metadata.pop("port")

        if not password:
            logger.debug(f"1Password item '{title}' has no password")
            return None

        return (username, password, metadata)

    def set_credential(
        self, key: str, username: str, password: str, metadata: Dict[str, Any]
    ) -> bool:
        """Create or update the item, preserving fields dbcreds does not own."""
        title = self.item_title(key)
        try:
            fields = self._build_fields(username, password, metadata)
        except (TypeError, ValueError) as e:
            logger.error(f"Could not build 1Password template for '{title}': {e}")
            return False

        existing = self._run(["item", "get", title, *self._vault_args(), "--format", "json"])
        if existing.returncode == 0:
            return self._update(title, existing.stdout, fields)
        return self._create(title, fields)

    def delete_credential(self, key: str) -> bool:
        """Delete the item."""
        title = self.item_title(key)
        result = self._run(["item", "delete", title, *self._vault_args()])
        if result.returncode != 0:
            logger.debug(f"Could not delete '{title}': {result.stderr.strip()}")
            return False
        return True

    # -- item construction -------------------------------------------------

    def _build_fields(
        self, username: str, password: str, metadata: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Split metadata between native fields and the JSON sidecar field."""
        native: List[Dict[str, Any]] = [
            {"id": "username", "type": "STRING", "label": "username", "value": username},
            {"id": "password", "type": "CONCEALED", "label": "password", "value": password},
        ]

        leftovers = dict(metadata)
        for meta_key, (field_id, label, field_type) in _META_TO_FIELD.items():
            if leftovers.get(meta_key) in (None, ""):
                leftovers.pop(meta_key, None)
                continue
            value = leftovers.pop(meta_key)
            # Enums serialise to their value, not 'DatabaseType.DORIS'.
            native.append(
                {
                    "id": field_id,
                    "type": field_type,
                    "label": label,
                    "value": str(getattr(value, "value", value)),
                }
            )

        if leftovers:
            native.append(
                {
                    "id": _METADATA_FIELD,
                    "type": "STRING",
                    "label": _METADATA_FIELD,
                    "value": json.dumps(leftovers, default=str, sort_keys=True),
                }
            )

        return native

    def _create(self, title: str, fields: List[Dict[str, Any]]) -> bool:
        """Create a new Database item from a piped template."""
        template = json.dumps({"fields": fields})
        # No --template flag: op reads the template from stdin when piped, and
        # passing both is an error.
        result = self._run(
            ["item", "create", "--category", "database", "--title", title, *self._vault_args()],
            stdin=template,
        )
        if result.returncode != 0:
            logger.error(f"Could not create 1Password item '{title}': {result.stderr.strip()}")
            return False
        return True

    def _update(self, title: str, existing_json: str, fields: List[Dict[str, Any]]) -> bool:
        """
        Update an existing item.

        The whole item is round-tripped rather than sending only the changed
        fields: a partial template drops everything it omits.
        """
        try:
            item = json.loads(existing_json)
        except json.JSONDecodeError as e:
            logger.error(f"Could not parse existing item '{title}': {e}")
            return False

        by_label = {f.get("label") or f.get("id"): f for f in item.get("fields", [])}
        for field in fields:
            label = field["label"]
            if label in by_label:
                by_label[label]["value"] = field["value"]
            else:
                item.setdefault("fields", []).append(field)

        result = self._run(["item", "edit", title, *self._vault_args()], stdin=json.dumps(item))
        if result.returncode != 0:
            logger.error(f"Could not update 1Password item '{title}': {result.stderr.strip()}")
            return False
        return True
