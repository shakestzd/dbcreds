# dbcreds/backends/environment.py
"""
Environment variable backend for credential storage.

This backend reads credentials from environment variables, useful for
containerized deployments and CI/CD pipelines.
"""

import os
from typing import Any, Dict, Optional, Tuple

from loguru import logger

from dbcreds.backends.base import CredentialBackend


class EnvironmentBackend(CredentialBackend):
    """
    Environment variable credential backend.

    Reads credentials from environment variables using a naming convention.
    Variables should be named as: DBCREDS_{ENV}_{FIELD}

    Example:
        DBCREDS_DEV_HOST=localhost
        DBCREDS_DEV_PORT=5432
        DBCREDS_DEV_USERNAME=myuser
        DBCREDS_DEV_PASSWORD=mypass
    """

    # set_credential() only mutates os.environ for the current process, so the
    # secret is gone once that process exits. This backend is a read path for
    # externally-provided credentials, not durable storage. See
    # CredentialBackend.
    stores_secrets = False

    def is_available(self) -> bool:
        """Environment variables are always available."""
        return True

    def get_credential(self, key: str) -> Optional[Tuple[str, str, Dict[str, Any]]]:
        """Retrieve credential from environment variables."""
        # Extract environment name from key (e.g., "dbcreds:dev" -> "dev")
        if not key.startswith("dbcreds:"):
            return None

        env_name = key.split(":", 1)[1].upper()
        prefix = f"DBCREDS_{env_name}_"

        # Look for environment variables with this prefix
        metadata = {}
        username = None
        password = None

        for var_name, value in os.environ.items():
            if var_name.startswith(prefix):
                field_name = var_name[len(prefix) :].lower()
                if field_name == "username":
                    username = value
                elif field_name == "password":
                    password = value
                else:
                    # Try to convert to appropriate type
                    if field_name == "port":
                        try:
                            metadata[field_name] = int(value)
                        except ValueError:
                            metadata[field_name] = value
                    else:
                        metadata[field_name] = value

        if username and password:
            logger.debug(f"Found credentials in environment for {key}")
            return (username, password, metadata)

        return None

    def set_credential(self, key: str, username: str, password: str, metadata: Dict[str, Any]) -> bool:
        """
        Set credential in environment variables.

        Note: This only affects the current process and its children.
        """
        if not key.startswith("dbcreds:"):
            return False

        env_name = key.split(":", 1)[1].upper()
        prefix = f"DBCREDS_{env_name}_"

        # Set environment variables
        os.environ[f"{prefix}USERNAME"] = username
        os.environ[f"{prefix}PASSWORD"] = password

        for field, value in metadata.items():
            os.environ[f"{prefix}{field.upper()}"] = str(value)

        return True

    def delete_credential(self, key: str) -> bool:
        """Delete credential from environment variables."""
        if not key.startswith("dbcreds:"):
            return False

        env_name = key.split(":", 1)[1].upper()
        prefix = f"DBCREDS_{env_name}_"

        # Remove all variables with this prefix
        vars_to_remove = [var for var in os.environ if var.startswith(prefix)]
        for var in vars_to_remove:
            os.environ.pop(var, None)

        return True