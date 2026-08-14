# dbcreds/backends/config.py
"""
JSON configuration file backend.

This backend stores non-sensitive configuration in JSON files and can
be used as a fallback or for storing metadata.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from dbcreds.backends.base import CredentialBackend


class ConfigFileBackend(CredentialBackend):
    """
    Configuration file backend.

    Stores environment configurations and non-sensitive metadata in JSON files.
    This backend should not be used for storing passwords directly.
    """

    # Passwords are deliberately stripped before saving, so this backend can
    # never return one from get_credential(). See CredentialBackend.
    stores_secrets = False

    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize the config file backend.

        Args:
            config_dir: Directory to store configuration files
        """
        self.config_dir = Path(config_dir or os.path.expanduser("~/.dbcreds"))
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.environments_file = self.config_dir / "environments.json"
        self.metadata_file = self.config_dir / "metadata.json"

    def is_available(self) -> bool:
        """Check if we can write to the config directory."""
        try:
            test_file = self.config_dir / ".test"
            test_file.touch()
            test_file.unlink()
            return True
        except Exception as e:
            logger.debug(f"Config directory not writable: {e}")
            return False

    def get_credential(self, key: str) -> Optional[Tuple[str, str, Dict[str, Any]]]:
        """
        Retrieve credential metadata from config file.

        Note: This backend does not store passwords.
        """
        metadata = self._load_metadata()
        if key in metadata:
            data = metadata[key]
            username = data.pop("username", "")
            # Password is not stored in config files
            return (username, "", data)
        return None

    def set_credential(self, key: str, username: str, password: str, metadata: Dict[str, Any]) -> bool:
        """
        Store credential metadata in config file.

        Note: Password is not stored, only metadata.
        """
        all_metadata = self._load_metadata()
        all_metadata[key] = {"username": username, **metadata}
        # Remove password if accidentally included in metadata
        all_metadata[key].pop("password", None)
        return self._save_metadata(all_metadata)

    def delete_credential(self, key: str) -> bool:
        """Delete credential metadata from config file."""
        metadata = self._load_metadata()
        if key in metadata:
            del metadata[key]
            return self._save_metadata(metadata)
        return True

    def load_environments(self) -> List[Dict[str, Any]]:
        """Load environment configurations."""
        if self.environments_file.exists():
            try:
                with open(self.environments_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load environments: {e}")
        return []

    def save_environments(self, environments: List[Dict[str, Any]]) -> bool:
        """Save environment configurations."""
        try:
            with open(self.environments_file, "w") as f:
                json.dump(environments, f, indent=2, default=str)
            return True
        except Exception as e:
            logger.error(f"Failed to save environments: {e}")
            return False

    def _load_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Load metadata from file."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load metadata: {e}")
        return {}

    def _save_metadata(self, metadata: Dict[str, Dict[str, Any]]) -> bool:
        """Save metadata to file."""
        try:
            with open(self.metadata_file, "w") as f:
                json.dump(metadata, f, indent=2, default=str)
            return True
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
            return False
