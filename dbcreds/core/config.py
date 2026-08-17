# dbcreds/core/config.py
"""
Persisted settings for dbcreds itself.

Backends need configuration that is a property of the machine, not of the code:
which 1Password vault to look in, how item titles are shaped, which account to
use. Hard-coding any of that would make the tool specific to one installation,
and leaving it to environment variables alone means it is lost every new shell.

So it lives in a JSON file dbcreds owns, next to the environment registry, and is
managed through `dbcreds config`.

Resolution order, highest first:

1. an explicit argument passed in code
2. the setting's environment variable, for a one-shell override
3. this config file
4. the caller's default

Nothing secret belongs here. Passwords live in a credential store; this file
holds only pointers, and is written with owner-only permissions regardless.
"""

import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, Optional

CONFIG_FILENAME = "config.json"

_DEFAULT_CONFIG_DIR = "~/.dbcreds"


def config_path(config_dir: Optional[str] = None) -> Path:
    """
    Return the path of the config file.

    Args:
        config_dir: Configuration directory; defaults to ~/.dbcreds

    Returns:
        Path to config.json, which may not exist yet
    """
    base = Path(os.path.expanduser(config_dir or _DEFAULT_CONFIG_DIR))
    return base / CONFIG_FILENAME


def load_config(config_dir: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Read the config file.

    A missing or unreadable file is not an error: dbcreds works entirely without
    one, so this returns an empty mapping rather than failing a command that only
    happened to consult a setting.

    Args:
        config_dir: Configuration directory; defaults to ~/.dbcreds

    Returns:
        Nested mapping of section -> key -> value

    Examples:
        >>> load_config()  # doctest: +SKIP
        {'onepassword': {'vault': 'MyVault'}}
    """
    path = config_path(config_dir)
    if not path.exists():
        return {}

    try:
        with open(path, "r") as handle:
            loaded = json.load(handle)
    except (OSError, json.JSONDecodeError):
        from dbcreds.core.manager import _get_logger

        _get_logger().warning(f"Ignoring unreadable config file: {path}")
        return {}

    return loaded if isinstance(loaded, dict) else {}


def save_config(
    config: Dict[str, Dict[str, Any]], config_dir: Optional[str] = None
) -> None:
    """
    Write the config file with owner-only permissions.

    Args:
        config: Nested mapping of section -> key -> value
        config_dir: Configuration directory; defaults to ~/.dbcreds
    """
    path = config_path(config_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as handle:
        json.dump(config, handle, indent=2, sort_keys=True)
        handle.write("\n")

    # Pointers rather than secrets, but there is no reason for anyone else to
    # read which vaults and accounts this machine uses.
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def get_setting(
    section: str,
    key: str,
    *,
    env_var: Optional[str] = None,
    default: Any = None,
    config_dir: Optional[str] = None,
) -> Any:
    """
    Resolve one setting.

    Args:
        section: Section name, e.g. 'onepassword'
        key: Setting name within the section, e.g. 'vault'
        env_var: Environment variable that overrides the file, if any
        default: Returned when nothing else supplies a value
        config_dir: Configuration directory; defaults to ~/.dbcreds

    Returns:
        The resolved value

    Examples:
        >>> get_setting("onepassword", "vault", env_var="DBCREDS_OP_VAULT")  # doctest: +SKIP
        'MyVault'
    """
    if env_var:
        from_env = os.environ.get(env_var)
        if from_env:
            return from_env

    from_file = load_config(config_dir).get(section, {})
    if isinstance(from_file, dict) and from_file.get(key) not in (None, ""):
        return from_file[key]

    return default


def set_setting(
    section: str, key: str, value: Any, config_dir: Optional[str] = None
) -> None:
    """
    Write one setting, creating the section and file as needed.

    Args:
        section: Section name, e.g. 'onepassword'
        key: Setting name within the section
        value: Value to store
        config_dir: Configuration directory; defaults to ~/.dbcreds
    """
    config = load_config(config_dir)
    config.setdefault(section, {})[key] = value
    save_config(config, config_dir)


def unset_setting(section: str, key: str, config_dir: Optional[str] = None) -> bool:
    """
    Remove one setting.

    Args:
        section: Section name
        key: Setting name within the section
        config_dir: Configuration directory; defaults to ~/.dbcreds

    Returns:
        True if the setting existed and was removed
    """
    config = load_config(config_dir)
    if key not in config.get(section, {}):
        return False

    del config[section][key]
    if not config[section]:
        del config[section]
    save_config(config, config_dir)
    return True
