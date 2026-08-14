# dbcreds/core/security.py
"""Security utilities for dbcreds."""

import re
import secrets
import string
from typing import Any, Dict

from dbcreds.core.exceptions import ValidationError

DEFAULT_PASSWORD_LENGTH = 32
MIN_PASSWORD_LENGTH = 8

# RFC 3986 "unreserved" punctuation. These need no percent-encoding anywhere in
# a URI, so a password drawn from this set can never corrupt the connection
# strings dbcreds emits (postgresql://user:password@host:port/database).
URI_SAFE_SYMBOLS = "-._~"

# Additional punctuation for callers who explicitly opt out of URI safety.
# Quotes, backticks and backslashes stay out regardless -- they turn passwords
# into a shell-quoting problem wherever they are pasted.
EXTRA_SYMBOLS = "!#$%&()*+,:;<=>?@[]^{|}"


def generate_password(
    length: int = DEFAULT_PASSWORD_LENGTH, uri_safe: bool = True
) -> str:
    """
    Generate a cryptographically secure random password.

    The password always contains at least one lowercase letter, one uppercase
    letter, one digit and one symbol, so it satisfies the usual database
    password-complexity policies.

    Args:
        length: Password length (minimum 8, enough for one of each class)
        uri_safe: Restrict symbols to URI-unreserved characters, so the password
            survives being embedded in a connection string. Disabling this
            widens the alphabet but the result may need percent-encoding.

    Returns:
        The generated password

    Raises:
        ValidationError: If length is below MIN_PASSWORD_LENGTH

    Examples:
        >>> password = generate_password()
        >>> len(password)
        32
        >>> generate_password(length=16, uri_safe=False)  # doctest: +SKIP
        'x7#Kq2$mV9pLr4Tz'
    """
    if length < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password length must be at least {MIN_PASSWORD_LENGTH} characters"
        )

    symbols = URI_SAFE_SYMBOLS if uri_safe else URI_SAFE_SYMBOLS + EXTRA_SYMBOLS
    classes = (
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        symbols,
    )
    alphabet = "".join(classes)

    # Rejection sampling keeps every position uniformly drawn from the full
    # alphabet; placing one character per class and shuffling would not.
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(char in char_class for char in password) for char_class in classes):
            return password


def sanitize_environment_name(name: str) -> str:
    """Sanitize environment name to prevent injection attacks."""
    if not re.match(r"^[a-zA-Z0-9_-]+$", name):
        raise ValidationError(
            "Environment name can only contain letters, numbers, hyphens, and underscores"
        )
    return name.lower()


def sanitize_connection_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize connection parameters."""
    # Remove any potentially dangerous keys
    dangerous_keys = ["password", "passwd", "pwd"]
    sanitized = {k: v for k, v in params.items() if k.lower() not in dangerous_keys}
    
    # Validate host
    if "host" in sanitized:
        if not re.match(r"^[a-zA-Z0-9.-]+$", sanitized["host"]):
            raise ValidationError("Invalid host format")
    
    # Validate port
    if "port" in sanitized:
        try:
            port = int(sanitized["port"])
            if not 1 <= port <= 65535:
                raise ValidationError("Port must be between 1 and 65535")
        except (ValueError, TypeError):
            raise ValidationError("Invalid port number")
    
    return sanitized


def mask_password(connection_string: str) -> str:
    """Mask password in connection strings for logging."""
    # Pattern to match passwords in various connection string formats
    patterns = [
        r"(password=)([^;]+)",
        r"(pwd=)([^;]+)",
        r"(:\/\/[^:]+:)([^@]+)(@)",
    ]
    
    masked = connection_string
    for pattern in patterns:
        masked = re.sub(pattern, r"\1****\3", masked, flags=re.IGNORECASE)
    
    return masked
