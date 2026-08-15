# dbcreds/core/exceptions.py
"""
Custom exceptions for dbcreds.

This module defines all custom exceptions used throughout the package.
"""

from typing import Optional


class CredentialError(Exception):
    """Base exception for all credential-related errors."""

    pass


class CredentialNotFoundError(CredentialError):
    """Raised when requested credentials are not found."""

    pass


class PasswordExpiredError(CredentialError):
    """Raised when a password has expired."""

    pass


class BackendError(CredentialError):
    """Raised when a backend operation fails."""

    pass


class RotationError(CredentialError):
    """
    Raised when a password rotation fails.

    Attributes:
        new_password: The generated password, present only when the database
            already accepted it but it could not be saved and could not be
            rolled back. In that case it is the only remaining copy and the
            caller must surface it to the user.
        applied: Whether the database password was actually changed.
    """

    def __init__(
        self,
        message: str,
        new_password: Optional[str] = None,
        applied: bool = False,
    ):
        super().__init__(message)
        self.new_password = new_password
        self.applied = applied


class ValidationError(CredentialError):
    """Raised when credential validation fails."""

    pass


class SecurityError(CredentialError):
    """Raised when security operations fail."""

    pass


class AuditError(CredentialError):
    """Raised when audit operations fail."""

    pass