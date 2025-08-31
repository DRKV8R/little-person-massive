"""
Custom exceptions for AAuth.
"""


class AAuthError(Exception):
    """Base exception for AAuth errors."""
    pass


class AuthenticationError(AAuthError):
    """Raised when authentication fails."""
    pass


class ValidationError(AAuthError):
    """Raised when input validation fails."""
    pass


class ConfigurationError(AAuthError):
    """Raised when configuration is invalid."""
    pass


class RateLimitError(AAuthError):
    """Raised when rate limits are exceeded."""
    pass


class TokenError(AAuthError):
    """Raised when token operations fail."""
    pass


class MFAError(AAuthError):
    """Raised when MFA operations fail."""
    pass


class UserNotFoundError(AuthenticationError):
    """Raised when user is not found."""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid."""
    pass


class AccountLockedError(AuthenticationError):
    """Raised when account is locked due to too many failed attempts."""
    pass


class PasswordValidationError(ValidationError):
    """Raised when password doesn't meet requirements."""
    pass


class EmailValidationError(ValidationError):
    """Raised when email format is invalid."""
    pass