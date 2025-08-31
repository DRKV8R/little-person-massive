"""
Authentication methods enumeration and constants.
"""

from enum import Enum


class AuthMethod(Enum):
    """Available authentication methods in AAuth."""
    
    JWT = "jwt"
    SESSION = "session"
    API_KEY = "api_key"
    BASIC = "basic"
    MFA = "mfa"
    SOCIAL = "social"
    PASSWORDLESS_2FA = "passwordless_2fa"


class TokenType(Enum):
    """Token types for different authentication flows."""
    
    ACCESS = "access"
    REFRESH = "refresh"
    RESET = "reset"
    VERIFICATION = "verification"


class MFAMethod(Enum):
    """Multi-factor authentication methods."""
    
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"


class SocialProvider(Enum):
    """Supported social authentication providers."""
    
    GOOGLE = "google"
    GITHUB = "github"
    FACEBOOK = "facebook"
    TWITTER = "twitter"
    LINKEDIN = "linkedin"