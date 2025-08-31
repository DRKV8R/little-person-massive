"""
AAuth - Alternative Authentication System

A lightweight, flexible authentication system designed as a generic alternative to OAuth.
"""

from .core import AAuth
from .auth_methods import AuthMethod
from .exceptions import AAuthError, AuthenticationError, ValidationError
from .config import AAuthConfig

__version__ = "0.1.0"
__all__ = [
    "AAuth",
    "AuthMethod", 
    "AAuthError",
    "AuthenticationError",
    "ValidationError",
    "AAuthConfig"
]